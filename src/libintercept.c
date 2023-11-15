#include "libintercept.h"

#include <stdarg.h>

#include <sys/syscall.h>

#include <libsyscall_intercept_hook_point.h>

#include <x86linux/helper.h>

/* Variables for signal & system call interception */

int (*libintercept_syscall_hook)(long syscall_number, long arg0, long arg1,
                                 long arg2, long arg3, long arg4, long arg5,
                                 long *result) = NULL;

void (*libintercept_clone_hook_child)(void) = NULL;
void (*libintercept_clone_hook_parent)(long pid) = NULL;

int (*libintercept_signal_hook)(int sig, siginfo_t *info, void *context) = NULL;

static struct sigaction _orig_sigaction[NSIG] = {0};

/* Wrapper functions */

long raw_syscall(long syscall_number, ...) {
  long _ret, arg0, arg1, arg2, arg3, arg4, arg5;

  va_list ap;
  va_start(ap, syscall_number);
  arg0 = va_arg(ap, long);
  arg1 = va_arg(ap, long);
  arg2 = va_arg(ap, long);
  arg3 = va_arg(ap, long);
  arg4 = va_arg(ap, long);
  arg5 = va_arg(ap, long);
  va_end(ap);

  return (errno = syscall_error_code(
              _ret = syscall_no_intercept(syscall_number, arg0, arg1, arg2,
                                          arg3, arg4, arg5)))
             ? -1
             : _ret;
}

static void _libintercept_signal_wrapper(int sig, siginfo_t *info,
                                         void *context);
static __attribute__((hot, flatten)) int _libintercept_syscall_hook(
    __attribute__((unused)) long syscall_number,
    __attribute__((unused)) long arg0, __attribute__((unused)) long arg1,
    __attribute__((unused)) long arg2, __attribute__((unused)) long arg3,
    __attribute__((unused)) long arg4, __attribute__((unused)) long arg5,
    __attribute__((unused)) long *result) {
  /**
   * Intercept syscall instruction and save return value to `*result`.
   *
   * Return 0 to omit real syscall instruction to be executed.
   */

  int forward = 1;

  if (syscall_number == SYS_rt_sigaction) {
    /* Do not allow user to actually change signal handler. */

    /* Backup old sigaction saved. */

    struct sigaction osa;
    memcpy(&osa, &_orig_sigaction[arg0], sizeof(struct sigaction));

    if (arg1) {
      /* Save requested `struct sigaction` first, then alter it. */

      memcpy(&_orig_sigaction[arg0], (const void *)arg1,
             sizeof(struct sigaction));

      ((struct sigaction *restrict)arg1)->sa_sigaction =
          _libintercept_signal_wrapper;

      // *((int *)&arg1 + 2) |= SA_SIGINFO
      ((struct sigaction *restrict)arg1)->sa_flags |= SA_SIGINFO; // ?
    }

    *result = raw_syscall(SYS_rt_sigaction, arg0, arg1, arg2, arg3);
    if (*result == -1)
      *result = -errno;

    /* Give the expected sigaction to the user side (if requested). */

    if (arg2)
      memcpy((void *)arg2, &osa, sizeof(struct sigaction));

    forward = 0;
  } else {
    /* Disable syscall interception. */

    intercept_hook_point = NULL;

    /* Forward to user function first (if available). */

    if (libintercept_syscall_hook) {
      forward = libintercept_syscall_hook(syscall_number, arg0, arg1, arg2,
                                          arg3, arg4, arg5, result);

      /* Save `errno` to `*result` upon error. */

      if (!forward && (*result == -1))
        *result = -errno;
    }

    /* Enable syscall interception again. */

    intercept_hook_point = _libintercept_syscall_hook;
  }

  return forward;
}

static void _libintercept_signal_wrapper(int sig, siginfo_t *info,
                                         void *context) {
  int within_hook = intercept_hook_point ? 0 : 1, forward = 1;

  /* Disable syscall interception. */

  intercept_hook_point = NULL;

  if (libintercept_signal_hook)
    forward = libintercept_signal_hook(sig, info, context);

  if (forward) {
    if (!_orig_sigaction[sig].sa_sigaction) {
      /* User did not set signal handler; Use default signal handler for now. */

      struct sigaction osa;
      log_perror_assert(!sigaction(sig, NULL, &osa));
      log_perror_assert(signal(sig, SIG_DFL) != SIG_ERR);

      /* Unblock this signal first, raise it, then restore signal mask. */

      sigset_t tmp = {0}, old_sigset;
      log_perror_assert(!sigaddset(&tmp, sig));
      log_perror_assert(!sigprocmask(SIG_UNBLOCK, &tmp, &old_sigset));
      log_perror_assert(!raise(sig));
      log_perror_assert(!sigprocmask(SIG_SETMASK, &old_sigset, NULL));

      /* Restore previous signal mask and sigaction. */

      log_perror_assert(!sigaction(sig, &osa, NULL));
    } else {
      /* Enable syscall interception again. */

      intercept_hook_point = _libintercept_syscall_hook;

      /* Call the saved custom signal handler. */

      _orig_sigaction[sig].sa_sigaction(sig, info, context);

      /* Check for SA_RESETHAND. */

      // if (_orig_sigaction[sig].sa_flags & SA_RESETHAND) // not working
      if (*((int *)&_orig_sigaction[sig] + 2) & SA_RESETHAND) // Why?
        /* Do NOT reset `sa_flags`-related! (standard) */
        _orig_sigaction[sig].sa_sigaction = NULL;
    }
  }

  /* Enable syscall interception again (if required). */

  if (within_hook)
    intercept_hook_point = NULL;
  else
    intercept_hook_point = _libintercept_syscall_hook;
}

static void _libintercept_syscall_hook_child(void) {
  /* Reinitialize TLS value. */

  intercept_hook_point = _libintercept_syscall_hook;

  if (libintercept_clone_hook_child)
    libintercept_clone_hook_child();
}
static void _libintercept_syscall_hook_parent(long pid) {
  if (libintercept_clone_hook_parent)
    libintercept_clone_hook_parent(pid);
}

/* Constructor */

static void _libintercept_signal_hook_init(void) {
  /* Allow signal interception only when syscall interception is allowed. */

  if (syscall_hook_in_process_allowed()) {

    /* Register our signal wrapper as handler for all signals. */

    for (int i = 1; i < NSIG; ++i) {
      if (i != SIGKILL && i != SIGSTOP && (i <= SIGSYS || i >= SIGRTMIN)) {
        /* Backup the original sigaction. */

        struct sigaction osa;
        log_perror_assert(!sigaction(i, NULL, &osa));
        memcpy(&_orig_sigaction[i], &osa, sizeof(struct sigaction));

        /* Update the sigaction. */

        osa.sa_sigaction = _libintercept_signal_wrapper;
        osa.sa_flags |= SA_SIGINFO;
        log_perror_assert(!sigaction(i, &osa, NULL));
      }
    }

  } else {
    /* (for execve*()) Search if the current signal handlers are ours. */

    for (int i = 1; i < NSIG; ++i) {
      if (i != SIGKILL && i != SIGSTOP && (i <= SIGSYS || i >= SIGRTMIN)) {
        struct sigaction osa;
        log_perror_assert(!sigaction(i, NULL, &osa));
        if (osa.sa_sigaction == _libintercept_signal_wrapper)
          /* Restore to the default singal handler. */
          log_perror_assert(signal(i, SIG_DFL) != SIG_ERR);
      }
    }
  }
}
static __attribute__((constructor)) void
_libintercept_syscall_hook_constructor(void) {
  /* Disable all previous interception. */

  intercept_hook_point = NULL;
  intercept_hook_point_clone_child = NULL;
  intercept_hook_point_clone_parent = NULL;

#ifndef NDEBUG
  fprintf(stderr,
          "libintercept 0.1.0 (Debug) - Jihong Min (hurryman2212@gmail.com)\n");
#else
  fprintf(
      stderr,
      "libintercept 0.1.0 (Release) - Jihong Min (hurryman2212@gmail.com)\n");
#endif

  /* Initialize signal interception. */

  _libintercept_signal_hook_init();

  /* Start system call interception. */

  intercept_hook_point = _libintercept_syscall_hook;
  intercept_hook_point_clone_child = _libintercept_syscall_hook_child;
  intercept_hook_point_clone_parent = _libintercept_syscall_hook_parent;

  if (syscall_hook_in_process_allowed())
    log_warn("Syscall & signal interception is now active!");
  else {
    log_err("Syscall & signal interception is not allowed for this execution!");
    const char *env = getenv("INTERCEPT_HOOK_CMDLINE_FILTER");
    if (env)
      log_err("env: INTERCEPT_HOOK_CMDLINE_FILTER=%s", env);
  }
}
