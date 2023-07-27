#include "libintercept.h"

#include <sys/signal.h>
#include <sys/syscall.h>

#include <libsyscall_intercept_hook_point.h>

#include <x86linux/helper.h>

/* Variables for signal & system call interception */

int (*libintercept_syscall_hook)(long syscall_number, long arg0, long arg1,
                                 long arg2, long arg3, long arg4, long arg5,
                                 long *result) = NULL;

static void (*_orig_signal_handle[NSIG])(int sig, siginfo_t *info,
                                         void *context) = {NULL};
static bitset64_t _orig_signal_resethand[BITSET64_ARR_LEN(NSIG)] = {0};

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

  switch (syscall_number) {
  case SYS_rt_sigaction:
    /* Do not allow user to actually change signal handler. */

    /* Check for SA_RESETHAND. */

    if (((const struct sigaction *_Nullable restrict)arg1)->sa_flags &
        SA_RESETHAND)
      x86_set_bit_atomic(_orig_signal_resethand, arg0);

    if (arg1) {
      /* Check for the ignored signal. */

      if (((const struct sigaction *_Nullable restrict)arg1)->sa_handler !=
          SIG_IGN) {
        /* Save the requested signal hander. */

        _orig_signal_handle[arg0] =
            ((const struct sigaction *_Nullable restrict)arg1)->sa_sigaction;

        /* Enforce our signal handler for this signal. */

        ((struct sigaction *_Nullable restrict)arg1)->sa_sigaction =
            _libintercept_signal_wrapper;
      }
    }

    /* Forward to original syscall. */

    break;

  case SYS_execve:
  case SYS_execveat:
    /* POSIX compatibility: Reset all saved custom signal handler. */

    memset(_orig_signal_handle, 0, sizeof(_orig_signal_handle));

    break;

  default:
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
  int within_hook = intercept_hook_point ? 0 : 1;

  if (_orig_signal_handle[sig] == NULL) {
    /* User did not set signal handler; Raise default signal handler. */

    intercept_hook_point = NULL;

    log_perror_assert(signal(sig, SIG_DFL) != SIG_ERR);
    sigset_t tmp = {0}, old_sigset;
    log_assert(!sigaddset(&tmp, sig));
    /* Unblock this signal first. */
    log_perror_assert(!sigprocmask(SIG_UNBLOCK, &tmp, &old_sigset));
    log_perror_assert(!raise(sig));

    /* Restore previous signal mask and sigaction. */

    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = _libintercept_signal_wrapper;
    sa.sa_mask = old_sigset;
    log_perror_assert(!sigaction(sig, &sa, NULL));
  } else {
    /* Call the saved custom signal handler. */

    intercept_hook_point = _libintercept_syscall_hook;

    _orig_signal_handle[sig](sig, info, context);

    /* Check for SA_RESETHAND. */

    if (x86_test_bit(_orig_signal_resethand, sig)) {
      intercept_hook_point = NULL;

      log_perror_assert(signal(sig, SIG_DFL) != SIG_ERR);

      _orig_signal_handle[sig] = NULL;

      x86_unset_bit_atomic(_orig_signal_resethand, sig);
    }
  }

  if (within_hook)
    intercept_hook_point = NULL;
  else
    intercept_hook_point = _libintercept_syscall_hook;
}

static void _libintercept_signal_hook_init(void) {
  /* Register our signal wrapper as handler for all signals. */

  sigset_t old_sigset;
  log_perror_assert(!sigprocmask(SIG_UNBLOCK, NULL, &old_sigset));
  for (int i = 1; i < NSIG; ++i) {
    if (i != SIGKILL && i != SIGSTOP && (i <= SIGSYS || i >= SIGRTMIN)) {
      struct sigaction sa = {0}, osa;
      sa.sa_flags = SA_SIGINFO;
      sa.sa_sigaction = _libintercept_signal_wrapper;
      sa.sa_mask = old_sigset;
      log_perror_assert(!sigaction(i, &sa, &osa));
      if (osa.sa_flags & SA_SIGINFO) {
        if (osa.sa_sigaction) {
          _orig_signal_handle[i] = osa.sa_sigaction;
          log_abort("There was an original `sa_sigaction`!");
        }
      } else {
        if (osa.sa_handler) {
          _orig_signal_handle[i] =
              (void (*)(int, siginfo_t *, void *))osa.sa_handler;
          log_abort("There was an original `sa_handler`!");
        }
      }
    }
  }
}

/* Constructor */

static void _libintercept_syscall_hook_child(void) {
  /* Reinitialize TLS value. */

  intercept_hook_point = _libintercept_syscall_hook;
}
static __attribute__((constructor)) void
_libintercept_syscall_hook_constructor(void) {
  intercept_hook_point = NULL;

  /* Initialize callbacks for clone()-related functions. */

  intercept_hook_point_clone_child = _libintercept_syscall_hook_child;
  intercept_hook_point_clone_parent = NULL; // N/A

  /* Start signal interception. */

  _libintercept_signal_hook_init();

  log_info("Enabling signal & system call interception...");

  /* Start system call interception. */

  intercept_hook_point = _libintercept_syscall_hook;
}
