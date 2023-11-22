#include "libintercept.h"

#include <errno.h>

#include <syscall.h>

#include <pthread.h>

#include <libsyscall_intercept_hook_point.h>

#include <x86linux/helper.h>

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

void libintercept_start_thread_group_monitor(void *arg) {
  if (libintercept_thread_group_monitor)
    log_abort_if_errno(pthread_create(&libintercept_thread_group_monitor_ident,
                                      &libintercept_thread_group_monitor_attr,
                                      libintercept_thread_group_monitor, arg));
}

/* Variables for signal & system call interception */

long (*libintercept_syscall_hook)(long syscall_number, long arg0, long arg1,
                                  long arg2, long arg3, long arg4, long arg5,
                                  int *forward) = NULL;

void (*libintercept_signal_hook)(int sig, siginfo_t *info, void *context,
                                 int *forward,
                                 struct sigaction *orig_sigaction) = NULL;

_Thread_local pid_t self_tid = 0;
void *(*libintercept_clone_hook_child)(pid_t parent_tgid) = NULL;
void (*libintercept_clone_hook_parent)(pid_t child_tid) = NULL;

pid_t self_tgid = 0;
size_t nr_local_thread = 1;
pthread_attr_t libintercept_thread_group_monitor_attr = {0};
pthread_t libintercept_thread_group_monitor_ident = 0;
void *(*libintercept_thread_group_monitor)(void *arg) = NULL;

/* Static variables & functions */

/* (standard) All local threads share the same sigaction. */
static struct sigaction orig_sigaction[NSIG] = {0};
static void _libintercept_signal_wrapper(int sig, siginfo_t *info,
                                         void *context);
static int libintercept_rt_sigaction(int signum,
                                     struct sigaction *__restrict act,
                                     struct sigaction *__restrict oldact,
                                     size_t sigsetsize) {
  int ret;

  struct sigaction osa;
  /* Backup old sigaction saved. */
  memcpy(&osa, &orig_sigaction[signum], sizeof(struct sigaction));
  if (act) {
    /* Save requested `struct sigaction` first, then alter it. */
    memcpy(&orig_sigaction[signum], act, sizeof(struct sigaction));

    act->sa_sigaction = _libintercept_signal_wrapper;
    // *((int *)&sa + 2) |= SA_SIGINFO // also working
    act->sa_flags |= SA_SIGINFO; // ?
  }

  // ret = sigaction(signum, act, oldact); // not working
  ret = raw_syscall(SYS_rt_sigaction, signum, act, oldact, sigsetsize);
  if (act)
    memcpy(act, &orig_sigaction[signum], sizeof(struct sigaction));

  /* Give the expected sigaction to the user side (if requested). */
  if (oldact)
    memcpy(oldact, &osa, sizeof(struct sigaction));

  return ret;
}
static __attribute__((hot, flatten)) int _libintercept_syscall_wrapper(
    __attribute__((unused)) long syscall_number,
    __attribute__((unused)) long arg0, __attribute__((unused)) long arg1,
    __attribute__((unused)) long arg2, __attribute__((unused)) long arg3,
    __attribute__((unused)) long arg4, __attribute__((unused)) long arg5,
    __attribute__((unused)) long *result) {
  /**
   * Intercept syscall instruction and save return value to `*result`.
   *
   * Return 0 to prohibit the original syscall from forwarding to the kernel.
   */

  int forward = 0;

  /* Disable syscall interception. */
  intercept_hook_point = NULL;

  switch (syscall_number) {
  case SYS_vfork:
  case SYS_rt_sigreturn:
  case SYS_clone:
  case SYS_clone3:
    /* Inhibit above system calls from interception. */
    forward = 1;
    break;

  case SYS_rt_sigaction:
    /* Do not allow user to actually change signal handler! */
    *result = libintercept_rt_sigaction(arg0, address_cast(arg1),
                                        address_cast(arg2), arg3);
    if (*result == -1)
      *result = -errno;
    break;

  case SYS_exit:
    if (__sync_sub_and_fetch(&nr_local_thread, 1)) {
      forward = 1;
      break;
    }
    /* This is the last local thread (except the monitor). */
  case SYS_exit_group:
    nr_local_thread = 0;
    /* Kill the thread group monitor for this group (if there is). */
    if (libintercept_thread_group_monitor_ident)
      pthread_kill(libintercept_thread_group_monitor_ident, SIGTERM);
    forward = 1;
    break;

  default:
    /* Forward to user function first (if available). */
    if (libintercept_syscall_hook) {
      *result = libintercept_syscall_hook(syscall_number, arg0, arg1, arg2,
                                          arg3, arg4, arg5, &forward);
      /* Save `errno` to `*result` upon error. */
      if (!forward && *result == -1)
        *result = -errno;
    } else
      forward = 1;
  }

  /* Enable syscall interception again. */
  intercept_hook_point = _libintercept_syscall_wrapper;

  return forward;
}

static void _libintercept_clone_wrapper_child(void) {
  pid_t parent_tgid = self_tgid;
  self_tgid = getpid();
  if (self_tgid == parent_tgid)
    __sync_add_and_fetch(&nr_local_thread, 1);
  else
    nr_local_thread = 1;

  self_tid = gettid();
  void *ret = NULL;
  if (libintercept_clone_hook_child)
    ret = libintercept_clone_hook_child(parent_tgid);

  /* Start a new instance of thread group monitor (if available). */
  if ((self_tgid != parent_tgid) && libintercept_thread_group_monitor)
    libintercept_start_thread_group_monitor(ret);

  /* Reinitialize TLS variable for hooking. */
  intercept_hook_point = _libintercept_syscall_wrapper;
}
static void _libintercept_clone_wrapper_parent(long pid) {
  /* Disable syscall interception. */
  intercept_hook_point = NULL;

  if (libintercept_clone_hook_parent)
    libintercept_clone_hook_parent(pid);

  /* Enable syscall interception again. */
  intercept_hook_point = _libintercept_syscall_wrapper;
}

static __attribute__((hot, flatten)) void
_libintercept_signal_wrapper(int sig, siginfo_t *info, void *context) {
  int within_hook = intercept_hook_point ? 0 : 1;

  /* Disable syscall interception. */
  intercept_hook_point = NULL;

  int forward = 0;
  /* Call user signal hook first (if available). */
  if (libintercept_signal_hook)
    libintercept_signal_hook(sig, info, context, &forward,
                             &orig_sigaction[sig]);
  else
    forward = 1;

  if (forward) {
    if (!orig_sigaction[sig].sa_sigaction) {
      /* User did not set signal handler; Use default signal handler for now. */

      struct sigaction osa;
      log_abort_on_error(sigaction(sig, NULL, &osa));
      log_abort_on_error(signal(sig, SIG_DFL));

      /* Unblock this signal first, raise it, then restore signal mask. */
      sigset_t tmp = {0}, old_sigset;
      log_abort_on_error(sigaddset(&tmp, sig));
      log_abort_on_error(sigprocmask(SIG_UNBLOCK, &tmp, &old_sigset));
      log_abort_on_error(raise(sig));
      log_abort_on_error(sigprocmask(SIG_SETMASK, &old_sigset, NULL));

      /* Restore previous signal mask and sigaction. */
      log_abort_on_error(sigaction(sig, &osa, NULL));
    } else {
      /* Enable syscall interception before the original signal handler. */
      intercept_hook_point = _libintercept_syscall_wrapper;

      /* Call the saved custom signal handler. */
      orig_sigaction[sig].sa_sigaction(sig, info, context);

      /* Check for SA_RESETHAND. */

      // if (orig_sigaction[sig].sa_flags & SA_RESETHAND) // not working
      if (*((int *)&orig_sigaction[sig] + 2) & SA_RESETHAND) // Why?
        /* Do NOT reset `sa_flags` here (since it is the standard behavior)! */
        orig_sigaction[sig].sa_sigaction = NULL;
    }
  }

  /* Enable syscall interception again (if required). */
  if (within_hook)
    intercept_hook_point = NULL;
  else
    intercept_hook_point = _libintercept_syscall_wrapper;
}

/* Constructor */

static void _libintercept_signal_wrapper_init(void) {
  /* Allow signal interception only when syscall interception is allowed. */
  if (syscall_hook_in_process_allowed()) {
    /* Register our signal wrapper as handler for all signals. */

    for (int i = 1; i < NSIG; ++i) {
      if (i != SIGKILL && i != SIGSTOP && (i <= SIGSYS || i >= SIGRTMIN)) {
        struct sigaction osa;
        /* Backup the original sigaction. */
        log_abort_on_error(sigaction(i, NULL, &osa));
        memcpy(&orig_sigaction[i], &osa, sizeof(struct sigaction));

        /* Update the sigaction. */
        osa.sa_sigaction = _libintercept_signal_wrapper;
        osa.sa_flags |= SA_SIGINFO;
        log_abort_on_error(sigaction(i, &osa, NULL));
      }
    }

  } else {
    /* (for execve*()) Search if the current signal handlers are ours. */

    for (int i = 1; i < NSIG; ++i) {
      if (i != SIGKILL && i != SIGSTOP && (i <= SIGSYS || i >= SIGRTMIN)) {
        struct sigaction osa;
        log_abort_on_error(sigaction(i, NULL, &osa));
        if (osa.sa_sigaction == _libintercept_signal_wrapper)
          /* Restore to the default singal handler. */
          log_abort_on_error(signal(i, SIG_DFL));
      }
    }
  }
}
static __attribute__((constructor(101))) void _libintercept_constructor(void) {
  /* Disable all previous interception. */
  intercept_hook_point = NULL;
  intercept_hook_point_clone_child = NULL;
  intercept_hook_point_clone_parent = NULL;

  /* Save initial self Thread ID & Thread Group ID. */
  self_tid = gettid();
  self_tgid = getpid();

  log_init(NULL, 0, -1, 1, 0);
  log_enable(LOG_EMERG);

  pthread_attr_init(&libintercept_thread_group_monitor_attr);
  pthread_attr_setdetachstate(&libintercept_thread_group_monitor_attr,
                              PTHREAD_CREATE_DETACHED);

  /* Initialize signal interception. */
  _libintercept_signal_wrapper_init();

  /* Start system call interception. */
  intercept_hook_point = _libintercept_syscall_wrapper;
  intercept_hook_point_clone_child = _libintercept_clone_wrapper_child;
  intercept_hook_point_clone_parent = _libintercept_clone_wrapper_parent;
}
