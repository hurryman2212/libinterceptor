#include "libinterceptor.h"

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

void libinterceptor_attach_thread_group_monitor(void *arg) {
  /* Thread-safe */
  pthread_t ident = __sync_val_compare_and_swap(
      &libinterceptor_thread_group_monitor_ident, 0, 1);
  if (!ident && libinterceptor_thread_group_monitor)
    log_abort_if_errno(
        pthread_create(&libinterceptor_thread_group_monitor_ident,
                       &libinterceptor_thread_group_monitor_attr,
                       libinterceptor_thread_group_monitor, arg));
}
void libinterceptor_detach_thread_group_monitor(void) {
  /* Thread-safe */
  pthread_t ident =
      __sync_val_compare_and_swap(&libinterceptor_thread_group_monitor_ident,
                                  libinterceptor_thread_group_monitor_ident, 0);
  if (ident)
    pthread_kill(ident, SIGKILL); // ?
}

/* Variables for signal & system call interception */

long (*libinterceptor_syscall_hook)(long syscall_number, long arg0, long arg1,
                                    long arg2, long arg3, long arg4, long arg5,
                                    int *forward) = NULL;

void (*libinterceptor_signal_hook)(int sig, siginfo_t *info, void *context,
                                   int *forward,
                                   struct sigaction *orig_sigaction) = NULL;

_Thread_local pid_t self_tid = 0;
void *(*libinterceptor_clone_hook_child)(pid_t parent_tgid) = NULL;
void (*libinterceptor_clone_hook_parent)(pid_t child_tid) = NULL;

pid_t self_tgid = 0;
size_t nr_local_thread = 1;
size_t nr_thread_grp = 1;
size_t cnt_thread = 1;

pthread_attr_t libinterceptor_thread_group_monitor_attr = {0};
void *(*libinterceptor_thread_group_monitor)(void *arg) = NULL;

pthread_t libinterceptor_thread_group_monitor_ident = 0;

/* Static variables & functions */

/**
 * (standard) All local threads share the same sigaction.
 *
 * (See `man 2 clone` about CLONE_SIGHAND, CLONE_VM, and CLONE_THREAD.)
 */
static struct sigaction orig_sigaction[NSIG] = {0};
static void _libinterceptor_signal_wrapper(int sig, siginfo_t *info,
                                           void *context);
static int libinterceptor_rt_sigaction(int signum,
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

    act->sa_sigaction = _libinterceptor_signal_wrapper;
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
static __attribute__((hot, flatten)) int _libinterceptor_syscall_wrapper(
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
    *result = libinterceptor_rt_sigaction(arg0, address_cast(arg1),
                                          address_cast(arg2), arg3);
    if (*result == -1)
      *result = -errno;
    break;

  case SYS_exit:
    if (__sync_sub_and_fetch(&nr_local_thread, 1) != 1 ||
        !libinterceptor_thread_group_monitor_ident) {
      /* No need to shutdown the thread group monitor */
      forward = 1;
      break;
    }
  case SYS_exit_group:
    /* Kill the thread group monitor for this group (if there is). */
    if (libinterceptor_thread_group_monitor_ident &&
        libinterceptor_thread_group_monitor_ident != pthread_self())
      libinterceptor_detach_thread_group_monitor();

    nr_local_thread = 0;
    __sync_sub_and_fetch(&nr_thread_grp, 1);

    forward = 1;
    break;

  default:
    /* Forward to user function first (if available). */
    if (unlikely(!libinterceptor_syscall_hook))
      forward = 1;
    else {
      *result = libinterceptor_syscall_hook(syscall_number, arg0, arg1, arg2,
                                            arg3, arg4, arg5, &forward);
      /* Save `errno` to `*result` upon error. */
      if (!forward && *result == -1)
        *result = -errno;
    }
  }

  /* Enable syscall interception again. */
  intercept_hook_point = _libinterceptor_syscall_wrapper;

  return forward;
}

static void _libinterceptor_clone_wrapper_child(void) {
  __sync_add_and_fetch(&cnt_thread, 1);
  pid_t parent_tgid = self_tgid;
  self_tgid = getpid();
  self_tid = gettid();

  if (self_tgid == parent_tgid)
    __sync_add_and_fetch(&nr_local_thread, 1);
  else {
    __sync_add_and_fetch(&nr_thread_grp, 1);
    nr_local_thread = 1;
    libinterceptor_thread_group_monitor_ident = 0;
  }

  void *ret = NULL;
  if (libinterceptor_clone_hook_child)
    ret = libinterceptor_clone_hook_child(parent_tgid);

  /* Start a new instance of thread group monitor (if available). */
  if (self_tgid != parent_tgid)
    libinterceptor_attach_thread_group_monitor(ret);

  /* Reinitialize TLS variable for hooking. */
  intercept_hook_point = _libinterceptor_syscall_wrapper;
}
static void _libinterceptor_clone_wrapper_parent(long pid) {
  /* Disable syscall interception. */
  intercept_hook_point = NULL;

  if (libinterceptor_clone_hook_parent)
    libinterceptor_clone_hook_parent(pid);

  /* Enable syscall interception again. */
  intercept_hook_point = _libinterceptor_syscall_wrapper;
}

static __attribute__((hot, flatten)) void
_libinterceptor_signal_wrapper(int sig, siginfo_t *info, void *context) {
  int within_hook = intercept_hook_point ? 0 : 1;

  /* Disable syscall interception. */
  intercept_hook_point = NULL;

  int forward = 0;
  /* Call user signal hook first (if available). */
  if (unlikely(!libinterceptor_signal_hook))
    forward = 1;
  else
    libinterceptor_signal_hook(sig, info, context, &forward,
                               &orig_sigaction[sig]);

  if (forward) {
    if (unlikely(!orig_sigaction[sig].sa_sigaction)) {
      /* User did not set signal handler; Use default signal handler for now. */

      struct sigaction osa;
      log_abort_on_error(sigaction(sig, NULL, &osa));
      log_abort_on_error(signal(sig, SIG_DFL));

      /* Unblock this signal first, then raise it. */
      sigset_t tmp = {0}, old_sigset;
      log_abort_on_error(sigaddset(&tmp, sig));
      log_abort_on_error(sigprocmask(SIG_UNBLOCK, &tmp, &old_sigset));
      log_abort_on_error(raise(sig));

      /* Restore previous signal mask and sigaction. */
      log_abort_on_error(sigprocmask(SIG_SETMASK, &old_sigset, NULL));
      log_abort_on_error(sigaction(sig, &osa, NULL)); // ?
    } else {
      /* Enable syscall interception before the original signal handler. */
      intercept_hook_point = _libinterceptor_syscall_wrapper;

      /* Call the saved custom signal handler. */
      orig_sigaction[sig].sa_sigaction(sig, info, context);

      /* Check for SA_RESETHAND. */

      // if (orig_sigaction[sig].sa_flags & SA_RESETHAND) // not working
      if (*((int *)&orig_sigaction[sig] + 2) & SA_RESETHAND) // Why?
        /* Do NOT reset `sa_flags` here! (Since it is confirmed behavior.) */
        orig_sigaction[sig].sa_sigaction = NULL;
    }
  }

  /* Enable syscall interception again (if required). */
  if (within_hook)
    intercept_hook_point = NULL;
  else
    intercept_hook_point = _libinterceptor_syscall_wrapper;
}

/* Constructor */

static void _libinterceptor_signal_wrapper_init(void) {
  /* Allow signal interception only when syscall interception is allowed. */
  if (syscall_hook_in_process_allowed()) {
    /* Register our signal wrapper as handler for all signals. */
    for (int i = 1; i < NSIG; ++i) {
      if (unlikely((i > SIGSYS && i < SIGRTMIN) || i == SIGKILL ||
                   i == SIGSTOP))
        continue;

      struct sigaction osa;
      log_abort_on_error(sigaction(i, NULL, &osa));
      if (unlikely(i == SIGRTMAX && osa.sa_sigaction))
        /* (workaround for valgrind) Omit SIGRT32 interception. */
        continue;

      /* Backup the original sigaction. */
      memcpy(&orig_sigaction[i], &osa, sizeof(struct sigaction));

      /* Update the sigaction. */
      osa.sa_sigaction = _libinterceptor_signal_wrapper;
      osa.sa_flags |= SA_SIGINFO;
      log_abort_on_error(sigaction(i, &osa, NULL));
    }
  }
}
static __attribute__((constructor(101))) void
_libinterceptor_constructor(void) {
  /* Disable all previous interception. */
  intercept_hook_point = NULL;
  intercept_hook_point_clone_child = NULL;
  intercept_hook_point_clone_parent = NULL;

  /* Save initial self Thread ID & Thread Group ID. */
  self_tid = gettid();
  self_tgid = getpid();

  log_init(NULL, 0, -1, 1, 0);
  log_enable(LOG_EMERG);

  /* Set default attribute of thread group monitor. */
  pthread_attr_init(&libinterceptor_thread_group_monitor_attr);
  pthread_attr_setdetachstate(&libinterceptor_thread_group_monitor_attr,
                              PTHREAD_CREATE_DETACHED);

  /* Early attachment of thread group monitor if (somehow) available. */
  libinterceptor_attach_thread_group_monitor(NULL);

  /* Initialize signal interception. */
  _libinterceptor_signal_wrapper_init();

  /* Start system call interception. */
  intercept_hook_point = _libinterceptor_syscall_wrapper;
  intercept_hook_point_clone_child = _libinterceptor_clone_wrapper_child;
  intercept_hook_point_clone_parent = _libinterceptor_clone_wrapper_parent;
}
