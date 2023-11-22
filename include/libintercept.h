#pragma once

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Do not directly call raw_syscall(SYS_rt_sigaction, ...)! */
long raw_syscall(long syscall_number, ...);

/**
 * GLIBC syscall()-like hooking function
 *
 * The input parameters are for raw_syscall() (do not use GLIBC's syscall()!).
 *
 * Save 0 to `*forward` to bypass the original syscall forwarded to the kernel.
 *
 * For following system calls, hooking is inhibited: vfork(), rt_sigreturn(),
 * clone(), clone3(), rt_sigaction(), exit() and exit_group().
 *
 * (for interception)
 * Upon error, save appropriate `errno` value to it and return -1.
 */
extern long (*libintercept_syscall_hook)(long syscall_number, long arg0,
                                         long arg1, long arg2, long arg3,
                                         long arg4, long arg5, int *forward);

/**
 * Signal handler hooking function
 *
 * Save 0 to `*forward` to bypass the original signal handler.
 */
extern void (*libintercept_signal_hook)(int sig, siginfo_t *info, void *context,
                                        int *forward,
                                        struct sigaction *orig_sigaction);

#ifdef __cplusplus
extern thread_local pid_t self_tid;
#else
extern _Thread_local pid_t self_tid;
#endif
/* Return value will be passed to new thread group monitor (if available). */
extern void *(*libintercept_clone_hook_child)(pid_t parent_tgid);
extern void (*libintercept_clone_hook_parent)(pid_t child_tid);

extern pid_t self_tgid;
/* Number of thread(s) in the thread group except the thread group monitor. */
extern size_t nr_local_thread;
/* 0 == No running thread group monitor yet. */
extern pthread_attr_t libintercept_thread_group_monitor_attr;
extern pthread_t libintercept_thread_group_monitor_ident;
extern void *(*libintercept_thread_group_monitor)(void *arg);
void libintercept_start_thread_group_monitor(void *arg);

#ifdef __cplusplus
}
#endif
