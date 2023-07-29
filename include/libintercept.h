#pragma once

#include <sys/signal.h>

#ifdef __cplusplus
extern "C" {
#endif

long raw_syscall(long syscall_number, ...);

/**
 * GLIBC syscall()-like hooking function
 *
 * The input parameters are for raw_syscall() (do not use GLIBC's syscall()).
 *
 * Return 0 to bypass the original syscall or other to forward it and you should
 * always forward these syscalls: vfork(), rt_sigreturn(), clone() and clone3().
 *
 * (for interception)
 * Upon success, save the return value to `*ret`.
 * Upon error, set appropriate `errno` value then save -1 to `*ret`.
 */
extern int (*libintercept_syscall_hook)(long syscall_number, long arg0,
                                        long arg1, long arg2, long arg3,
                                        long arg4, long arg5, long *ret);

extern int (*libintercept_signal_hook)(int sig, siginfo_t *info, void *context);

#ifdef __cplusplus
}
#endif
