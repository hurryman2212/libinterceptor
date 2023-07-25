# libintercept
This is a library intended to be used as a 'preloaded' one via `LD_PRELOAD` and currently only supports x86-64 Linux as it depends on libsyscall_intercept.
You need the special version of [libsyscall_intercept](https://github.com/hurryman2212/syscall_intercept) using the TLS (thread local storage) function pointer variable for hooking.

Link to this library with your syscall hook implementation saved to `int (*libintercept_syscall_hook)(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)`.
The hook should save the result to `*result` if handled, otherwise return a non-zero value to forward to the original syscall.

The key difference from libsyscall_intercept is that this is the AS-safe implementation where the syscall interception will not happen for system calls within your hook.

By default, the backend libsyscall_intercept only intercepts syscalls within glibc objects. Use `INTERCEPT_ALL_OBJS=1` environment variable for intercepting syscalls in all loaded objects.
