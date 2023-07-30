# libintercept
libintercept - Library for Syscall & Signal Interception

This is a library intended to be used as a 'preloaded' one via `LD_PRELOAD` and currently only supports x86-64 Linux as it depends on libsyscall_intercept.
You need [the special version of libsyscall_intercept](https://github.com/hurryman2212/syscall_intercept) using the TLS (thread local storage) function pointer variable for hooking.

## Syscall interception
Link to this library with your syscall hook implementation saved to `int (*libintercept_syscall_hook)(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *ret)`.
The hook should save the result to `*ret` (upon error, save -1 and set appropriate `errno` value) if handled, otherwise return a non-zero value to forward to the original syscall.
For handling the initial input parameters: They are for the raw syscall instruction, so do not pass to GLIBC's syscall() wrapper (use `raw_syscall(syscall_number, ...)` for GLIBC-style wrapper, but it still uses the raw parameter format)!

The key difference from libsyscall_intercept is that this is the AS-safe implementation where the syscall interception will not happen for system calls within your hook.

By default, the backend libsyscall_intercept only intercepts syscalls within glibc objects. Use `INTERCEPT_ALL_OBJS=1` environment variable for intercepting syscalls in all loaded objects.

## Signal interception
Use `int (*libintercept_signal_hook)(int sig, siginfo_t *info, void *context)` as the signal hooking point.
Return non-zero value to call the current original signal handler, otherwise 0.

## Example
Build your library to be preloaded via `LD_PRELOAD` and set the hooking function pointer values.
```c
#include <string.h>

#include <sys/syscall.h>

#include <libaudit.h>

#include <libintercept.h>
#include <x86linux/helper.h>

int _signal_hook(__attribute__((unused)) int sig,
                 __attribute__((unused)) siginfo_t *info,
                 __attribute__((unused)) void *context) {
  int forward = 1;

  log_info("SIG%s", sigabbrev_np(sig));

  return forward;
}

static __attribute__((hot, flatten)) int _syscall_hook(
    __attribute__((unused)) long syscall_number,
    __attribute__((unused)) long arg0, __attribute__((unused)) long arg1,
    __attribute__((unused)) long arg2, __attribute__((unused)) long arg3,
    __attribute__((unused)) long arg4, __attribute__((unused)) long arg5,
    __attribute__((unused)) long *ret) {
  /* You can use any functions that calls syscall wrappers internally! */

  int forward = 1, errno_save = 0;

  if ((syscall_number == SYS_vfork) || (syscall_number == SYS_rt_sigreturn) ||
      (syscall_number == SYS_clone) || (syscall_number == SYS_clone3))
    log_warn("%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) -> Forwarding...",
             audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1,
             arg2, arg3, arg4, arg5);
  else {
    *ret = raw_syscall(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
    errno_save = errno;
    forward = 0;

    if (errno)
      log_debug("%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx (%s)",
                audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1,
                arg2, arg3, arg4, arg5, *ret, strerrordesc_np(errno));
    else
      log_debug("%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx",
                audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1,
                arg2, arg3, arg4, arg5, *ret);
  }

  if (!forward)
    errno = errno_save;
  return forward;
}

static __attribute__((constructor)) void _syscall_hook_constructor(void) {
  libintercept_syscall_hook = _syscall_hook;
  libintercept_signal_hook = _signal_hook;
}
```
