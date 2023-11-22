# libinterceptor
Preloaded Library for Userspace Syscall Instruction, Signal and Thread Interception

This is a library intended to be used as a 'preloaded' one via `LD_PRELOAD` and currently only supports x86-64 Linux as it depends on libsyscall_intercept.
You need [the special version of libsyscall_intercept](https://github.com/hurryman2212/syscall_intercept) using the TLS (thread local storage) function pointer variable for hooking.

Additionally, you need [libx86linuxextra](https://github.com/hurryman2212/x86linuxextra) as a dependency.

## Usage
Please refer to `libinterceptor.h`.

## Example
Build your library to be preloaded via `LD_PRELOAD` and set the hooking function pointer values.
```c
#include <errno.h>

#include <syscall.h>

#include <libaudit.h>

#include <libinterceptor.h>
#include <x86linux/helper.h>

static void _signal_hook(
    __attribute__((unused)) int sig, __attribute__((unused)) siginfo_t *info,
    __attribute__((unused)) void *context, __attribute__((unused)) int *forward,
    __attribute__((unused)) struct sigaction *orig_sigaction) {
  log_debug("Thread %d \"%s\" received signal SIG%s.", cnt_glob_thread,
            program_invocation_short_name, sigabbrev_np(sig));
}

static __attribute__((hot, flatten)) int _syscall_hook(
    __attribute__((unused)) long syscall_number,
    __attribute__((unused)) long arg0, __attribute__((unused)) long arg1,
    __attribute__((unused)) long arg2, __attribute__((unused)) long arg3,
    __attribute__((unused)) long arg4, __attribute__((unused)) long arg5,
    __attribute__((unused)) int *forward) {
  /* You can use any functions that calls syscall wrappers internally! */

  long ret = 0;
  int errno_save = 0;

  if ((syscall_number == SYS_vfork) || (syscall_number == SYS_rt_sigreturn) ||
      (syscall_number == SYS_clone) || (syscall_number == SYS_clone3)) {
    log_debug("%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = ?",
              audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1,
              arg2, arg3, arg4, arg5);
    *forward = 1;
  } else {
    ret = raw_syscall(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
    errno_save = errno;

    if (errno_save)
      log_err("%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx %s (%s)",
              audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1,
              arg2, arg3, arg4, arg5, ret, strerrorname_np(errno_save),
              strerrordesc_np(errno_save));
    else
      log_debug("%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx",
                audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1,
                arg2, arg3, arg4, arg5, ret);
  }

  /* ... */

  if (!*forward)
    errno = errno_save;
  return ret;
}

static __attribute__((constructor)) void _hook_constructor(void) {
  libinterceptor_syscall_hook = _syscall_hook;
  libinterceptor_signal_hook = _signal_hook;
}
```
