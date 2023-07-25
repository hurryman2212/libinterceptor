#pragma once

#ifdef __cplusplus
extern "C" {
#endif

extern int (*libintercept_syscall_hook)(long syscall_number, long arg0,
                                        long arg1, long arg2, long arg3,
                                        long arg4, long arg5, long *result);

#ifdef __cplusplus
}
#endif
