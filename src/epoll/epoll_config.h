// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_EPOLL_CONFIG_H
#define CALLWEAVE_EPOLL_CONFIG_H

#define CW_EPOLL_MAX_IO_SYSCALLS 24

struct cw_epoll_io_syscall {
    __s32 syscall_nr;
    __u32 operation;
};

/* Shared load-time configuration for the epoll tracer. */
struct cw_epoll_config {
    __u64 min_wait_ns;
    __u64 min_dispatch_ns;
    __u64 min_callback_ns;
    __u32 enabled;
    __u32 callback_enabled;
    __u32 callback_key_arg;
    __u32 callback_match;
    __u32 defer_until_exec;
    __u32 io_syscall_count;
    __s32 wait_syscall_nr;
    __s32 pwait_syscall_nr;
    __s32 pwait2_syscall_nr;
    __s32 ctl_syscall_nr;
    __s32 eventfd_syscall_nr;
    __s32 eventfd2_syscall_nr;
    __s32 timerfd_create_syscall_nr;
    __s32 timerfd_settime_syscall_nr;
    __s32 signalfd_syscall_nr;
    __s32 signalfd4_syscall_nr;
    struct cw_epoll_io_syscall io_syscalls[CW_EPOLL_MAX_IO_SYSCALLS];
};

#endif
