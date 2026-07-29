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
    __u32 enabled;
    __u32 io_syscall_count;
    __s32 wait_syscall_nr;
    __s32 pwait_syscall_nr;
    __s32 pwait2_syscall_nr;
    __s32 ctl_syscall_nr;
    struct cw_epoll_io_syscall io_syscalls[CW_EPOLL_MAX_IO_SYSCALLS];
};

#endif
