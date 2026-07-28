// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_CORE_CONFIG_H
#define CALLWEAVE_CORE_CONFIG_H

/*
 * Shared load-time configuration for target selection and the core function
 * tracer. vmlinux.h provides these types for BPF; linux/types.h provides them
 * for user space.
 */
struct cw_target_config {
    __u64 pidns_dev;
    __u64 pidns_ino;
    __u32 target_pid;
    __u32 reserved;
};

struct cw_trace_config {
    __u32 returns_enabled;
    __u32 attribution_enabled;
    __s32 futex_syscall_nr;
    __u32 reserved;
};

#endif
