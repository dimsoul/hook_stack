// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_IO_URING_CONFIG_H
#define CALLWEAVE_IO_URING_CONFIG_H

/* Shared load-time configuration for the io_uring tracer. */
struct cw_io_uring_config {
    __u64 min_latency_ns;
    __u32 enabled;
    __u32 callback_enabled;
    __u32 callback_arg;
    __u32 errors_only;
};

#endif
