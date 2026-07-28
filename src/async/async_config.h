// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_ASYNC_CONFIG_H
#define CALLWEAVE_ASYNC_CONFIG_H

/*
 * Shared load-time configuration for cross-thread asynchronous correlation.
 * The target argument value of zero enables automatic argument matching.
 */
struct cw_async_config {
    __u64 max_age_ns;
    __u32 enabled;
    __u32 discovery_enabled;
    __u32 source_arg;
    __u32 target_arg;
    __u32 final_hop_id;
    __u32 reserved;
};

#endif
