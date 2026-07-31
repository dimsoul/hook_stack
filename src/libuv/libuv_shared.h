// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_LIBUV_SHARED_H
#define CALLWEAVE_LIBUV_SHARED_H

#define CW_LIBUV_COMM_LEN 16

struct cw_libuv_handle_key {
    __u32 pid;
    __u32 reserved;
    __u64 handle;
};

struct cw_libuv_poll_handle {
    __u64 callback;
    __u32 events;
    __s32 fd;
    __u32 generation;
    __u32 active;
};

struct cw_libuv_registration_event {
    __u64 timestamp_ns;
    __u64 handle;
    __u64 callback;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 events;
    __s32 fd;
    __u32 generation;
    char comm[CW_LIBUV_COMM_LEN];
};

struct cw_libuv_counters {
    __u64 initialized;
    __u64 started;
    __u64 stopped;
    __u64 closed;
    __u64 registrations_emitted;
    __u64 registrations_dropped;
};

#endif
