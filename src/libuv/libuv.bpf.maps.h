// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_LIBUV_BPF_MAPS_H
#define CALLWEAVE_LIBUV_BPF_MAPS_H

struct cw_libuv_init_state {
    struct cw_libuv_handle_key key;
    __s32 fd;
    __u32 reserved;
};

struct cw_libuv_start_state {
    struct cw_libuv_handle_key key;
    __u64 callback;
    __u32 events;
    __u32 reserved;
};

struct cw_libuv_stop_state {
    struct cw_libuv_handle_key key;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct cw_libuv_handle_key);
    __type(value, struct cw_libuv_poll_handle);
} libuv_poll_handles SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libuv_init_state);
} libuv_init_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libuv_start_state);
} libuv_start_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libuv_stop_state);
} libuv_stop_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cw_libuv_counters);
} libuv_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} libuv_registration_events SEC(".maps");

#endif
