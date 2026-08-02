// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_LIBEVENT_BPF_MAPS_H
#define CALLWEAVE_LIBEVENT_BPF_MAPS_H

struct cw_libevent_definition_state {
    struct cw_libevent_key key;
    __u64 callback;
    __u64 callback_arg;
    __s32 fd;
    __u32 events;
};

struct cw_libevent_operation_state {
    struct cw_libevent_key key;
};

struct cw_libevent_bufferevent_new_state {
    struct cw_libevent_key key;
    __s32 fd;
    __u32 options;
};

struct cw_libevent_bufferevent_fd_state {
    struct cw_libevent_key key;
    __s32 fd;
    __u32 reserved;
};

struct cw_libevent_bufferevent_toggle_state {
    struct cw_libevent_key key;
    __u32 events;
    __u32 reserved;
};

struct cw_libevent_listener_new_state {
    struct cw_libevent_key key;
    __u64 callback;
    __u64 callback_arg;
    __s32 fd;
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct cw_libevent_key);
    __type(value, struct cw_libevent_registration);
} libevent_registrations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct cw_libevent_key);
    __type(value, struct cw_libevent_bufferevent);
} libevent_bufferevents SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cw_libevent_key);
    __type(value, struct cw_libevent_listener);
} libevent_listeners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct cw_libevent_key);
    __type(value, __u32);
} libevent_generations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_definition_state);
} libevent_new_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_definition_state);
} libevent_assign_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_operation_state);
} libevent_add_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_operation_state);
} libevent_del_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_bufferevent_new_state);
} libevent_bufferevent_new_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_bufferevent_fd_state);
} libevent_bufferevent_fd_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_bufferevent_toggle_state);
} libevent_bufferevent_enable_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_bufferevent_toggle_state);
} libevent_bufferevent_disable_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cw_libevent_listener_new_state);
} libevent_listener_new_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cw_libevent_counters);
} libevent_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} libevent_registration_events SEC(".maps");

#endif
