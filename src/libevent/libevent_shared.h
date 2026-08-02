// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_LIBEVENT_SHARED_H
#define CALLWEAVE_LIBEVENT_SHARED_H

#define CW_LIBEVENT_COMM_LEN 16

#define CW_LIBEVENT_EV_TIMEOUT 0x01U
#define CW_LIBEVENT_EV_READ 0x02U
#define CW_LIBEVENT_EV_WRITE 0x04U
#define CW_LIBEVENT_EV_SIGNAL 0x08U
#define CW_LIBEVENT_EV_PERSIST 0x10U

enum cw_libevent_registration_action {
    CW_LIBEVENT_DEFINED = 1,
    CW_LIBEVENT_ACTIVATED,
};

enum cw_libevent_object_kind {
    CW_LIBEVENT_OBJECT_EVENT = 1,
    CW_LIBEVENT_OBJECT_BUFFEREVENT,
    CW_LIBEVENT_OBJECT_LISTENER,
};

enum cw_libevent_callback_role {
    CW_LIBEVENT_CALLBACK_EVENT = 1,
    CW_LIBEVENT_CALLBACK_READ,
    CW_LIBEVENT_CALLBACK_WRITE,
    CW_LIBEVENT_CALLBACK_STATUS,
    CW_LIBEVENT_CALLBACK_ACCEPT,
};

enum cw_libevent_kind {
    CW_LIBEVENT_KIND_UNKNOWN = 0,
    CW_LIBEVENT_KIND_IO,
    CW_LIBEVENT_KIND_TIMER,
    CW_LIBEVENT_KIND_SIGNAL,
};

struct cw_libevent_key {
    __u32 pid;
    __u32 reserved;
    __u64 event;
};

struct cw_libevent_registration {
    __u64 callback;
    __u64 callback_arg;
    __s32 fd;
    __u32 events;
    __u32 generation;
    __u32 active;
    __u32 kind;
    __u32 reserved;
};

struct cw_libevent_bufferevent {
    __u64 read_callback;
    __u64 write_callback;
    __u64 event_callback;
    __u64 callback_arg;
    __s32 fd;
    __u32 generation;
    __u32 enabled_events;
    __u32 active;
};

struct cw_libevent_listener {
    __u64 callback;
    __u64 callback_arg;
    __s32 fd;
    __u32 generation;
    __u32 active;
    __u32 reserved;
};

struct cw_libevent_registration_event {
    __u64 timestamp_ns;
    __u64 event;
    __u64 callback;
    __u64 callback_arg;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 fd;
    __u32 events;
    __u32 generation;
    __u32 action;
    __u32 kind;
    __u32 object_kind;
    __u32 callback_role;
    char comm[CW_LIBEVENT_COMM_LEN];
};

struct cw_libevent_counters {
    __u64 created;
    __u64 assigned;
    __u64 added;
    __u64 deleted;
    __u64 freed;
    __u64 io_events;
    __u64 timer_events;
    __u64 signal_events;
    __u64 unsupported_events;
    __u64 persistent_events;
    __u64 oneshot_events;
    __u64 registrations_emitted;
    __u64 registrations_dropped;
    __u64 definitions_missing;
    __u64 bufferevents_created;
    __u64 bufferevents_callbacks_set;
    __u64 bufferevents_fd_set;
    __u64 bufferevents_enabled;
    __u64 bufferevents_disabled;
    __u64 bufferevents_freed;
    __u64 listeners_created;
    __u64 listeners_freed;
    __u64 high_level_callbacks_emitted;
};

#endif
