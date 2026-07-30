// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_EPOLL_BPF_MAPS_H
#define CALLWEAVE_EPOLL_BPF_MAPS_H

struct cw_epoll_wait_state {
    __u64 start_ns;
    __u64 events_address;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 epoll_fd;
    __u32 epoll_generation;
    __s32 timeout_ms;
    __s32 stack_id;
    __u32 max_events;
    __u32 wait_kind;
    char comm[CW_EPOLL_COMM_LEN];
};

struct cw_epoll_ctl_state {
    __u64 data;
    __u32 pid;
    __s32 epoll_fd;
    __u32 epoll_generation;
    __s32 fd;
    __u32 fd_generation;
    __s32 operation;
    __u32 events;
};

struct cw_epoll_dispatch_key {
    __u64 pid_tgid;
    __s32 fd;
    __u32 reserved;
};

struct cw_epoll_dispatch_candidate {
    struct cw_epoll_dispatch_item item;
    __u64 last_requested_bytes;
    __u64 oneshot_rearms_at_ready;
};

struct cw_epoll_dispatch_batch {
    __u64 ready_ns;
    __u64 offcpu_start_ns;
    __u64 wakeup_ns;
    __u64 offcpu_ns;
    __u64 blocked_ns;
    __u64 runqueue_ns;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 epoll_fd;
    __u32 epoll_generation;
    __u32 count;
    char comm[CW_EPOLL_COMM_LEN];
    __s32 fds[CW_EPOLL_MAX_READY];
};

struct cw_epoll_io_state {
    struct cw_epoll_dispatch_key key;
    __u64 start_ns;
    __u64 requested_bytes;
    __u32 pid;
    __u32 operation;
    __u32 io_flags;
    __u32 reserved;
};

struct cw_epoll_callback_key {
    __u64 pid_tgid;
    __u32 depth;
    __u32 reserved;
};

struct cw_epoll_callback_frame {
    struct cw_epoll_callback_event event;
    __u32 matched;
    __u32 reserved;
};

struct cw_epoll_callback_thread {
    __u32 depth;
    __u32 reserved;
    __u64 offcpu_start_ns;
    __u64 wakeup_ns;
};

enum cw_epoll_wake_sys_action {
    CW_EPOLL_WAKE_SYS_NONE,
    CW_EPOLL_WAKE_SYS_CREATE_EVENTFD,
    CW_EPOLL_WAKE_SYS_CREATE_TIMERFD,
    CW_EPOLL_WAKE_SYS_CREATE_SIGNALFD,
    CW_EPOLL_WAKE_SYS_TIMERFD_SETTIME,
    CW_EPOLL_WAKE_SYS_EVENTFD_WRITE,
    CW_EPOLL_WAKE_SYS_CLOSE,
    CW_EPOLL_WAKE_SYS_DUP,
};

struct cw_epoll_wake_sys_state {
    struct cw_epoll_wake_source source;
    __u64 signal_mask;
    __u32 pid;
    __u32 action;
    __s32 fd;
    __s32 target_fd;
    __s32 clock_id;
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_wait_state);
} epoll_wait_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_ctl_state);
} epoll_ctl_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_resource_key);
    __type(value, struct cw_epoll_registration);
} epoll_registrations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_token_key);
    __type(value, struct cw_epoll_token_value);
} epoll_tokens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_resource_key);
    __type(value, struct cw_epoll_resource_stats);
} epoll_resource_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cw_epoll_resource_stats);
} epoll_resource_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cw_epoll_loop_key);
    __type(value, struct cw_epoll_loop_stats);
} epoll_loop_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cw_epoll_counters);
} epoll_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64[MAX_ASYNC_STACK_DEPTH]);
} epoll_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} epoll_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_dispatch_key);
    __type(value, struct cw_epoll_dispatch_candidate);
} epoll_dispatch_candidates SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_dispatch_batch);
} epoll_dispatch_batches SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_io_state);
} epoll_io_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_fd_key);
    __type(value, __u32);
} epoll_fd_generations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cw_epoll_instance_key);
    __type(value, struct cw_epoll_instance_stats);
} epoll_instance_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} epoll_dispatch_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_fd_key);
    __type(value, struct cw_epoll_fd_metadata);
} epoll_fd_metadata SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_fd_key);
    __type(value, struct cw_epoll_wake_source);
} epoll_wake_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_wake_sys_state);
} epoll_wake_sys_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct cw_epoll_wake_source);
} epoll_signal_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} epoll_target_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_wait_state);
} epoll_wake_wait_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_dispatch_key);
    __type(value, struct cw_epoll_wake_source);
} epoll_dispatch_wakes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cw_epoll_callback_thread);
} epoll_callback_threads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct cw_epoll_callback_key);
    __type(value, struct cw_epoll_callback_frame);
} epoll_callback_frames SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} epoll_callback_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} epoll_exec_gate SEC(".maps");

static __always_inline bool cw_epoll_capture_active(void)
{
    __u32 zero = 0;
    __u32 *active;

    if (!cw_epoll_cfg.enabled)
        return false;
    if (!cw_epoll_cfg.defer_until_exec)
        return true;
    active = bpf_map_lookup_elem(&epoll_exec_gate, &zero);
    return active && *active;
}

#endif
