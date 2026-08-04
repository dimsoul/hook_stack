// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_EPOLL_SHARED_H
#define CALLWEAVE_EPOLL_SHARED_H

#define CW_EPOLL_COMM_LEN 16
#define CW_EPOLL_MAX_READY 16
#define CW_EPOLL_MAX_CALLBACK_DEPTH 8

enum cw_epoll_callback_match {
    CW_EPOLL_CALLBACK_MATCH_FD = 1,
    CW_EPOLL_CALLBACK_MATCH_DATA,
    CW_EPOLL_CALLBACK_MATCH_LIBUV,
    CW_EPOLL_CALLBACK_MATCH_LIBEVENT,
};

enum cw_epoll_io_operation {
    CW_EPOLL_IO_NONE,
    CW_EPOLL_IO_READ,
    CW_EPOLL_IO_READV,
    CW_EPOLL_IO_RECVFROM,
    CW_EPOLL_IO_RECVMSG,
    CW_EPOLL_IO_RECVMMSG,
    CW_EPOLL_IO_WRITE,
    CW_EPOLL_IO_WRITEV,
    CW_EPOLL_IO_SENDTO,
    CW_EPOLL_IO_SENDMSG,
    CW_EPOLL_IO_SENDMMSG,
    CW_EPOLL_IO_ACCEPT,
    CW_EPOLL_IO_ACCEPT4,
    CW_EPOLL_IO_CONNECT,
    CW_EPOLL_IO_CLOSE,
    CW_EPOLL_IO_DUP,
    CW_EPOLL_IO_DUP2,
    CW_EPOLL_IO_DUP3,
    CW_EPOLL_IO_FCNTL_DUP,
    CW_EPOLL_IO_SPLICE,
};

enum cw_epoll_dispatch_flags {
    CW_EPOLL_DISPATCH_CONSUMED = 1U << 0,
    CW_EPOLL_DISPATCH_EAGAIN = 1U << 1,
    CW_EPOLL_DISPATCH_SHORT_READ = 1U << 2,
    CW_EPOLL_DISPATCH_EOF = 1U << 3,
    CW_EPOLL_DISPATCH_CLOSED = 1U << 4,
    CW_EPOLL_DISPATCH_REARMED = 1U << 5,
    CW_EPOLL_DISPATCH_ET_CANDIDATE = 1U << 6,
    CW_EPOLL_DISPATCH_ET_UNDRAINED = 1U << 7,
    CW_EPOLL_DISPATCH_ONESHOT_CANDIDATE = 1U << 8,
    CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM = 1U << 9,
    CW_EPOLL_DISPATCH_MSG_PEEK = 1U << 10,
    CW_EPOLL_DISPATCH_CALLBACK_COMPLETED = 1U << 11,
};

enum cw_epoll_wait_kind {
    CW_EPOLL_WAIT,
    CW_EPOLL_PWAIT,
    CW_EPOLL_PWAIT2,
};

enum cw_epoll_wake_kind {
    CW_EPOLL_WAKE_NONE,
    CW_EPOLL_WAKE_EVENTFD,
    CW_EPOLL_WAKE_TIMERFD,
    CW_EPOLL_WAKE_SIGNALFD,
};

enum cw_epoll_wake_action {
    CW_EPOLL_WAKE_ACTION_NONE,
    CW_EPOLL_WAKE_ACTION_EVENTFD_WRITE,
    CW_EPOLL_WAKE_ACTION_TIMERFD_ARM,
    CW_EPOLL_WAKE_ACTION_SIGNAL_SEND,
};

enum cw_epoll_wake_flags {
    CW_EPOLL_WAKE_LATENCY_VALID = 1U << 0,
    CW_EPOLL_WAKE_TIMER_ABSTIME = 1U << 1,
    CW_EPOLL_WAKE_TIMER_DISARMED = 1U << 2,
};

struct cw_epoll_wake_source {
    __u64 first_timestamp_ns;
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u64 operations;
    __u64 value;
    __u64 timer_initial_ns;
    __u64 timer_interval_ns;
    __u32 kind;
    __u32 action;
    __u32 flags;
    __u32 signal_number;
    __u32 source_pid;
    __u32 source_tid;
    __u32 source_global_pid;
    __u32 source_global_tid;
    __s32 stack_id;
    __u32 reserved;
    char comm[CW_EPOLL_COMM_LEN];
};

struct cw_epoll_futex_wait {
    __u64 address;
    __u64 duration_ns;
    __u64 wake_ns;
    __u32 operation;
    __u32 waker_pid;
    __u32 waker_tid;
    __u32 waker_global_pid;
    __u32 waker_global_tid;
    __s32 waker_stack_id;
    __s32 waker_pidns_error;
    char waker_comm[CW_EPOLL_COMM_LEN];
    __u32 reserved;
};

struct cw_epoll_fd_metadata {
    __u64 signal_mask;
    __u32 kind;
    __s32 clock_id;
    struct cw_epoll_wake_source timer_source;
};

struct cw_epoll_ready {
    __u64 data;
    __s32 fd;
    __u32 events;
};

struct cw_epoll_event {
    __u64 timestamp_ns;
    __u64 start_ns;
    __u64 wait_ns;
    __u64 events_address;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 epoll_fd;
    __s32 result;
    __s32 timeout_ms;
    __s32 stack_id;
    __u32 max_events;
    __u32 captured_events;
    __u32 unresolved_events;
    __u32 wait_kind;
    char comm[CW_EPOLL_COMM_LEN];
    struct cw_epoll_ready ready[CW_EPOLL_MAX_READY];
};

struct cw_epoll_counters {
    __u64 calls;
    __u64 ready_returns;
    __u64 ready_events;
    __u64 timeouts;
    __u64 errors;
    __u64 interrupted;
    __u64 saturated_batches;
    __u64 truncated_events;
    __u64 unresolved_events;
    __u64 emitted;
    __u64 dropped;
    __u64 dispatches;
    __u64 unconsumed;
    __u64 dispatch_emitted;
    __u64 dispatch_dropped;
    __u64 io_errors;
    __u64 potential_et_undrained;
    __u64 potential_oneshot_missing_rearm;
    __u64 fd_closes;
    __u64 fd_duplications;
    __u64 fd_reuses;
    __u64 wake_ready;
    __u64 wake_attributed;
    __u64 eventfd_ready;
    __u64 timerfd_ready;
    __u64 signalfd_ready;
    __u64 callback_matched;
    __u64 callback_fd_matched;
    __u64 callback_data_matched;
    __u64 callback_libuv_matched;
    __u64 callback_libevent_matched;
    __u64 callback_unmatched;
    __u64 callback_completed;
    __u64 callback_overflow;
    __u64 callback_emitted;
    __u64 callback_dropped;
    __u64 callback_futex_waits;
    __u64 callback_futex_wait_ns;
    __u64 evidence_exact;
    __u64 evidence_ready_to_io;
    __u64 evidence_ready_only;
};

struct cw_epoll_loop_key {
    __u32 global_pid;
    __u32 global_tid;
    __s32 epoll_fd;
    __u32 epoll_generation;
};

struct cw_epoll_loop_stats {
    __u64 first_ns;
    __u64 last_ns;
    __u64 calls;
    __u64 ready_returns;
    __u64 ready_events;
    __u64 total_wait_ns;
    __u64 maximum_wait_ns;
    __u64 timeouts;
    __u64 errors;
    __u64 interrupted;
    __u64 saturated_batches;
    __u64 truncated_events;
    __u64 unresolved_events;
    __u64 maximum_batch;
    __u64 dispatches;
    __u64 unconsumed;
    __u64 total_dispatch_ns;
    __u64 maximum_dispatch_ns;
    __u64 potential_et_undrained;
    __u64 io_errors;
    __u64 cycles;
    __u64 total_cycle_ns;
    __u64 maximum_cycle_ns;
    __u64 cycle_offcpu_ns;
    __u64 cycle_blocked_ns;
    __u64 cycle_runqueue_ns;
    __u64 potential_oneshot_missing_rearm;
    __u32 pid;
    __u32 tid;
    __s32 stack_id;
    char comm[CW_EPOLL_COMM_LEN];
};

struct cw_epoll_resource_key {
    __u32 pid;
    __s32 epoll_fd;
    __u32 epoll_generation;
    __s32 fd;
    __u32 fd_generation;
};

struct cw_epoll_resource_stats {
    __u64 data;
    __u64 ready_count;
    __u64 last_ready_ns;
    __u32 interest_events;
    __u32 observed_events;
    __u32 registrations;
    __u32 active;
    __u64 dispatches;
    __u64 unconsumed;
    __u64 total_dispatch_ns;
    __u64 maximum_dispatch_ns;
    __u64 io_calls;
    __u64 bytes_read;
    __u64 bytes_written;
    __u64 io_errors;
    __u64 eagain;
    __u64 potential_et_undrained;
    __u64 oneshot_events;
    __u64 oneshot_rearms;
    __u64 potential_oneshot_missing_rearm;
    __s32 dispatch_stack_id;
    __u32 reserved;
    __u64 wake_ready;
    __u64 wake_attributed;
    __u64 wake_operations;
    __u64 wake_last_source_timestamp_ns;
    __u64 wake_latency_samples;
    __u64 wake_total_latency_ns;
    __u64 wake_maximum_latency_ns;
    struct cw_epoll_wake_source last_wake;
    __u64 callback_matched;
    __u64 callback_completed;
    __u64 callback_total_delay_ns;
    __u64 callback_maximum_delay_ns;
    __u64 callback_total_duration_ns;
    __u64 callback_maximum_duration_ns;
    __u64 callback_offcpu_ns;
    __u64 callback_blocked_ns;
    __u64 callback_runqueue_ns;
    __u64 callback_futex_waits;
    __u64 callback_futex_wait_ns;
    __u64 callback_slowest_blocked_ns;
    __u64 callback_slowest_futex_waits;
    __u64 callback_slowest_futex_wait_ns;
    __u64 callback_key;
    __s32 callback_stack_id;
    __u32 callback_reserved;
    struct cw_epoll_futex_wait callback_slowest_futex_wait;
};

struct cw_epoll_token_key {
    __u64 data;
    __u32 pid;
    __s32 epoll_fd;
    __u32 epoll_generation;
    __u32 reserved;
};

struct cw_epoll_token_value {
    __s32 fd;
    __u32 fd_generation;
    __u32 ambiguous;
    __u32 reserved;
};

struct cw_epoll_registration {
    __u64 data;
    __u32 events;
    __u32 reserved;
};

struct cw_epoll_dispatch_item {
    __u64 data;
    __u64 ready_ns;
    __u64 first_io_ns;
    __u64 last_io_ns;
    __u64 total_io_ns;
    __u64 bytes_read;
    __u64 bytes_written;
    __u64 requested_bytes;
    __u32 ready_events;
    __u32 interest_events;
    __u32 io_calls;
    __u32 read_calls;
    __u32 write_calls;
    __u32 flags;
    __s32 fd;
    __u32 epoll_generation;
    __u32 fd_generation;
    __s32 first_operation;
    __s32 last_operation;
    __s32 last_result;
    __s32 stack_id;
    __u32 io_errors;
    struct cw_epoll_wake_source wake;
};

struct cw_epoll_dispatch_event {
    __u64 timestamp_ns;
    __u64 return_to_wait_ns;
    __u64 cycle_offcpu_ns;
    __u64 cycle_blocked_ns;
    __u64 cycle_runqueue_ns;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 epoll_fd;
    __u32 reserved;
    char comm[CW_EPOLL_COMM_LEN];
    struct cw_epoll_dispatch_item item;
};

struct cw_epoll_callback_event {
    __u64 timestamp_ns;
    __u64 ready_ns;
    __u64 start_ns;
    __u64 delay_ns;
    __u64 duration_ns;
    __u64 offcpu_ns;
    __u64 blocked_ns;
    __u64 runqueue_ns;
    __u64 futex_waits;
    __u64 futex_wait_ns;
    __u64 data;
    __u64 callback_key;
    __u64 callback_address;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 epoll_fd;
    __s32 fd;
    __u32 epoll_generation;
    __u32 fd_generation;
    __u32 ready_events;
    __u32 match_kind;
    __s32 stack_id;
    char comm[CW_EPOLL_COMM_LEN];
    struct cw_epoll_wake_source wake;
    struct cw_epoll_futex_wait longest_futex_wait;
};

struct cw_epoll_fd_key {
    __u32 pid;
    __s32 fd;
};

struct cw_epoll_instance_key {
    __u32 pid;
    __s32 epoll_fd;
    __u32 epoll_generation;
    __u32 reserved;
};

struct cw_epoll_instance_stats {
    __u64 calls;
    __u64 ready_returns;
    __u64 ready_events;
    __u64 active_waiters;
    __u64 peak_waiters;
    __u64 exclusive_resources;
};

#endif
