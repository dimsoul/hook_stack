// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_IO_URING_SHARED_H
#define CALLWEAVE_IO_URING_SHARED_H

/*
 * Shared ABI between the BPF programs and the user-space reader.
 * vmlinux.h provides these types for BPF; linux/types.h provides them
 * for user space.
 */

#define CW_IO_URING_COMM_LEN 16

struct io_uring_request_state {
    __u64 submit_ns;
    __u64 defer_ns;
    __u64 async_queue_ns;
    __u64 worker_start_ns;
    __u64 ring_ctx;
    __u64 user_data;
    __u64 request_flags;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 fd;
    __s32 stack_id;
    __u8 opcode;
    __u8 sq_thread;
    __u8 deferred;
    __u8 io_wq;
    __u8 io_wq_hashed;
    __u8 poll_armed;
    __u16 reserved;
    char comm[CW_IO_URING_COMM_LEN];
};

struct io_uring_event {
    __u64 timestamp_ns;
    __u64 submit_ns;
    __u64 duration_ns;
    __u64 defer_delay_ns;
    __u64 io_wq_queue_ns;
    __u64 after_io_wq_ns;
    __u64 ring_ctx;
    __u64 request;
    __u64 user_data;
    __u64 request_flags;
    __u32 submit_pid;
    __u32 submit_tid;
    __u32 submit_global_pid;
    __u32 submit_global_tid;
    __u32 complete_global_pid;
    __u32 complete_global_tid;
    __s32 fd;
    __s32 result;
    __u32 cqe_flags;
    __s32 stack_id;
    __u8 opcode;
    __u8 sq_thread;
    __u8 deferred;
    __u8 io_wq;
    __u8 io_wq_hashed;
    __u8 poll_armed;
    __u16 reserved;
    char submit_comm[CW_IO_URING_COMM_LEN];
    char complete_comm[CW_IO_URING_COMM_LEN];
};

struct io_uring_counters {
    __u64 submitted;
    __u64 completions;
    __u64 finished;
    __u64 pending;
    __u64 peak_pending;
    __u64 unmatched;
    __u64 dropped_events;
    __u64 errors;
    __u64 expected_timeouts;
    __u64 callback_matched;
    __u64 callback_unmatched;
    __u64 callback_dropped;
};

struct io_uring_aggregate_key {
    __u64 ring_ctx;
    __s32 stack_id;
    __s32 fd;
    __u32 opcode;
    __u32 reserved;
};

struct io_uring_aggregate {
    __u64 count;
    __u64 errors;
    __u64 total_ns;
    __u64 maximum_ns;
    __u64 slow_count;
    __u64 deferred_count;
    __u64 io_wq_count;
    __u64 io_wq_queue_total_ns;
    __u64 io_wq_queue_maximum_ns;
};

struct io_uring_result_key {
    __s32 result;
    __u32 opcode;
};

struct io_uring_ring_stats {
    __u64 submitted;
    __u64 completions;
    __u64 errors;
    __u64 expected_timeouts;
    __u64 pending;
    __u64 peak_pending;
    __u64 total_ns;
    __u64 maximum_ns;
    __u64 deferred;
    __u64 io_wq;
    __u64 io_wq_hashed;
    __u64 io_wq_queue_total_ns;
    __u64 io_wq_queue_maximum_ns;
    __u64 poll_armed;
    __u64 cq_waits;
    __u64 cq_overflows;
    __u64 request_failures;
    __u64 links;
    __u64 failed_links;
    __u64 registrations;
    __u32 owner_pid;
    __s32 ring_fd;
    __u32 flags;
    __u32 sq_entries;
    __u32 cq_entries;
    __u32 registered_files;
    __u32 registered_buffers;
};

struct io_uring_failure_key {
    __u64 ring_ctx;
    __s32 error;
    __u32 opcode;
};

struct io_uring_failure_stats {
    __u64 count;
    __u64 user_data;
    __u64 offset;
    __u64 address;
    __u64 address3;
    __u32 length;
    __u32 operation_flags;
    __u32 file_index;
    __u16 buffer_index;
    __u8 sqe_flags;
    __u8 ioprio;
};

struct io_uring_link_key {
    __u64 ring_ctx;
    __u64 parent_user_data;
    __u64 child_user_data;
};

struct io_uring_link_stats {
    __u64 parent_request;
    __u64 child_request;
    __u64 count;
    __u64 failures;
    __u8 parent_opcode;
    __u8 child_opcode;
    __u16 reserved;
    __u32 reserved2;
};

struct io_uring_completion_key {
    __u32 global_pid;
    __u32 reserved;
    __u64 user_data;
};

struct io_uring_completion_context {
    __u64 completion_ns;
    __u64 submit_ns;
    __u64 duration_ns;
    __u64 ring_ctx;
    __u64 request;
    __s32 result;
    __u32 cqe_flags;
    __u8 opcode;
    __u8 reserved[7];
};

struct io_uring_callback_event {
    __u64 timestamp_ns;
    __u64 completion_ns;
    __u64 callback_delay_ns;
    __u64 request_duration_ns;
    __u64 ring_ctx;
    __u64 request;
    __u64 user_data;
    __u32 pid;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 result;
    __u32 cqe_flags;
    __s32 stack_id;
    __u8 opcode;
    __u8 reserved[3];
    char comm[CW_IO_URING_COMM_LEN];
};

#endif
