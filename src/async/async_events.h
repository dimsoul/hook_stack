// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_ASYNC_EVENTS_H
#define CALLWEAVE_ASYNC_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#include "callweave_internal.h"

enum event_type {
    EVENT_ENTRY,
    EVENT_RETURN,
};

enum wait_kind {
    WAIT_KIND_NONE,
    WAIT_KIND_FUTEX,
};

struct wait_resource {
    uint64_t address;
    uint64_t duration_ns;
    uint64_t wake_ns;
    uint32_t kind;
    uint32_t operation;
    uint32_t waker_pid;
    uint32_t waker_tid;
    uint32_t waker_global_pid;
    uint32_t waker_global_tid;
    int32_t waker_stack_id;
    int32_t waker_pidns_error;
    char waker_comm[16];
};

struct async_hop_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_id;
    uint32_t reserved;
    uint64_t key;
    uint64_t source_ns;
    uint64_t notify_entry_ns;
    uint64_t notify_exit_ns;
    uint64_t epoll_enter_ns;
    uint64_t epoll_exit_ns;
    uint64_t queue_ns;
    uint64_t target_ns;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    uint32_t lifecycle_kind;
    uint32_t lifecycle_flags;
    struct wait_resource wait;
};

struct discovery_wakeup {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_id;
    int32_t pidns_error;
    uint64_t wake_ns;
};

struct stack_trace_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_size;
    int32_t pidns_error;
    uint32_t event_type;
    uint32_t reserved;
    uint64_t timestamp_ns;
    uint64_t duration_ns;
    int64_t return_value;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    struct wait_resource wait;
    uint32_t async_hop_count;
    uint32_t async_truncated;
    struct async_hop_event async_hops[MAX_ASYNC_HOPS];
    uint32_t discovery_valid;
    uint32_t discovery_reserved;
    struct discovery_wakeup discovery_waker;
    uint64_t discovery_wakeup_ns;
    uint64_t stack[MAX_STACK_DEPTH];
};

struct async_worker_key {
    uint32_t hop_index;
    uint32_t global_tid;
};

struct async_worker_stats {
    uint64_t started;
    uint64_t completed;
    uint64_t active;
    uint64_t peak_active;
    uint64_t work_total_ns;
    uint64_t blocked_total_ns;
    uint64_t futex_waits;
    uint32_t pid;
    uint32_t tid;
    char comm[16];
};

_Static_assert(offsetof(struct stack_trace_event, stack) == 1904,
               "userspace and BPF event layouts differ");
_Static_assert(sizeof(struct stack_trace_event) == 2928,
               "userspace and BPF event sizes differ");

#endif
