// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "core/core_config.h"
#include "async/async_config.h"
#include "epoll/epoll_config.h"
#include "epoll/epoll_shared.h"
#include "libuv/libuv_shared.h"
#include "libevent/libevent_shared.h"
#include "io_uring/io_uring_config.h"
#include "io_uring/io_uring_shared.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 128
#define MAX_ASYNC_STACK_DEPTH 127
#define MAX_ASYNC_HOPS 8
#define MAX_NESTED_CALLS 16
#define ASYNC_HOP_ID_MASK 0xffffU
#define ASYNC_TARGET_ARG_SHIFT 16
#define FUTEX_CMD_MASK 0x7fU
#define FUTEX_WAIT 0U
#define FUTEX_WAKE 1U
#define FUTEX_WAIT_BITSET 9U
#define FUTEX_WAKE_BITSET 10U
#define IO_URING_CQE_F_MORE (1U << 1)
#define IO_URING_OP_TIMEOUT 11U
#define IO_URING_ETIME 62

enum wait_kind {
    WAIT_KIND_NONE,
    WAIT_KIND_FUTEX,
};

enum event_type {
    EVENT_ENTRY,
    EVENT_RETURN,
};

struct wait_resource {
    u64 address;
    u64 duration_ns;
    u64 wake_ns;
    u32 kind;
    u32 operation;
    u32 waker_pid;
    u32 waker_tid;
    u32 waker_global_pid;
    u32 waker_global_tid;
    s32 waker_stack_id;
    s32 waker_pidns_error;
    char waker_comm[16];
};

struct async_hop_event {
    u32 pid;
    u32 tid;
    u32 global_pid;
    u32 global_tid;
    char comm[16];
    s32 stack_id;
    u32 reserved;
    u64 key;
    u64 queue_ns;
    u64 target_ns;
    u64 offcpu_ns;
    u64 blocked_ns;
    u64 runqueue_ns;
    struct wait_resource wait;
};

struct discovery_wakeup {
    u32 pid;
    u32 tid;
    u32 global_pid;
    u32 global_tid;
    char comm[16];
    s32 stack_id;
    s32 pidns_error;
    u64 wake_ns;
};

struct stack_trace_event {
    u32 pid;
    u32 tid;
    u32 global_pid;
    u32 global_tid;
    char comm[16];
    s32 stack_size;
    s32 pidns_error;
    u32 event_type;
    u32 reserved;
    u64 timestamp_ns;
    u64 duration_ns;
    s64 return_value;
    u64 offcpu_ns;
    u64 blocked_ns;
    u64 runqueue_ns;
    struct wait_resource wait;
    u32 async_hop_count;
    u32 async_truncated;
    struct async_hop_event async_hops[MAX_ASYNC_HOPS];
    u32 discovery_valid;
    u32 discovery_reserved;
    struct discovery_wakeup discovery_waker;
    u64 discovery_wakeup_ns;
    u64 stack[MAX_STACK_DEPTH];
};

struct thread_state {
    u32 depth;
    u32 reserved;
    u64 offcpu_start_ns;
    u64 wakeup_ns;
};

struct invocation_key {
    u64 pid_tgid;
    u32 depth;
    u32 reserved;
};

struct invocation_state {
    u64 start_ns;
    u64 offcpu_ns;
    u64 blocked_ns;
    u64 runqueue_ns;
    struct wait_resource wait;
    u32 async_stats_done;
    u32 reserved;
};

struct async_context_key {
    u32 global_pid;
    u32 reserved;
    u64 value;
};

struct async_hop_context {
    u32 pid;
    u32 tid;
    u32 global_pid;
    u32 global_tid;
    char comm[16];
    s32 stack_id;
    u32 reserved;
    u64 key;
    u64 source_ns;
    u64 queue_ns;
    u64 target_ns;
    u64 offcpu_ns;
    u64 blocked_ns;
    u64 runqueue_ns;
    struct wait_resource wait;
};

struct async_chain {
    u32 hop_count;
    u32 truncated;
    struct async_hop_context hops[MAX_ASYNC_HOPS];
};

struct async_target_thread {
    u32 depth;
    u32 reserved;
    u64 offcpu_start_ns;
    u64 wakeup_ns;
};

struct async_hop_stats {
    u64 submitted;
    u64 started;
    u64 completed;
    u64 pending;
    u64 peak_pending;
    u64 active;
    u64 peak_active;
    u64 queue_total_ns;
    u64 work_total_ns;
    u64 futex_waits;
    u64 futex_wait_ns;
    u64 duplicate_keys;
    u64 expired;
    u64 unmatched_targets;
    u64 dropped;
};

struct async_worker_key {
    u32 hop_index;
    u32 global_tid;
};

struct async_worker_stats {
    u64 started;
    u64 completed;
    u64 active;
    u64 peak_active;
    u64 work_total_ns;
    u64 blocked_total_ns;
    u64 futex_waits;
    u32 pid;
    u32 tid;
    char comm[16];
};

struct futex_wait_state {
    u64 address;
    u64 start_ns;
    u32 operation;
    u32 reserved;
};

struct futex_resource_key {
    u32 global_pid;
    u32 reserved;
    u64 address;
};

struct futex_waker {
    u64 wake_ns;
    u32 pid;
    u32 tid;
    u32 global_pid;
    u32 global_tid;
    s32 stack_id;
    s32 pidns_error;
    char comm[16];
};

_Static_assert(__builtin_offsetof(struct stack_trace_event, stack) == 1520,
               "unexpected BPF event layout");
_Static_assert(sizeof(struct stack_trace_event) == 2544,
               "unexpected BPF event size");

const volatile struct cw_target_config cw_target_cfg = {0};
const volatile struct cw_trace_config cw_trace_cfg = {0};
const volatile struct cw_async_config cw_async_cfg = {0};
const volatile struct cw_epoll_config cw_epoll_cfg = {0};
const volatile struct cw_io_uring_config cw_io_uring_cfg = {0};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct thread_state);
} thread_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct invocation_key);
    __type(value, struct invocation_state);
} invocation_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct async_context_key);
    __type(value, struct async_chain);
} async_contexts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct async_chain);
} async_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64[MAX_ASYNC_STACK_DEPTH]);
} async_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct async_target_thread);
} async_target_threads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct invocation_key);
    __type(value, struct invocation_state);
} async_target_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct invocation_key);
    __type(value, struct async_chain);
} active_lineages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct invocation_key);
    __type(value, struct async_chain);
} final_lineages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct discovery_wakeup);
} discovery_wakeups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} discovery_target_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64[MAX_ASYNC_STACK_DEPTH]);
} discovery_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct futex_wait_state);
} futex_waits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct futex_resource_key);
    __type(value, struct futex_waker);
} futex_wakers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ASYNC_HOPS);
    __type(key, u32);
    __type(value, struct async_hop_stats);
} async_hop_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct async_worker_key);
    __type(value, struct async_worker_stats);
} async_worker_stats SEC(".maps");

#include "io_uring/io_uring.bpf.maps.h"
#include "epoll/epoll.bpf.maps.h"
#include "libuv/libuv.bpf.maps.h"
#include "libevent/libevent.bpf.maps.h"

static __always_inline int get_process_info(u64 *pid_tgid, u32 *global_pid,
                                            u32 *global_tid, u32 *pid,
                                            u32 *tid, s32 *pidns_error)
{
    struct bpf_pidns_info pidns = {0};

    *pid_tgid = bpf_get_current_pid_tgid();
    *global_pid = *pid_tgid >> 32;
    *global_tid = (u32)*pid_tgid;
    *pid = *global_pid;
    *tid = *global_tid;
    *pidns_error = bpf_get_ns_current_pid_tgid(
        cw_target_cfg.pidns_dev, cw_target_cfg.pidns_ino, &pidns, sizeof(pidns));
    if (!*pidns_error) {
        *pid = pidns.tgid;
        *tid = pidns.pid;
    }

    return !cw_target_cfg.target_pid || *pid == cw_target_cfg.target_pid;
}

static __always_inline void fill_process_info(struct stack_trace_event *event,
                                              u32 global_pid, u32 global_tid,
                                              u32 pid, u32 tid,
                                              s32 pidns_error)
{
    event->global_pid = global_pid;
    event->global_tid = global_tid;
    event->pid = pid;
    event->tid = tid;
    event->pidns_error = pidns_error;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline u64 task_pid_tgid(struct task_struct *task)
{
    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task, tgid);

    return (u64)tgid << 32 | pid;
}

static __always_inline u64 read_uprobe_stack_argument(
    struct pt_regs *ctx, u32 slot)
{
    u64 value = 0;
    u64 address = PT_REGS_SP_CORE(ctx) + slot * sizeof(value);

    if (bpf_probe_read_user(&value, sizeof(value),
                            (const void *)address))
        return 0;
    return value;
}

static __always_inline u64 read_uprobe_argument(struct pt_regs *ctx, u32 index)
{
    switch (index) {
    case 1:
        return PT_REGS_PARM1_CORE(ctx);
    case 2:
        return PT_REGS_PARM2_CORE(ctx);
    case 3:
        return PT_REGS_PARM3_CORE(ctx);
    case 4:
        return PT_REGS_PARM4_CORE(ctx);
    case 5:
        return PT_REGS_PARM5_CORE(ctx);
    case 6:
#if defined(__TARGET_ARCH_s390)
        return 0;
#else
        return PT_REGS_PARM6_CORE(ctx);
#endif
    case 7:
#if defined(__TARGET_ARCH_x86)
        return read_uprobe_stack_argument(ctx, 1);
#elif defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_mips) || \
      defined(__TARGET_ARCH_powerpc) || defined(__TARGET_ARCH_riscv)
        return PT_REGS_PARM7_CORE(ctx);
#else
        return 0;
#endif
    case 8:
#if defined(__TARGET_ARCH_x86)
        return read_uprobe_stack_argument(ctx, 2);
#elif defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_mips) || \
      defined(__TARGET_ARCH_powerpc) || defined(__TARGET_ARCH_riscv)
        return PT_REGS_PARM8_CORE(ctx);
#else
        return 0;
#endif
    default:
        return 0;
    }
}

static __always_inline int try_target_argument(
    struct pt_regs *ctx, u32 global_pid, u32 argument,
    u64 *matched_value, u32 *matched_argument)
{
    struct async_context_key key = {
        .global_pid = global_pid,
    };

    key.value = read_uprobe_argument(ctx, argument);
    if (!key.value || !bpf_map_lookup_elem(&async_contexts, &key))
        return 0;
    if (*matched_argument)
        return -1;
    *matched_value = key.value;
    *matched_argument = argument;
    return 0;
}

static __always_inline u64 resolve_target_key(
    struct pt_regs *ctx, u32 global_pid, u32 configured_argument,
    u32 *matched_argument)
{
    u64 matched_value = 0;

    *matched_argument = 0;
    if (configured_argument) {
        *matched_argument = configured_argument;
        return read_uprobe_argument(ctx, configured_argument);
    }
    if (try_target_argument(ctx, global_pid, 1, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 2, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 3, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 4, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 5, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 6, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 7, &matched_value,
                            matched_argument) ||
        try_target_argument(ctx, global_pid, 8, &matched_value,
                            matched_argument))
        return 0;
    return matched_value;
}

static __always_inline void move_async_hop(
    struct async_hop_context *destination,
    const struct async_hop_context *source)
{
    destination->pid = source->pid;
    destination->tid = source->tid;
    destination->global_pid = source->global_pid;
    destination->global_tid = source->global_tid;
    __builtin_memcpy(destination->comm, source->comm,
                     sizeof(destination->comm));
    destination->stack_id = source->stack_id;
    destination->reserved = source->reserved;
    destination->key = source->key;
    destination->source_ns = source->source_ns;
    destination->queue_ns = source->queue_ns;
    destination->target_ns = source->target_ns;
    destination->offcpu_ns = source->offcpu_ns;
    destination->blocked_ns = source->blocked_ns;
    destination->runqueue_ns = source->runqueue_ns;
    __builtin_memcpy(&destination->wait, &source->wait,
                     sizeof(destination->wait));
}

static __always_inline u32 async_hop_index(u32 reserved)
{
    u32 hop_id = reserved & ASYNC_HOP_ID_MASK;

    return hop_id ? hop_id - 1 : 0;
}

static __always_inline void update_peak(u64 *peak, u64 value)
{
    u64 previous = *peak;

    if (value > previous)
        __sync_val_compare_and_swap(peak, previous, value);
}

static __always_inline void async_stats_submitted(u32 hop_index,
                                                  int duplicate)
{
    struct async_hop_stats *stats;
    u64 pending;

    if (hop_index >= MAX_ASYNC_HOPS)
        return;
    stats = bpf_map_lookup_elem(&async_hop_stats, &hop_index);
    if (!stats)
        return;
    __sync_fetch_and_add(&stats->submitted, 1);
    if (duplicate) {
        __sync_fetch_and_add(&stats->duplicate_keys, 1);
        return;
    }
    pending = __sync_add_and_fetch(&stats->pending, 1);
    update_peak(&stats->peak_pending, pending);
}

static __always_inline void async_stats_unmatched(u32 hop_index)
{
    struct async_hop_stats *stats;

    if (hop_index >= MAX_ASYNC_HOPS)
        return;
    stats = bpf_map_lookup_elem(&async_hop_stats, &hop_index);
    if (stats)
        __sync_fetch_and_add(&stats->unmatched_targets, 1);
}

static __always_inline void async_stats_expired(u32 hop_index)
{
    struct async_hop_stats *stats;

    if (hop_index >= MAX_ASYNC_HOPS)
        return;
    stats = bpf_map_lookup_elem(&async_hop_stats, &hop_index);
    if (!stats)
        return;
    if (stats->pending)
        __sync_fetch_and_sub(&stats->pending, 1);
    __sync_fetch_and_add(&stats->expired, 1);
}

static __always_inline void async_stats_started(
    u32 hop_index, u64 queue_ns, u32 pid, u32 tid, u32 global_tid)
{
    struct async_worker_key worker_key = {
        .hop_index = hop_index,
        .global_tid = global_tid,
    };
    struct async_worker_stats initial_worker = {
        .pid = pid,
        .tid = tid,
    };
    struct async_worker_stats *worker;
    struct async_hop_stats *stats;
    u64 active;
    u64 worker_active;

    if (hop_index >= MAX_ASYNC_HOPS)
        return;
    stats = bpf_map_lookup_elem(&async_hop_stats, &hop_index);
    if (!stats)
        return;
    if (stats->pending)
        __sync_fetch_and_sub(&stats->pending, 1);
    __sync_fetch_and_add(&stats->started, 1);
    __sync_fetch_and_add(&stats->queue_total_ns, queue_ns);
    active = __sync_add_and_fetch(&stats->active, 1);
    update_peak(&stats->peak_active, active);

    bpf_get_current_comm(initial_worker.comm, sizeof(initial_worker.comm));
    bpf_map_update_elem(&async_worker_stats, &worker_key,
                        &initial_worker, BPF_NOEXIST);
    worker = bpf_map_lookup_elem(&async_worker_stats, &worker_key);
    if (!worker)
        return;
    worker->pid = pid;
    worker->tid = tid;
    __builtin_memcpy(worker->comm, initial_worker.comm,
                     sizeof(worker->comm));
    __sync_fetch_and_add(&worker->started, 1);
    worker_active = __sync_add_and_fetch(&worker->active, 1);
    update_peak(&worker->peak_active, worker_active);
}

static __always_inline void async_stats_completed(
    u32 hop_index, u64 work_ns, u64 blocked_ns,
    u32 wait_kind, u64 wait_duration_ns, u32 global_tid, int dropped)
{
    struct async_worker_key worker_key = {
        .hop_index = hop_index,
        .global_tid = global_tid,
    };
    struct async_worker_stats *worker;
    struct async_hop_stats *stats;

    if (hop_index >= MAX_ASYNC_HOPS)
        return;
    stats = bpf_map_lookup_elem(&async_hop_stats, &hop_index);
    if (!stats)
        return;
    if (stats->active)
        __sync_fetch_and_sub(&stats->active, 1);
    __sync_fetch_and_add(&stats->completed, 1);
    __sync_fetch_and_add(&stats->work_total_ns, work_ns);
    if (wait_kind == WAIT_KIND_FUTEX) {
        __sync_fetch_and_add(&stats->futex_waits, 1);
        __sync_fetch_and_add(&stats->futex_wait_ns, wait_duration_ns);
    }
    if (dropped)
        __sync_fetch_and_add(&stats->dropped, 1);

    worker = bpf_map_lookup_elem(&async_worker_stats, &worker_key);
    if (!worker)
        return;
    if (worker->active)
        __sync_fetch_and_sub(&worker->active, 1);
    __sync_fetch_and_add(&worker->completed, 1);
    __sync_fetch_and_add(&worker->work_total_ns, work_ns);
    __sync_fetch_and_add(&worker->blocked_total_ns, blocked_ns);
    if (wait_kind == WAIT_KIND_FUTEX)
        __sync_fetch_and_add(&worker->futex_waits, 1);
}

SEC("uprobe")
int trace_async_source(struct pt_regs *ctx)
{
    struct async_context_key key = {0};
    struct async_target_thread *target_thread;
    struct async_chain *scratch;
    struct async_chain *active = NULL;
    struct async_hop_context *hop;
    struct invocation_key lineage_key = {0};
    u64 cookie;
    u64 pid_tgid;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    u32 zero = 0;
    u32 argument;
    u32 hop_index;
    u32 stats_hop;
    u32 depth = 0;
    u64 now;
    int duplicate;
    int i;
    s32 pidns_error;

    if (!cw_async_cfg.enabled ||
        !get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;

    cookie = bpf_get_attach_cookie(ctx);
    argument = cookie ? (u32)cookie : cw_async_cfg.source_arg;
    key.global_pid = global_pid;
    key.value = read_uprobe_argument(ctx, argument);
    if (!key.value)
        return 0;
    duplicate = bpf_map_lookup_elem(&async_contexts, &key) != NULL;

    scratch = bpf_map_lookup_elem(&async_scratch, &zero);
    if (!scratch)
        return 0;

    target_thread = bpf_map_lookup_elem(&async_target_threads, &pid_tgid);
    if (target_thread) {
        depth = target_thread->depth;
        if (depth > MAX_NESTED_CALLS)
            depth = MAX_NESTED_CALLS;
        if (depth) {
            lineage_key.pid_tgid = pid_tgid;
            lineage_key.depth = depth - 1;
            active = bpf_map_lookup_elem(&active_lineages, &lineage_key);
        }
    }

    now = bpf_ktime_get_ns();
    if (active) {
        struct invocation_state *invocation;

        scratch->hop_count = active->hop_count;
        scratch->truncated = active->truncated;
#pragma unroll
        for (i = 0; i < MAX_ASYNC_HOPS; i++)
            move_async_hop(&scratch->hops[i], &active->hops[i]);
        lineage_key.pid_tgid = pid_tgid;
        lineage_key.depth = depth - 1;
        invocation = bpf_map_lookup_elem(&async_target_invocations,
                                         &lineage_key);
        if (invocation && scratch->hop_count) {
            u32 last = scratch->hop_count - 1;

            if (last < MAX_ASYNC_HOPS) {
                struct async_hop_context *previous =
                    &scratch->hops[last];

                previous->target_ns = now - invocation->start_ns;
                previous->offcpu_ns = invocation->offcpu_ns;
                previous->blocked_ns = invocation->blocked_ns;
                previous->runqueue_ns = invocation->runqueue_ns;
                __builtin_memcpy(&previous->wait, &invocation->wait,
                                 sizeof(previous->wait));
                if (!invocation->async_stats_done) {
                    invocation->async_stats_done = 1;
                    async_stats_completed(
                        async_hop_index(previous->reserved),
                        previous->target_ns, previous->blocked_ns,
                        previous->wait.kind, previous->wait.duration_ns,
                        global_tid, 0);
                    scratch = bpf_map_lookup_elem(&async_scratch, &zero);
                    if (!scratch)
                        return 0;
                }
            }
        }
    } else {
        scratch->hop_count = 0;
        scratch->truncated = 0;
    }

    if (scratch->hop_count >= MAX_ASYNC_HOPS) {
#pragma unroll
        for (i = 0; i < MAX_ASYNC_HOPS - 1; i++)
            move_async_hop(&scratch->hops[i], &scratch->hops[i + 1]);
        scratch->hop_count = MAX_ASYNC_HOPS - 1;
        scratch->truncated++;
    }

    hop_index = scratch->hop_count;
    if (hop_index >= MAX_ASYNC_HOPS)
        return 0;
    hop = &scratch->hops[hop_index];
    hop->pid = pid;
    hop->tid = tid;
    hop->global_pid = global_pid;
    hop->global_tid = global_tid;
    hop->reserved = (u32)(cookie >> 32);
    hop->key = key.value;
    hop->source_ns = now;
    hop->queue_ns = 0;
    hop->target_ns = 0;
    hop->offcpu_ns = 0;
    hop->blocked_ns = 0;
    hop->runqueue_ns = 0;
    __builtin_memset(&hop->wait, 0, sizeof(hop->wait));
    bpf_get_current_comm(hop->comm, sizeof(hop->comm));
    hop->stack_id = bpf_get_stackid(ctx, &async_stacks, BPF_F_USER_STACK);
    scratch->hop_count = hop_index + 1;
    stats_hop = async_hop_index(hop->reserved);

    bpf_map_update_elem(&async_contexts, &key, scratch, BPF_ANY);
    async_stats_submitted(stats_hop, duplicate);
    return 0;
}

SEC("uprobe")
int trace_async_target(struct pt_regs *ctx)
{
    struct async_context_key context_key = {0};
    struct async_target_thread initial_thread = {0};
    struct async_target_thread *target_thread;
    struct invocation_key lineage_key = {0};
    struct invocation_state invocation = {0};
    struct async_chain *chain;
    u64 cookie;
    u64 pid_tgid;
    u64 now;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    u32 argument;
    u32 matched_argument;
    u32 expected_hop;
    u32 stats_hop;
    u32 depth;
    u32 last;
    u64 queue_ns;
    s32 pidns_error;

    if (!cw_async_cfg.enabled ||
        !get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;

    target_thread = bpf_map_lookup_elem(&async_target_threads, &pid_tgid);
    if (!target_thread) {
        bpf_map_update_elem(&async_target_threads, &pid_tgid,
                            &initial_thread, BPF_NOEXIST);
        target_thread = bpf_map_lookup_elem(&async_target_threads,
                                            &pid_tgid);
    }
    if (!target_thread)
        return 0;

    depth = target_thread->depth;
    if (depth != (__u32)-1)
        target_thread->depth = depth + 1;
    if (depth >= MAX_NESTED_CALLS)
        return 0;

    cookie = bpf_get_attach_cookie(ctx);
    argument = cookie ? (u32)cookie : cw_async_cfg.target_arg;
    expected_hop = async_hop_index((u32)(cookie >> 32));
    context_key.global_pid = global_pid;
    context_key.value = resolve_target_key(ctx, global_pid, argument,
                                           &matched_argument);
    if (!context_key.value) {
        async_stats_unmatched(expected_hop);
        return 0;
    }

    chain = bpf_map_lookup_elem(&async_contexts, &context_key);
    if (!chain || !chain->hop_count) {
        async_stats_unmatched(expected_hop);
        return 0;
    }
    last = chain->hop_count - 1;
    if (last >= MAX_ASYNC_HOPS)
        return 0;
    chain->hops[last].reserved =
        (chain->hops[last].reserved & ASYNC_HOP_ID_MASK) |
        (matched_argument << ASYNC_TARGET_ARG_SHIFT);

    now = bpf_ktime_get_ns();
    if (cw_async_cfg.max_age_ns &&
        now - chain->hops[last].source_ns > cw_async_cfg.max_age_ns) {
        async_stats_expired(async_hop_index(chain->hops[last].reserved));
        bpf_map_delete_elem(&async_contexts, &context_key);
        return 0;
    }
    chain->hops[last].queue_ns = now - chain->hops[last].source_ns;
    stats_hop = async_hop_index(chain->hops[last].reserved);
    queue_ns = chain->hops[last].queue_ns;

    lineage_key.pid_tgid = pid_tgid;
    lineage_key.depth = depth;
    invocation.start_ns = now;
    bpf_map_update_elem(&async_target_invocations, &lineage_key,
                        &invocation, BPF_ANY);
    bpf_map_update_elem(&active_lineages, &lineage_key, chain, BPF_ANY);
    bpf_map_delete_elem(&async_contexts, &context_key);
    async_stats_started(stats_hop, queue_ns, pid, tid, global_tid);
    return 0;
}

SEC("uretprobe")
int trace_async_target_return(struct pt_regs *ctx)
{
    struct async_target_thread *target_thread;
    struct invocation_key lineage_key = {0};
    struct invocation_state *invocation;
    struct async_chain *lineage;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 now = bpf_ktime_get_ns();
    u32 depth;

    (void)ctx;
    if (!cw_async_cfg.enabled)
        return 0;

    target_thread = bpf_map_lookup_elem(&async_target_threads, &pid_tgid);
    if (!target_thread || !target_thread->depth)
        return 0;

    depth = target_thread->depth - 1;
    target_thread->depth = depth;
    if (depth < MAX_NESTED_CALLS) {
        lineage_key.pid_tgid = pid_tgid;
        lineage_key.depth = depth;
        invocation = bpf_map_lookup_elem(&async_target_invocations,
                                         &lineage_key);
        lineage = bpf_map_lookup_elem(&active_lineages, &lineage_key);
        if (invocation && !invocation->async_stats_done &&
            lineage && lineage->hop_count) {
            u32 last = lineage->hop_count - 1;

            if (last < MAX_ASYNC_HOPS && now >= invocation->start_ns) {
                invocation->async_stats_done = 1;
                async_stats_completed(
                    async_hop_index(lineage->hops[last].reserved),
                    now - invocation->start_ns, invocation->blocked_ns,
                    invocation->wait.kind, invocation->wait.duration_ns,
                    (u32)pid_tgid, 1);
            }
        }
        bpf_map_delete_elem(&async_target_invocations, &lineage_key);
        bpf_map_delete_elem(&active_lineages, &lineage_key);
    }
    if (!depth)
        bpf_map_delete_elem(&async_target_threads, &pid_tgid);
    return 0;
}

static __always_inline void clear_async_event(struct stack_trace_event *event)
{
    event->async_hop_count = 0;
    event->async_truncated = 0;
}

static __always_inline void fill_discovery_event(
    struct stack_trace_event *event, u64 pid_tgid)
{
    struct discovery_wakeup *wakeup;
    u64 now;

    event->discovery_valid = 0;
    event->discovery_reserved = 0;
    event->discovery_wakeup_ns = 0;
    if (!cw_async_cfg.discovery_enabled)
        return;

    wakeup = bpf_map_lookup_elem(&discovery_wakeups, &pid_tgid);
    if (!wakeup)
        return;

    now = bpf_ktime_get_ns();
    event->discovery_waker = *wakeup;
    if (now >= wakeup->wake_ns)
        event->discovery_wakeup_ns = now - wakeup->wake_ns;
    event->discovery_valid = 1;
    bpf_map_delete_elem(&discovery_wakeups, &pid_tgid);
}

static __always_inline void copy_async_hop_to_event(
    struct async_hop_event *destination,
    const struct async_hop_context *source)
{
    destination->pid = source->pid;
    destination->tid = source->tid;
    destination->global_pid = source->global_pid;
    destination->global_tid = source->global_tid;
    __builtin_memcpy(destination->comm, source->comm,
                     sizeof(destination->comm));
    destination->stack_id = source->stack_id;
    destination->reserved = source->reserved;
    destination->key = source->key;
    destination->queue_ns = source->queue_ns;
    destination->target_ns = source->target_ns;
    destination->offcpu_ns = source->offcpu_ns;
    destination->blocked_ns = source->blocked_ns;
    destination->runqueue_ns = source->runqueue_ns;
    __builtin_memcpy(&destination->wait, &source->wait,
                     sizeof(destination->wait));
}

static __always_inline void copy_async_chain_to_event(
    struct stack_trace_event *event, struct async_chain *chain)
{
    u32 count = chain->hop_count;

    if (count > MAX_ASYNC_HOPS)
        count = MAX_ASYNC_HOPS;
    event->async_hop_count = count;
    event->async_truncated = chain->truncated;
    if (count > 0)
        copy_async_hop_to_event(&event->async_hops[0], &chain->hops[0]);
    if (count > 1)
        copy_async_hop_to_event(&event->async_hops[1], &chain->hops[1]);
    if (count > 2)
        copy_async_hop_to_event(&event->async_hops[2], &chain->hops[2]);
    if (count > 3)
        copy_async_hop_to_event(&event->async_hops[3], &chain->hops[3]);
    if (count > 4)
        copy_async_hop_to_event(&event->async_hops[4], &chain->hops[4]);
    if (count > 5)
        copy_async_hop_to_event(&event->async_hops[5], &chain->hops[5]);
    if (count > 6)
        copy_async_hop_to_event(&event->async_hops[6], &chain->hops[6]);
    if (count > 7)
        copy_async_hop_to_event(&event->async_hops[7], &chain->hops[7]);
}

static __always_inline void consume_async_context(
    struct pt_regs *ctx, struct stack_trace_event *event, u32 global_pid,
    u32 global_tid, u32 pid, u32 tid, struct invocation_key *final_key)
{
    struct async_context_key key = {
        .global_pid = global_pid,
    };
    struct async_chain *chain;
    u64 now;
    u64 queue_ns;
    u32 last;
    u32 matched_argument;
    u32 stats_hop;

    if (event)
        clear_async_event(event);
    key.value = resolve_target_key(ctx, global_pid, cw_async_cfg.target_arg,
                                   &matched_argument);
    if (!key.value) {
        if (cw_async_cfg.final_hop_id)
            async_stats_unmatched(cw_async_cfg.final_hop_id - 1);
        return;
    }

    chain = bpf_map_lookup_elem(&async_contexts, &key);
    if (!chain || !chain->hop_count) {
        if (cw_async_cfg.final_hop_id)
            async_stats_unmatched(cw_async_cfg.final_hop_id - 1);
        return;
    }
    last = chain->hop_count - 1;
    if (last >= MAX_ASYNC_HOPS)
        return;
    chain->hops[last].reserved =
        (chain->hops[last].reserved & ASYNC_HOP_ID_MASK) |
        (matched_argument << ASYNC_TARGET_ARG_SHIFT);
    now = bpf_ktime_get_ns();
    if (cw_async_cfg.max_age_ns &&
        now - chain->hops[last].source_ns > cw_async_cfg.max_age_ns) {
        async_stats_expired(async_hop_index(chain->hops[last].reserved));
        bpf_map_delete_elem(&async_contexts, &key);
        return;
    }
    chain->hops[last].queue_ns = now - chain->hops[last].source_ns;
    stats_hop = async_hop_index(chain->hops[last].reserved);
    queue_ns = chain->hops[last].queue_ns;
    if (final_key) {
        bpf_map_update_elem(&final_lineages, final_key, chain, BPF_ANY);
        if (event)
            clear_async_event(event);
    } else if (event) {
        copy_async_chain_to_event(event, chain);
    }
    bpf_map_delete_elem(&async_contexts, &key);
    async_stats_started(stats_hop, queue_ns, pid, tid, global_tid);
}

static __always_inline void fill_entry_event(
    struct pt_regs *ctx, struct stack_trace_event *event,
    u32 global_pid, u32 global_tid, u32 pid, u32 tid, s32 pidns_error)
{
    fill_process_info(event, global_pid, global_tid, pid, tid, pidns_error);
    event->event_type = EVENT_ENTRY;
    event->reserved = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->duration_ns = 0;
    event->return_value = 0;
    event->offcpu_ns = 0;
    event->blocked_ns = 0;
    event->runqueue_ns = 0;
    __builtin_memset(&event->wait, 0, sizeof(event->wait));
    event->stack_size = bpf_get_stack(ctx, event->stack,
                                      sizeof(event->stack),
                                      BPF_F_USER_STACK);
}

static __always_inline void add_offcpu_interval(
    u64 pid_tgid, struct thread_state *thread, u64 now)
{
    struct invocation_key key = {
        .pid_tgid = pid_tgid,
    };
    u64 offcpu_ns;
    u64 blocked_ns = 0;
    u64 runqueue_ns = 0;
    u32 depth = thread->depth;
    int i;

    if (!thread->offcpu_start_ns || now <= thread->offcpu_start_ns)
        return;

    offcpu_ns = now - thread->offcpu_start_ns;
    if (thread->wakeup_ns >= thread->offcpu_start_ns &&
        thread->wakeup_ns <= now) {
        blocked_ns = thread->wakeup_ns - thread->offcpu_start_ns;
        runqueue_ns = now - thread->wakeup_ns;
    }

    if (depth > MAX_NESTED_CALLS)
        depth = MAX_NESTED_CALLS;
#pragma unroll
    for (i = 0; i < MAX_NESTED_CALLS; i++) {
        struct invocation_state *invocation;

        if ((u32)i >= depth)
            break;
        key.depth = i;
        invocation = bpf_map_lookup_elem(&invocation_states, &key);
        if (!invocation)
            continue;
        invocation->offcpu_ns += offcpu_ns;
        invocation->blocked_ns += blocked_ns;
        invocation->runqueue_ns += runqueue_ns;
    }

    thread->offcpu_start_ns = 0;
    thread->wakeup_ns = 0;
}

static __always_inline void add_async_offcpu_interval(
    u64 pid_tgid, struct async_target_thread *thread, u64 now)
{
    struct invocation_key key = {
        .pid_tgid = pid_tgid,
    };
    u64 offcpu_ns;
    u64 blocked_ns = 0;
    u64 runqueue_ns = 0;
    u32 depth = thread->depth;
    int i;

    if (!thread->offcpu_start_ns || now <= thread->offcpu_start_ns)
        return;

    offcpu_ns = now - thread->offcpu_start_ns;
    if (thread->wakeup_ns >= thread->offcpu_start_ns &&
        thread->wakeup_ns <= now) {
        blocked_ns = thread->wakeup_ns - thread->offcpu_start_ns;
        runqueue_ns = now - thread->wakeup_ns;
    }

    if (depth > MAX_NESTED_CALLS)
        depth = MAX_NESTED_CALLS;
#pragma unroll
    for (i = 0; i < MAX_NESTED_CALLS; i++) {
        struct invocation_state *invocation;

        if ((u32)i >= depth)
            break;
        key.depth = i;
        invocation = bpf_map_lookup_elem(&async_target_invocations, &key);
        if (!invocation)
            continue;
        invocation->offcpu_ns += offcpu_ns;
        invocation->blocked_ns += blocked_ns;
        invocation->runqueue_ns += runqueue_ns;
    }

    thread->offcpu_start_ns = 0;
    thread->wakeup_ns = 0;
}

static __always_inline void epoll_switch_out(u64 pid_tgid, u64 now)
{
    struct cw_epoll_dispatch_batch *batch;

    if (!cw_epoll_capture_active())
        return;
    batch = bpf_map_lookup_elem(
        &epoll_dispatch_batches, &pid_tgid);
    if (!batch)
        return;
    batch->offcpu_start_ns = now;
    batch->wakeup_ns = 0;
}

static __always_inline void epoll_switch_in(u64 pid_tgid, u64 now)
{
    struct cw_epoll_dispatch_batch *batch;
    u64 offcpu_ns;

    if (!cw_epoll_capture_active())
        return;
    batch = bpf_map_lookup_elem(
        &epoll_dispatch_batches, &pid_tgid);
    if (!batch || !batch->offcpu_start_ns ||
        now <= batch->offcpu_start_ns)
        return;
    offcpu_ns = now - batch->offcpu_start_ns;
    batch->offcpu_ns += offcpu_ns;
    if (batch->wakeup_ns >= batch->offcpu_start_ns &&
        batch->wakeup_ns <= now) {
        batch->blocked_ns +=
            batch->wakeup_ns - batch->offcpu_start_ns;
        batch->runqueue_ns += now - batch->wakeup_ns;
    }
    batch->offcpu_start_ns = 0;
    batch->wakeup_ns = 0;
}

static __always_inline void epoll_callback_switch_out(
    u64 pid_tgid, u64 now)
{
    struct cw_epoll_callback_thread *thread;

    if (!cw_epoll_cfg.callback_enabled ||
        !cw_epoll_capture_active())
        return;
    thread = bpf_map_lookup_elem(
        &epoll_callback_threads, &pid_tgid);
    if (!thread || !thread->depth)
        return;
    thread->offcpu_start_ns = now;
    thread->wakeup_ns = 0;
}

static __always_inline void epoll_callback_switch_in(
    u64 pid_tgid, u64 now)
{
    struct cw_epoll_callback_thread *thread;
    struct cw_epoll_callback_key key = {
        .pid_tgid = pid_tgid,
    };
    u64 offcpu_ns;
    u64 blocked_ns = 0;
    u64 runqueue_ns = 0;
    u32 depth;
    int i;

    if (!cw_epoll_cfg.callback_enabled ||
        !cw_epoll_capture_active())
        return;
    thread = bpf_map_lookup_elem(
        &epoll_callback_threads, &pid_tgid);
    if (!thread || !thread->depth ||
        !thread->offcpu_start_ns ||
        now <= thread->offcpu_start_ns)
        return;
    offcpu_ns = now - thread->offcpu_start_ns;
    if (thread->wakeup_ns >= thread->offcpu_start_ns &&
        thread->wakeup_ns <= now) {
        blocked_ns =
            thread->wakeup_ns - thread->offcpu_start_ns;
        runqueue_ns = now - thread->wakeup_ns;
    }
    depth = thread->depth;
    if (depth > CW_EPOLL_MAX_CALLBACK_DEPTH)
        depth = CW_EPOLL_MAX_CALLBACK_DEPTH;
#pragma unroll
    for (i = 0; i < CW_EPOLL_MAX_CALLBACK_DEPTH; i++) {
        struct cw_epoll_callback_frame *frame;

        if ((__u32)i >= depth)
            break;
        key.depth = i;
        frame = bpf_map_lookup_elem(
            &epoll_callback_frames, &key);
        if (!frame || !frame->matched)
            continue;
        frame->event.offcpu_ns += offcpu_ns;
        frame->event.blocked_ns += blocked_ns;
        frame->event.runqueue_ns += runqueue_ns;
    }
    thread->offcpu_start_ns = 0;
    thread->wakeup_ns = 0;
}

static __always_inline int is_futex_wait_operation(u32 operation)
{
    return operation == FUTEX_WAIT || operation == FUTEX_WAIT_BITSET;
}

static __always_inline int is_futex_wake_operation(u32 operation)
{
    return operation == FUTEX_WAKE || operation == FUTEX_WAKE_BITSET;
}

static __always_inline int is_traced_invocation(u64 pid_tgid)
{
    struct thread_state *thread =
        bpf_map_lookup_elem(&thread_states, &pid_tgid);
    struct async_target_thread *async_thread =
        bpf_map_lookup_elem(&async_target_threads, &pid_tgid);

    return (thread && thread->depth) ||
           (async_thread && async_thread->depth);
}

static __always_inline void update_regular_futex_wait(
    u64 pid_tgid, const struct wait_resource *wait)
{
    struct thread_state *thread =
        bpf_map_lookup_elem(&thread_states, &pid_tgid);
    struct invocation_key key = {
        .pid_tgid = pid_tgid,
    };
    struct invocation_state *invocation;

    if (!thread || !thread->depth)
        return;
    key.depth = thread->depth - 1;
    if (key.depth >= MAX_NESTED_CALLS)
        return;
    invocation = bpf_map_lookup_elem(&invocation_states, &key);
    if (invocation && wait->duration_ns > invocation->wait.duration_ns)
        __builtin_memcpy(&invocation->wait, wait,
                         sizeof(invocation->wait));
}

static __always_inline void update_async_futex_wait(
    u64 pid_tgid, const struct wait_resource *wait)
{
    struct async_target_thread *thread =
        bpf_map_lookup_elem(&async_target_threads, &pid_tgid);
    struct invocation_key key = {
        .pid_tgid = pid_tgid,
    };
    struct invocation_state *invocation;

    if (!thread || !thread->depth)
        return;
    key.depth = thread->depth - 1;
    if (key.depth >= MAX_NESTED_CALLS)
        return;
    invocation = bpf_map_lookup_elem(&async_target_invocations, &key);
    if (invocation && wait->duration_ns > invocation->wait.duration_ns)
        __builtin_memcpy(&invocation->wait, wait,
                         sizeof(invocation->wait));
}

SEC("raw_tp/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *registers = (struct pt_regs *)ctx->args[0];
    struct futex_wait_state wait = {0};
    struct futex_resource_key resource_key = {0};
    struct futex_waker waker = {0};
    u64 pid_tgid;
    u64 address;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    u32 operation;
    s32 pidns_error;

    if (!cw_trace_cfg.attribution_enabled ||
        (s32)ctx->args[1] != cw_trace_cfg.futex_syscall_nr)
        return 0;
    if (!get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;

    address = PT_REGS_PARM1_CORE_SYSCALL(registers);
    operation = (u32)PT_REGS_PARM2_CORE_SYSCALL(registers) &
                FUTEX_CMD_MASK;
    if (!address)
        return 0;

    if (is_futex_wait_operation(operation)) {
        if (!is_traced_invocation(pid_tgid))
            return 0;
        wait.address = address;
        wait.start_ns = bpf_ktime_get_ns();
        wait.operation = operation;
        bpf_map_update_elem(&futex_waits, &pid_tgid, &wait, BPF_ANY);
        return 0;
    }
    if (!is_futex_wake_operation(operation))
        return 0;

    resource_key.global_pid = global_pid;
    resource_key.address = address;
    waker.wake_ns = bpf_ktime_get_ns();
    waker.pid = pid;
    waker.tid = tid;
    waker.global_pid = global_pid;
    waker.global_tid = global_tid;
    waker.pidns_error = pidns_error;
    bpf_get_current_comm(waker.comm, sizeof(waker.comm));
    waker.stack_id = bpf_get_stackid(ctx, &discovery_stacks,
                                     BPF_F_USER_STACK);
    bpf_map_update_elem(&futex_wakers, &resource_key, &waker, BPF_ANY);
    return 0;
}

SEC("raw_tp/sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct futex_wait_state *active;
    struct futex_wait_state saved;
    struct futex_resource_key resource_key = {0};
    struct futex_waker *waker;
    struct wait_resource wait = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 now;

    (void)ctx;
    if (!cw_trace_cfg.attribution_enabled &&
        !cw_epoll_capture_active())
        return 0;
    active = bpf_map_lookup_elem(&futex_waits, &pid_tgid);
    if (!active)
        return 0;
    __builtin_memcpy(&saved, active, sizeof(saved));
    bpf_map_delete_elem(&futex_waits, &pid_tgid);

    now = bpf_ktime_get_ns();
    if (!saved.start_ns || now <= saved.start_ns)
        return 0;
    wait.kind = WAIT_KIND_FUTEX;
    wait.operation = saved.operation;
    wait.address = saved.address;
    wait.duration_ns = now - saved.start_ns;
    wait.waker_stack_id = -1;

    resource_key.global_pid = pid_tgid >> 32;
    resource_key.address = saved.address;
    waker = bpf_map_lookup_elem(&futex_wakers, &resource_key);
    if (waker && waker->wake_ns >= saved.start_ns &&
        waker->wake_ns <= now) {
        wait.wake_ns = waker->wake_ns - saved.start_ns;
        wait.waker_pid = waker->pid;
        wait.waker_tid = waker->tid;
        wait.waker_global_pid = waker->global_pid;
        wait.waker_global_tid = waker->global_tid;
        wait.waker_stack_id = waker->stack_id;
        wait.waker_pidns_error = waker->pidns_error;
        __builtin_memcpy(wait.waker_comm, waker->comm,
                         sizeof(wait.waker_comm));
    }

    update_regular_futex_wait(pid_tgid, &wait);
    update_async_futex_wait(pid_tgid, &wait);
    return 0;
}

SEC("uprobe")
int trace_function(struct pt_regs *ctx)
{
    struct stack_trace_event *event;
    struct thread_state initial_thread = {0};
    struct thread_state *thread;
    struct invocation_key final_key = {0};
    struct invocation_key *final_key_pointer = NULL;
    u64 pid_tgid;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    s32 pidns_error;

    if (!get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;
    if (cw_async_cfg.discovery_enabled) {
        u32 zero = 0;

        bpf_map_update_elem(&discovery_target_global, &zero, &global_pid,
                            BPF_ANY);
    }

    if (cw_trace_cfg.returns_enabled) {
        thread = bpf_map_lookup_elem(&thread_states, &pid_tgid);
        if (!thread) {
            bpf_map_update_elem(&thread_states, &pid_tgid, &initial_thread,
                                BPF_NOEXIST);
            thread = bpf_map_lookup_elem(&thread_states, &pid_tgid);
        }
        if (thread) {
            struct invocation_key key = {
                .pid_tgid = pid_tgid,
                .depth = thread->depth,
            };
            struct invocation_state invocation = {
                .start_ns = bpf_ktime_get_ns(),
            };
            u32 depth = thread->depth;

            if (depth < MAX_NESTED_CALLS)
                bpf_map_update_elem(&invocation_states, &key, &invocation,
                                    BPF_ANY);
            if (depth < MAX_NESTED_CALLS) {
                final_key = key;
                final_key_pointer = &final_key;
            }
            if (depth != (__u32)-1)
                thread->depth = depth + 1;
        }
    }

    if (cw_async_cfg.enabled)
        consume_async_context(ctx, NULL, global_pid, global_tid,
                              pid, tid, final_key_pointer);

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        clear_async_event(event);
        fill_entry_event(ctx, event, global_pid, global_tid, pid, tid,
                         pidns_error);
        fill_discovery_event(event, pid_tgid);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("uretprobe")
int trace_function_return(struct pt_regs *ctx)
{
    struct stack_trace_event *event;
    struct invocation_key key = {0};
    struct invocation_state *invocation;
    struct async_chain *lineage;
    struct thread_state *thread;
    struct wait_resource wait = {0};
    u64 end_ns = bpf_ktime_get_ns();
    u64 pid_tgid;
    u64 start_ns;
    u64 offcpu_ns;
    u64 blocked_ns;
    u64 runqueue_ns;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    u32 depth;
    s32 pidns_error;

    if (!cw_trace_cfg.returns_enabled ||
        !get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;

    thread = bpf_map_lookup_elem(&thread_states, &pid_tgid);
    if (!thread || !thread->depth)
        return 0;

    depth = thread->depth - 1;
    thread->depth = depth;
    if (depth >= MAX_NESTED_CALLS)
        return 0;

    key.pid_tgid = pid_tgid;
    key.depth = depth;
    invocation = bpf_map_lookup_elem(&invocation_states, &key);
    if (!invocation) {
        bpf_map_delete_elem(&final_lineages, &key);
        if (!depth)
            bpf_map_delete_elem(&thread_states, &pid_tgid);
        return 0;
    }

    start_ns = invocation->start_ns;
    offcpu_ns = invocation->offcpu_ns;
    blocked_ns = invocation->blocked_ns;
    runqueue_ns = invocation->runqueue_ns;
    __builtin_memcpy(&wait, &invocation->wait, sizeof(wait));
    bpf_map_delete_elem(&invocation_states, &key);
    if (!depth)
        bpf_map_delete_elem(&thread_states, &pid_tgid);
    if (!start_ns)
        return 0;

    lineage = bpf_map_lookup_elem(&final_lineages, &key);
    if (lineage && lineage->hop_count) {
        u32 last = lineage->hop_count - 1;

        if (last < MAX_ASYNC_HOPS) {
            lineage->hops[last].target_ns = end_ns - start_ns;
            lineage->hops[last].offcpu_ns = offcpu_ns;
            lineage->hops[last].blocked_ns = blocked_ns;
            lineage->hops[last].runqueue_ns = runqueue_ns;
            __builtin_memcpy(&lineage->hops[last].wait,
                             &wait,
                             sizeof(lineage->hops[last].wait));
            async_stats_completed(
                async_hop_index(lineage->hops[last].reserved),
                lineage->hops[last].target_ns, blocked_ns,
                wait.kind, wait.duration_ns,
                global_tid, 0);
        }
    }

    event = bpf_ringbuf_reserve(
        &events, __builtin_offsetof(struct stack_trace_event, stack), 0);
    if (!event) {
        bpf_map_delete_elem(&final_lineages, &key);
        return 0;
    }

    fill_process_info(event, global_pid, global_tid, pid, tid, pidns_error);
    event->event_type = EVENT_RETURN;
    event->stack_size = 0;
    event->reserved = 0;
    event->timestamp_ns = end_ns;
    event->duration_ns = end_ns - start_ns;
    event->return_value = (s64)PT_REGS_RC(ctx);
    event->offcpu_ns = offcpu_ns;
    event->blocked_ns = blocked_ns;
    event->runqueue_ns = runqueue_ns;
    __builtin_memcpy(&event->wait, &wait, sizeof(event->wait));
    event->discovery_valid = 0;
    event->discovery_reserved = 0;
    event->discovery_wakeup_ns = 0;
    lineage = bpf_map_lookup_elem(&final_lineages, &key);
    if (lineage && lineage->hop_count) {
        u32 last = lineage->hop_count - 1;

        if (last < MAX_ASYNC_HOPS) {
            copy_async_chain_to_event(event, lineage);
        } else {
            clear_async_event(event);
        }
    } else {
        clear_async_event(event);
    }
    bpf_map_delete_elem(&final_lineages, &key);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("raw_tp/sched_switch")
int trace_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    struct thread_state *thread;
    struct async_target_thread *async_thread;
    u64 now;
    u64 pid_tgid;

    if (!cw_trace_cfg.attribution_enabled &&
        !cw_epoll_capture_active())
        return 0;

    now = bpf_ktime_get_ns();
    pid_tgid = task_pid_tgid(prev);
    epoll_switch_out(pid_tgid, now);
    epoll_callback_switch_out(pid_tgid, now);
    if (cw_trace_cfg.attribution_enabled) {
        thread = bpf_map_lookup_elem(&thread_states, &pid_tgid);
        if (thread && thread->depth) {
            thread->offcpu_start_ns = now;
            thread->wakeup_ns = 0;
        }
        async_thread = bpf_map_lookup_elem(
            &async_target_threads, &pid_tgid);
        if (async_thread && async_thread->depth) {
            async_thread->offcpu_start_ns = now;
            async_thread->wakeup_ns = 0;
        }
    }

    pid_tgid = task_pid_tgid(next);
    epoll_switch_in(pid_tgid, now);
    epoll_callback_switch_in(pid_tgid, now);
    if (cw_trace_cfg.attribution_enabled) {
        thread = bpf_map_lookup_elem(&thread_states, &pid_tgid);
        if (thread && thread->depth)
            add_offcpu_interval(pid_tgid, thread, now);
        async_thread = bpf_map_lookup_elem(
            &async_target_threads, &pid_tgid);
        if (async_thread && async_thread->depth)
            add_async_offcpu_interval(
                pid_tgid, async_thread, now);
    }

    return 0;
}

static __always_inline int record_discovery_waker(
    struct bpf_raw_tracepoint_args *ctx, struct task_struct *task)
{
    struct discovery_wakeup wakeup = {0};
    struct bpf_pidns_info pidns = {0};
    u64 waker_pid_tgid;
    u64 pid_tgid;
    u32 zero = 0;
    u32 *discovery_global_pid;

    if (!cw_async_cfg.discovery_enabled)
        return 0;

    pid_tgid = task_pid_tgid(task);
    waker_pid_tgid = bpf_get_current_pid_tgid();
    wakeup.global_pid = waker_pid_tgid >> 32;
    wakeup.global_tid = (u32)waker_pid_tgid;
    discovery_global_pid =
        bpf_map_lookup_elem(&discovery_target_global, &zero);
    if (!discovery_global_pid || !*discovery_global_pid ||
        *discovery_global_pid != wakeup.global_pid)
        return 0;
    wakeup.pid = wakeup.global_pid;
    wakeup.tid = wakeup.global_tid;
    wakeup.pidns_error = bpf_get_ns_current_pid_tgid(
        cw_target_cfg.pidns_dev, cw_target_cfg.pidns_ino, &pidns, sizeof(pidns));
    if (!wakeup.pidns_error) {
        wakeup.pid = pidns.tgid;
        wakeup.tid = pidns.pid;
    }
    bpf_get_current_comm(wakeup.comm, sizeof(wakeup.comm));
    wakeup.stack_id = bpf_get_stackid(ctx, &discovery_stacks,
                                      BPF_F_USER_STACK);
    wakeup.wake_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&discovery_wakeups, &pid_tgid, &wakeup, BPF_ANY);
    return 0;
}

static __always_inline int record_task_wakeup(struct task_struct *task)
{
    struct thread_state *thread;
    struct async_target_thread *async_thread;
    u64 pid_tgid;

    if (!cw_trace_cfg.attribution_enabled &&
        !cw_epoll_capture_active())
        return 0;

    pid_tgid = task_pid_tgid(task);
    if (cw_epoll_capture_active()) {
        struct cw_epoll_dispatch_batch *batch =
            bpf_map_lookup_elem(
                &epoll_dispatch_batches, &pid_tgid);
        struct cw_epoll_callback_thread *callback_thread =
            bpf_map_lookup_elem(
                &epoll_callback_threads, &pid_tgid);

        if (batch && batch->offcpu_start_ns &&
            !batch->wakeup_ns)
            batch->wakeup_ns = bpf_ktime_get_ns();
        if (callback_thread &&
            callback_thread->offcpu_start_ns &&
            !callback_thread->wakeup_ns)
            callback_thread->wakeup_ns =
                bpf_ktime_get_ns();
    }
    if (cw_trace_cfg.attribution_enabled) {
        thread = bpf_map_lookup_elem(&thread_states, &pid_tgid);
        if (thread && thread->depth && thread->offcpu_start_ns &&
            !thread->wakeup_ns)
            thread->wakeup_ns = bpf_ktime_get_ns();
        async_thread = bpf_map_lookup_elem(
            &async_target_threads, &pid_tgid);
        if (async_thread && async_thread->depth &&
            async_thread->offcpu_start_ns && !async_thread->wakeup_ns)
            async_thread->wakeup_ns = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("raw_tp/sched_wakeup")
int trace_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    return record_task_wakeup((struct task_struct *)ctx->args[0]);
}

SEC("raw_tp/sched_waking")
int trace_sched_waking(struct bpf_raw_tracepoint_args *ctx)
{
    return record_discovery_waker(ctx,
                                  (struct task_struct *)ctx->args[0]);
}

#include "io_uring/io_uring.bpf.progs.h"
#include "epoll/epoll.bpf.progs.h"
#include "epoll/epoll_wake.bpf.progs.h"
#include "libuv/libuv.bpf.progs.h"
#include "libevent/libevent.bpf.progs.h"
#include "epoll/epoll_callback.bpf.progs.h"

char LICENSE[] SEC("license") = "GPL";
