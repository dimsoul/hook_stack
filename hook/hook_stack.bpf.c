// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 128
#define MAX_NESTED_CALLS 16

enum event_type {
    EVENT_ENTRY,
    EVENT_RETURN,
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
    u64 duration_ns;
    s64 return_value;
    u64 stack[MAX_STACK_DEPTH];
};

struct call_state {
    u32 depth;
    u32 reserved;
    u64 start_ns[MAX_NESTED_CALLS];
};

_Static_assert(__builtin_offsetof(struct stack_trace_event, stack) == 64,
               "unexpected BPF event layout");
_Static_assert(sizeof(struct stack_trace_event) == 1088,
               "unexpected BPF event size");

const volatile __u64 pidns_dev;
const volatile __u64 pidns_ino;
const volatile __u32 target_pid;
const volatile __u32 trace_returns;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct call_state);
} call_states SEC(".maps");

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
        pidns_dev, pidns_ino, &pidns, sizeof(pidns));
    if (!*pidns_error) {
        *pid = pidns.tgid;
        *tid = pidns.pid;
    }

    return !target_pid || *pid == target_pid;
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

SEC("uprobe")
int trace_function(struct pt_regs *ctx)
{
    struct stack_trace_event *event;
    struct call_state initial_state = {0};
    struct call_state *state;
    u64 pid_tgid;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    s32 pidns_error;

    if (!get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        fill_process_info(event, global_pid, global_tid, pid, tid,
                          pidns_error);
        event->event_type = EVENT_ENTRY;
        event->reserved = 0;
        event->duration_ns = 0;
        event->return_value = 0;
        event->stack_size = bpf_get_stack(ctx, event->stack,
                                          sizeof(event->stack),
                                          BPF_F_USER_STACK);
        bpf_ringbuf_submit(event, 0);
    }

    if (trace_returns) {
        state = bpf_map_lookup_elem(&call_states, &pid_tgid);
        if (!state) {
            bpf_map_update_elem(&call_states, &pid_tgid, &initial_state,
                                BPF_NOEXIST);
            state = bpf_map_lookup_elem(&call_states, &pid_tgid);
        }
        if (state) {
            u32 depth = state->depth;

            if (depth < MAX_NESTED_CALLS)
                state->start_ns[depth] = bpf_ktime_get_ns();
            if (depth != (__u32)-1)
                state->depth = depth + 1;
        }
    }

    return 0;
}

SEC("uretprobe")
int trace_function_return(struct pt_regs *ctx)
{
    struct stack_trace_event *event;
    struct call_state *state;
    u64 end_ns = bpf_ktime_get_ns();
    u64 pid_tgid;
    u64 start_ns;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    u32 depth;
    s32 pidns_error;

    if (!trace_returns ||
        !get_process_info(&pid_tgid, &global_pid, &global_tid, &pid, &tid,
                          &pidns_error))
        return 0;

    state = bpf_map_lookup_elem(&call_states, &pid_tgid);
    if (!state || !state->depth)
        return 0;

    depth = state->depth - 1;
    state->depth = depth;
    if (depth >= MAX_NESTED_CALLS)
        return 0;

    start_ns = state->start_ns[depth];
    state->start_ns[depth] = 0;
    if (!depth)
        bpf_map_delete_elem(&call_states, &pid_tgid);
    if (!start_ns)
        return 0;

    event = bpf_ringbuf_reserve(
        &events, __builtin_offsetof(struct stack_trace_event, stack), 0);
    if (!event)
        return 0;

    fill_process_info(event, global_pid, global_tid, pid, tid, pidns_error);
    event->event_type = EVENT_RETURN;
    event->stack_size = 0;
    event->reserved = 0;
    event->duration_ns = end_ns - start_ns;
    event->return_value = (s64)PT_REGS_RC(ctx);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
