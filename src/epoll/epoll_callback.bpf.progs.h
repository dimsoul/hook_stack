// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_EPOLL_CALLBACK_BPF_PROGS_H
#define CALLWEAVE_EPOLL_CALLBACK_BPF_PROGS_H

static __always_inline struct cw_epoll_counters *
cw_epoll_callback_counters(void)
{
    __u32 zero = 0;

    return bpf_map_lookup_elem(&epoll_counters, &zero);
}

static __always_inline void cw_epoll_callback_copy_wake(
    const struct cw_epoll_dispatch_key *key,
    const struct cw_epoll_dispatch_candidate *candidate,
    struct cw_epoll_wake_source *wake)
{
    struct cw_epoll_wake_source *pending =
        bpf_map_lookup_elem(&epoll_dispatch_wakes, key);

    if (pending)
        *wake = *pending;
    else
        *wake = candidate->item.wake;
}

static __attribute__((noinline)) void cw_epoll_callback_match(
    struct pt_regs *ctx, __u64 pid_tgid,
    const struct cw_epoll_process_identity *identity,
    struct cw_epoll_callback_frame *frame)
{
    __s32 fd = (__s32)read_uprobe_argument(
        ctx, cw_epoll_cfg.callback_fd_arg);
    struct cw_epoll_dispatch_key dispatch_key = {
        .pid_tgid = pid_tgid,
        .fd = fd,
    };
    struct cw_epoll_dispatch_candidate *candidate =
        bpf_map_lookup_elem(
            &epoll_dispatch_candidates, &dispatch_key);
    struct cw_epoll_dispatch_batch *batch =
        bpf_map_lookup_elem(
            &epoll_dispatch_batches, &pid_tgid);
    struct cw_epoll_counters *counters =
        cw_epoll_callback_counters();
    struct cw_epoll_resource_key resource_key;
    struct cw_epoll_resource_stats *resource_stats;
    __u64 now;

    if (fd < 0 || !candidate || !batch) {
        if (counters)
            __sync_fetch_and_add(
                &counters->callback_unmatched, 1);
        return;
    }
    now = bpf_ktime_get_ns();
    frame->matched = 1;
    frame->event.ready_ns = candidate->item.ready_ns;
    frame->event.start_ns = now;
    frame->event.delay_ns =
        now > candidate->item.ready_ns ?
            now - candidate->item.ready_ns : 0;
    frame->event.data = candidate->item.data;
    frame->event.pid = identity->pid;
    frame->event.tid = identity->tid;
    frame->event.global_pid = identity->global_pid;
    frame->event.global_tid = identity->global_tid;
    frame->event.epoll_fd = batch->epoll_fd;
    frame->event.fd = fd;
    frame->event.epoll_generation =
        candidate->item.epoll_generation;
    frame->event.fd_generation =
        candidate->item.fd_generation;
    frame->event.ready_events =
        candidate->item.ready_events;
    frame->event.stack_id = bpf_get_stackid(
        ctx, &epoll_stacks, BPF_F_USER_STACK);
    bpf_get_current_comm(
        frame->event.comm, sizeof(frame->event.comm));
    cw_epoll_callback_copy_wake(
        &dispatch_key, candidate, &frame->event.wake);
    if (counters)
        __sync_fetch_and_add(
            &counters->callback_matched, 1);
    resource_key.pid = identity->pid;
    resource_key.epoll_fd = batch->epoll_fd;
    resource_key.epoll_generation =
        candidate->item.epoll_generation;
    resource_key.fd = fd;
    resource_key.fd_generation =
        candidate->item.fd_generation;
    resource_stats = bpf_map_lookup_elem(
        &epoll_resource_stats, &resource_key);
    if (resource_stats) {
        __sync_fetch_and_add(
            &resource_stats->callback_matched, 1);
        __sync_fetch_and_add(
            &resource_stats->callback_total_delay_ns,
            frame->event.delay_ns);
        update_peak(
            &resource_stats->callback_maximum_delay_ns,
            frame->event.delay_ns);
    }
}

SEC("uprobe")
int trace_epoll_callback_entry(struct pt_regs *ctx)
{
    struct cw_epoll_process_identity identity;
    struct cw_epoll_callback_thread initial = {0};
    struct cw_epoll_callback_thread *thread;
    struct cw_epoll_callback_key key;
    struct cw_epoll_callback_frame frame = {
        .event = {
            .stack_id = -1,
        },
    };
    struct cw_epoll_counters *counters;
    __u64 pid_tgid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 pid;
    __u32 tid;
    __s32 pidns_error;
    __u32 depth;

    if (!cw_epoll_cfg.callback_enabled ||
        !cw_epoll_capture_active() ||
        !get_process_info(
            &pid_tgid, &global_pid, &global_tid,
            &pid, &tid, &pidns_error))
        return 0;
    thread = bpf_map_lookup_elem(
        &epoll_callback_threads, &pid_tgid);
    if (!thread) {
        bpf_map_update_elem(
            &epoll_callback_threads, &pid_tgid,
            &initial, BPF_NOEXIST);
        thread = bpf_map_lookup_elem(
            &epoll_callback_threads, &pid_tgid);
        if (!thread)
            return 0;
    }
    depth = thread->depth;
    thread->depth = depth + 1;
    if (depth >= CW_EPOLL_MAX_CALLBACK_DEPTH) {
        counters = cw_epoll_callback_counters();
        if (counters)
            __sync_fetch_and_add(
                &counters->callback_overflow, 1);
        return 0;
    }
    identity.pid_tgid = pid_tgid;
    identity.global_pid = global_pid;
    identity.global_tid = global_tid;
    identity.pid = pid;
    identity.tid = tid;
    cw_epoll_callback_match(
        ctx, pid_tgid, &identity, &frame);
    key.pid_tgid = pid_tgid;
    key.depth = depth;
    key.reserved = 0;
    bpf_map_update_elem(
        &epoll_callback_frames, &key, &frame, BPF_ANY);
    return 0;
}

static __attribute__((noinline)) void cw_epoll_finish_callback(
    struct cw_epoll_callback_frame *frame)
{
    struct cw_epoll_resource_key resource_key = {
        .pid = frame->event.pid,
        .epoll_fd = frame->event.epoll_fd,
        .epoll_generation = frame->event.epoll_generation,
        .fd = frame->event.fd,
        .fd_generation = frame->event.fd_generation,
    };
    struct cw_epoll_resource_stats *resource_stats =
        bpf_map_lookup_elem(
            &epoll_resource_stats, &resource_key);
    struct cw_epoll_counters *counters =
        cw_epoll_callback_counters();
    struct cw_epoll_callback_event *event;
    __u64 now = bpf_ktime_get_ns();
    __u64 previous_maximum = 0;

    frame->event.timestamp_ns = now;
    frame->event.duration_ns =
        now > frame->event.start_ns ?
            now - frame->event.start_ns : 0;
    if (counters)
        __sync_fetch_and_add(
            &counters->callback_completed, 1);
    if (resource_stats) {
        previous_maximum =
            resource_stats->callback_maximum_duration_ns;
        __sync_fetch_and_add(
            &resource_stats->callback_completed, 1);
        __sync_fetch_and_add(
            &resource_stats->callback_total_duration_ns,
            frame->event.duration_ns);
        __sync_fetch_and_add(
            &resource_stats->callback_offcpu_ns,
            frame->event.offcpu_ns);
        __sync_fetch_and_add(
            &resource_stats->callback_blocked_ns,
            frame->event.blocked_ns);
        __sync_fetch_and_add(
            &resource_stats->callback_runqueue_ns,
            frame->event.runqueue_ns);
        update_peak(
            &resource_stats->callback_maximum_duration_ns,
            frame->event.duration_ns);
        if (frame->event.duration_ns >= previous_maximum)
            resource_stats->callback_stack_id =
                frame->event.stack_id;
    }
    if (frame->event.duration_ns <
        cw_epoll_cfg.min_callback_ns)
        return;
    event = bpf_ringbuf_reserve(
        &epoll_callback_events, sizeof(*event), 0);
    if (!event) {
        if (counters)
            __sync_fetch_and_add(
                &counters->callback_dropped, 1);
        return;
    }
    *event = frame->event;
    bpf_ringbuf_submit(event, 0);
    if (counters)
        __sync_fetch_and_add(
            &counters->callback_emitted, 1);
}

SEC("uretprobe")
int trace_epoll_callback_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_epoll_callback_thread *thread =
        bpf_map_lookup_elem(
            &epoll_callback_threads, &pid_tgid);
    struct cw_epoll_callback_key key;
    struct cw_epoll_callback_frame *frame;
    __u32 depth;

    (void)ctx;
    if (!cw_epoll_cfg.callback_enabled || !thread ||
        !thread->depth)
        return 0;
    depth = thread->depth - 1;
    thread->depth = depth;
    if (depth >= CW_EPOLL_MAX_CALLBACK_DEPTH)
        return 0;
    key.pid_tgid = pid_tgid;
    key.depth = depth;
    key.reserved = 0;
    frame = bpf_map_lookup_elem(
        &epoll_callback_frames, &key);
    if (frame && frame->matched)
        cw_epoll_finish_callback(frame);
    bpf_map_delete_elem(&epoll_callback_frames, &key);
    if (!depth)
        bpf_map_delete_elem(
            &epoll_callback_threads, &pid_tgid);
    return 0;
}

SEC("raw_tp/sched_process_exec")
int trace_epoll_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 pid;
    __u32 tid;
    __u32 zero = 0;
    __u32 active = 1;
    __s32 pidns_error;

    (void)ctx;
    if (!cw_epoll_cfg.enabled ||
        !cw_epoll_cfg.defer_until_exec ||
        !get_process_info(
            &pid_tgid, &global_pid, &global_tid,
            &pid, &tid, &pidns_error))
        return 0;
    bpf_map_update_elem(
        &epoll_exec_gate, &zero, &active, BPF_ANY);
    return 0;
}

#endif
