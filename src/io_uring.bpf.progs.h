// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_IO_URING_BPF_PROGS_H
#define CALLWEAVE_IO_URING_BPF_PROGS_H

static __always_inline struct io_uring_ring_stats *
get_io_uring_ring_stats(u64 ring_ctx, u32 owner_pid)
{
    struct io_uring_ring_stats initial = {
        .owner_pid = owner_pid,
        .ring_fd = -1,
    };
    struct io_uring_ring_stats *stats;
    struct io_ring_ctx *ring = (struct io_ring_ctx *)ring_ctx;

    if (!ring_ctx)
        return NULL;
    stats = bpf_map_lookup_elem(&io_uring_ring_stats, &ring_ctx);
    if (stats)
        return stats;
    initial.flags = BPF_CORE_READ(ring, flags);
    initial.sq_entries = BPF_CORE_READ(ring, sq_entries);
    initial.cq_entries = BPF_CORE_READ(ring, cq_entries);
    bpf_map_update_elem(&io_uring_ring_stats, &ring_ctx, &initial,
                        BPF_NOEXIST);
    return bpf_map_lookup_elem(&io_uring_ring_stats, &ring_ctx);
}

SEC("raw_tp/io_uring_create")
int trace_io_uring_create(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tgid;
    u64 ring_ctx = ctx->args[1];
    struct io_uring_ring_stats *stats;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    s32 pidns_error;

    if (!trace_io_uring ||
        !get_process_info(&pid_tgid, &global_pid, &global_tid,
                          &pid, &tid, &pidns_error))
        return 0;
    stats = get_io_uring_ring_stats(ring_ctx, pid);
    if (!stats)
        return 0;
    stats->ring_fd = (s32)ctx->args[0];
    stats->sq_entries = (u32)ctx->args[2];
    stats->cq_entries = (u32)ctx->args[3];
    stats->flags = (u32)ctx->args[4];
    return 0;
}

SEC("raw_tp/io_uring_register")
int trace_io_uring_register(struct bpf_raw_tracepoint_args *ctx)
{
    u64 ring_ctx = ctx->args[0];
    struct io_uring_ring_stats *stats;

    if (!trace_io_uring)
        return 0;
    stats = bpf_map_lookup_elem(&io_uring_ring_stats, &ring_ctx);
    if (!stats || (target_pid && target_pid != stats->owner_pid))
        return 0;
    __sync_fetch_and_add(&stats->registrations, 1);
    stats->registered_files = (u32)ctx->args[2];
    stats->registered_buffers = (u32)ctx->args[3];
    return 0;
}

SEC("raw_tp/io_uring_submit_req")
int trace_io_uring_submit_req(struct bpf_raw_tracepoint_args *ctx)
{
    struct io_kiocb *request = (struct io_kiocb *)ctx->args[0];
    struct io_uring_request_state state = {
        .fd = -1,
        .stack_id = -1,
    };
    struct io_uring_counters *counters;
    struct io_uring_task *uring_task;
    struct task_struct *submit_task;
    u64 current_pid_tgid;
    u64 request_key = (u64)request;
    u64 pending;
    u32 zero = 0;
    u8 one = 1;
    s32 pidns_error;

    if (!trace_io_uring || !request)
        return 0;

    uring_task = BPF_CORE_READ(request, tctx);
    if (!uring_task)
        return 0;
    submit_task = BPF_CORE_READ(uring_task, task);
    if (!submit_task)
        return 0;

    state.global_pid = BPF_CORE_READ(submit_task, tgid);
    state.global_tid = BPF_CORE_READ(submit_task, pid);
    state.pid = state.global_pid;
    state.tid = state.global_tid;
    current_pid_tgid = bpf_get_current_pid_tgid();
    if ((u32)(current_pid_tgid >> 32) == state.global_pid) {
        if (!get_process_info(&current_pid_tgid, &state.global_pid,
                              &state.global_tid, &state.pid, &state.tid,
                              &pidns_error))
            return 0;
        bpf_get_current_comm(state.comm, sizeof(state.comm));
        state.stack_id = bpf_get_stackid(ctx, &io_uring_stacks,
                                         BPF_F_USER_STACK);
    } else {
        if (target_pid && target_pid != state.global_pid)
            return 0;
        state.sq_thread = 1;
        __builtin_memcpy(state.comm, "sqpoll", sizeof("sqpoll"));
    }

    state.submit_ns = bpf_ktime_get_ns();
    state.ring_ctx = (u64)BPF_CORE_READ(request, ctx);
    state.user_data = BPF_CORE_READ(request, cqe.user_data);
    state.request_flags = BPF_CORE_READ(request, flags);
    state.opcode = BPF_CORE_READ(request, opcode);
    bpf_map_update_elem(&io_uring_contexts, &state.ring_ctx, &one,
                        BPF_ANY);
    bpf_map_update_elem(&io_uring_requests, &request_key, &state, BPF_ANY);

    counters = bpf_map_lookup_elem(&io_uring_counters, &zero);
    if (!counters)
        return 0;
    __sync_fetch_and_add(&counters->submitted, 1);
    pending = __sync_add_and_fetch(&counters->pending, 1);
    update_peak(&counters->peak_pending, pending);
    {
        struct io_uring_ring_stats *ring_stats =
            get_io_uring_ring_stats(state.ring_ctx, state.pid);

        if (ring_stats) {
            __sync_fetch_and_add(&ring_stats->submitted, 1);
            pending =
                __sync_add_and_fetch(&ring_stats->pending, 1);
            update_peak(&ring_stats->peak_pending, pending);
        }
    }
    return 0;
}

SEC("raw_tp/io_uring_defer")
int trace_io_uring_defer(struct bpf_raw_tracepoint_args *ctx)
{
    u64 request_key = ctx->args[0];
    struct io_uring_request_state *state;
    struct io_uring_ring_stats *ring_stats;

    if (!trace_io_uring || !request_key)
        return 0;
    state = bpf_map_lookup_elem(&io_uring_requests, &request_key);
    if (!state)
        return 0;
    if (!state->defer_ns) {
        state->defer_ns = bpf_ktime_get_ns();
        state->deferred = 1;
        ring_stats = bpf_map_lookup_elem(
            &io_uring_ring_stats, &state->ring_ctx);
        if (ring_stats)
            __sync_fetch_and_add(&ring_stats->deferred, 1);
    }
    return 0;
}

SEC("raw_tp/io_uring_queue_async_work")
int trace_io_uring_queue_async_work(struct bpf_raw_tracepoint_args *ctx)
{
    u64 request_key = ctx->args[0];
    struct io_uring_request_state *state;
    struct io_uring_ring_stats *ring_stats;

    if (!trace_io_uring || !request_key)
        return 0;
    state = bpf_map_lookup_elem(&io_uring_requests, &request_key);
    if (!state)
        return 0;
    if (!state->async_queue_ns) {
        state->async_queue_ns = bpf_ktime_get_ns();
        state->io_wq = 1;
        state->io_wq_hashed = ctx->args[1] ? 1 : 0;
        ring_stats = bpf_map_lookup_elem(
            &io_uring_ring_stats, &state->ring_ctx);
        if (ring_stats) {
            __sync_fetch_and_add(&ring_stats->io_wq, 1);
            if (state->io_wq_hashed)
                __sync_fetch_and_add(&ring_stats->io_wq_hashed, 1);
        }
    }
    return 0;
}

SEC("kprobe/io_wq_submit_work")
int BPF_KPROBE(trace_io_wq_submit_work, struct io_wq_work *work)
{
    struct io_kiocb *request;
    struct io_uring_request_state *state;
    u64 request_key;

    if (!trace_io_uring || !work)
        return 0;
    request = (struct io_kiocb *)((char *)work -
        bpf_core_field_offset(struct io_kiocb, work));
    request_key = (u64)request;
    state = bpf_map_lookup_elem(&io_uring_requests, &request_key);
    if (state && !state->worker_start_ns)
        state->worker_start_ns = bpf_ktime_get_ns();
    return 0;
}

SEC("raw_tp/io_uring_poll_arm")
int trace_io_uring_poll_arm(struct bpf_raw_tracepoint_args *ctx)
{
    u64 request_key = ctx->args[0];
    struct io_uring_request_state *state;
    struct io_uring_ring_stats *ring_stats;

    if (!trace_io_uring || !request_key)
        return 0;
    state = bpf_map_lookup_elem(&io_uring_requests, &request_key);
    if (!state || state->poll_armed)
        return 0;
    state->poll_armed = 1;
    ring_stats = bpf_map_lookup_elem(
        &io_uring_ring_stats, &state->ring_ctx);
    if (ring_stats)
        __sync_fetch_and_add(&ring_stats->poll_armed, 1);
    return 0;
}

SEC("raw_tp/io_uring_file_get")
int trace_io_uring_file_get(struct bpf_raw_tracepoint_args *ctx)
{
    struct io_kiocb *request = (struct io_kiocb *)ctx->args[0];
    struct io_uring_request_state *state;
    u64 request_key = (u64)request;

    if (!trace_io_uring || !request)
        return 0;
    state = bpf_map_lookup_elem(&io_uring_requests, &request_key);
    if (state)
        state->fd = (s32)ctx->args[1];
    return 0;
}

SEC("raw_tp/io_uring_cqring_wait")
int trace_io_uring_cqring_wait(struct bpf_raw_tracepoint_args *ctx)
{
    u64 ring_ctx = ctx->args[0];
    struct io_uring_ring_stats *stats;

    if (!trace_io_uring)
        return 0;
    stats = bpf_map_lookup_elem(&io_uring_ring_stats, &ring_ctx);
    if (stats && (!target_pid || target_pid == stats->owner_pid))
        __sync_fetch_and_add(&stats->cq_waits, 1);
    return 0;
}

SEC("raw_tp/io_uring_cqe_overflow")
int trace_io_uring_cqe_overflow(struct bpf_raw_tracepoint_args *ctx)
{
    u64 ring_ctx = ctx->args[0];
    struct io_uring_ring_stats *stats;

    if (!trace_io_uring)
        return 0;
    stats = bpf_map_lookup_elem(&io_uring_ring_stats, &ring_ctx);
    if (stats && (!target_pid || target_pid == stats->owner_pid))
        __sync_fetch_and_add(&stats->cq_overflows, 1);
    return 0;
}

SEC("raw_tp/io_uring_req_failed")
int trace_io_uring_req_failed(struct bpf_raw_tracepoint_args *ctx)
{
    struct io_uring_sqe *sqe =
        (struct io_uring_sqe *)ctx->args[0];
    struct io_kiocb *request =
        (struct io_kiocb *)ctx->args[1];
    struct io_uring_failure_key key = {0};
    struct io_uring_failure_stats initial = {0};
    struct io_uring_failure_stats *stats;
    struct io_uring_ring_stats *ring_stats;
    struct io_ring_ctx *ring;
    u64 ring_ctx;
    u64 pid_tgid;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    s32 pidns_error;

    if (!trace_io_uring || !sqe || !request)
        return 0;
    if (!get_process_info(&pid_tgid, &global_pid, &global_tid,
                          &pid, &tid, &pidns_error))
        return 0;
    ring = BPF_CORE_READ(request, ctx);
    ring_ctx = (u64)ring;
    ring_stats = get_io_uring_ring_stats(ring_ctx, pid);
    if (!ring_stats)
        return 0;
    __sync_fetch_and_add(&ring_stats->request_failures, 1);
    key.ring_ctx = ring_ctx;
    key.error = (s32)ctx->args[2];
    key.opcode = BPF_CORE_READ(sqe, opcode);
    initial.user_data = BPF_CORE_READ(sqe, user_data);
    initial.offset = BPF_CORE_READ(sqe, off);
    initial.address = BPF_CORE_READ(sqe, addr);
    initial.address3 = BPF_CORE_READ(sqe, addr3);
    initial.length = BPF_CORE_READ(sqe, len);
    initial.operation_flags = BPF_CORE_READ(sqe, rw_flags);
    initial.file_index = BPF_CORE_READ(sqe, file_index);
    initial.buffer_index = BPF_CORE_READ(sqe, buf_index);
    initial.sqe_flags = BPF_CORE_READ(sqe, flags);
    initial.ioprio = BPF_CORE_READ(sqe, ioprio);
    stats = bpf_map_lookup_elem(&io_uring_failures, &key);
    if (!stats) {
        bpf_map_update_elem(&io_uring_failures, &key, &initial,
                            BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&io_uring_failures, &key);
    }
    if (stats)
        __sync_fetch_and_add(&stats->count, 1);
    return 0;
}

static __always_inline void record_io_uring_link(
    struct io_kiocb *parent, struct io_kiocb *child, bool failed)
{
    struct io_uring_link_key key = {0};
    struct io_uring_link_stats initial = {0};
    struct io_uring_link_stats *stats;
    struct io_uring_request_state *parent_state;
    struct io_uring_request_state *child_state;
    struct io_uring_ring_stats *ring_stats;
    u64 parent_key = (u64)parent;
    u64 child_key = (u64)child;

    if (!parent || !child)
        return;
    parent_state = bpf_map_lookup_elem(
        &io_uring_requests, &parent_key);
    child_state = bpf_map_lookup_elem(
        &io_uring_requests, &child_key);
    if (!parent_state ||
        (target_pid && target_pid != parent_state->pid))
        return;
    key.ring_ctx = parent_state->ring_ctx;
    key.parent_user_data = parent_state->user_data;
    initial.parent_opcode = parent_state->opcode;
    if (child_state) {
        key.child_user_data = child_state->user_data;
        initial.child_opcode = child_state->opcode;
    } else {
        key.child_user_data = BPF_CORE_READ(child, cqe.user_data);
        initial.child_opcode = BPF_CORE_READ(child, opcode);
    }
    initial.parent_request = parent_key;
    initial.child_request = child_key;
    stats = bpf_map_lookup_elem(&io_uring_links, &key);
    if (!stats) {
        bpf_map_update_elem(&io_uring_links, &key, &initial,
                            BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&io_uring_links, &key);
    }
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        if (failed)
            __sync_fetch_and_add(&stats->failures, 1);
    }
    ring_stats = bpf_map_lookup_elem(
        &io_uring_ring_stats, &parent_state->ring_ctx);
    if (ring_stats) {
        if (failed)
            __sync_fetch_and_add(&ring_stats->failed_links, 1);
        else
            __sync_fetch_and_add(&ring_stats->links, 1);
    }
}

SEC("raw_tp/io_uring_link")
int trace_io_uring_link(struct bpf_raw_tracepoint_args *ctx)
{
    if (trace_io_uring)
        record_io_uring_link(
            (struct io_kiocb *)ctx->args[1],
            (struct io_kiocb *)ctx->args[0], false);
    return 0;
}

SEC("raw_tp/io_uring_fail_link")
int trace_io_uring_fail_link(struct bpf_raw_tracepoint_args *ctx)
{
    if (trace_io_uring)
        record_io_uring_link(
            (struct io_kiocb *)ctx->args[0],
            (struct io_kiocb *)ctx->args[1], true);
    return 0;
}

SEC("raw_tp/io_uring_complete")
int trace_io_uring_complete(struct bpf_raw_tracepoint_args *ctx)
{
    struct io_kiocb *request = (struct io_kiocb *)ctx->args[1];
    struct io_uring_cqe *completion =
        (struct io_uring_cqe *)ctx->args[2];
    struct io_uring_request_state *state;
    struct io_uring_request_state saved;
    struct io_uring_counters *counters;
    struct io_uring_aggregate_key aggregate_key = {0};
    struct io_uring_aggregate initial_aggregate = {0};
    struct io_uring_aggregate *aggregate;
    struct io_uring_result_key result_key = {0};
    u64 initial_result_count = 0;
    u64 *result_count;
    struct io_uring_event *event;
    u64 ring_ctx = ctx->args[0];
    u64 request_key = (u64)request;
    u64 current_pid_tgid;
    u64 duration_ns;
    u64 defer_delay_ns = 0;
    u64 io_wq_queue_ns = 0;
    u64 after_io_wq_ns = 0;
    u64 now;
    s32 result;
    u32 cqe_flags;
    u32 zero = 0;
    bool is_error;

    if (!trace_io_uring || !request || !completion)
        return 0;
    state = bpf_map_lookup_elem(&io_uring_requests, &request_key);
    if (!state) {
        if (bpf_map_lookup_elem(&io_uring_contexts, &ring_ctx)) {
            counters = bpf_map_lookup_elem(&io_uring_counters, &zero);
            if (counters)
                __sync_fetch_and_add(&counters->unmatched, 1);
        }
        return 0;
    }
    __builtin_memcpy(&saved, state, sizeof(saved));
    now = bpf_ktime_get_ns();
    duration_ns = now >= saved.submit_ns ? now - saved.submit_ns : 0;
    if (saved.defer_ns && saved.defer_ns >= saved.submit_ns)
        defer_delay_ns = saved.defer_ns - saved.submit_ns;
    if (saved.worker_start_ns && saved.async_queue_ns &&
        saved.worker_start_ns >= saved.async_queue_ns)
        io_wq_queue_ns =
            saved.worker_start_ns - saved.async_queue_ns;
    if (saved.worker_start_ns && now >= saved.worker_start_ns)
        after_io_wq_ns = now - saved.worker_start_ns;
    cqe_flags = BPF_CORE_READ(completion, flags);
    result = BPF_CORE_READ(completion, res);
    is_error =
        result < 0 &&
        !(saved.opcode == IO_URING_OP_TIMEOUT &&
          result == -IO_URING_ETIME);

    if (enable_io_uring_callback) {
        struct io_uring_completion_key completion_key = {
            .global_pid = saved.global_pid,
            .user_data = BPF_CORE_READ(completion, user_data),
        };
        struct io_uring_completion_context completion_context = {
            .completion_ns = now,
            .submit_ns = saved.submit_ns,
            .duration_ns = duration_ns,
            .ring_ctx = saved.ring_ctx,
            .request = request_key,
            .result = result,
            .cqe_flags = cqe_flags,
            .opcode = saved.opcode,
        };

        bpf_map_update_elem(&io_uring_completions, &completion_key,
                            &completion_context, BPF_ANY);
    }

    counters = bpf_map_lookup_elem(&io_uring_counters, &zero);
    if (counters) {
        __sync_fetch_and_add(&counters->completions, 1);
        if (is_error)
            __sync_fetch_and_add(&counters->errors, 1);
        else if (saved.opcode == IO_URING_OP_TIMEOUT &&
                 result == -IO_URING_ETIME)
            __sync_fetch_and_add(&counters->expected_timeouts, 1);
        if (!(cqe_flags & IO_URING_CQE_F_MORE)) {
            if (counters->pending)
                __sync_fetch_and_sub(&counters->pending, 1);
            __sync_fetch_and_add(&counters->finished, 1);
        }
    }

    {
        struct io_uring_ring_stats *ring_stats =
            bpf_map_lookup_elem(&io_uring_ring_stats,
                                &saved.ring_ctx);

        if (ring_stats) {
            __sync_fetch_and_add(&ring_stats->completions, 1);
            if (is_error)
                __sync_fetch_and_add(&ring_stats->errors, 1);
            else if (saved.opcode == IO_URING_OP_TIMEOUT &&
                     result == -IO_URING_ETIME)
                __sync_fetch_and_add(
                    &ring_stats->expected_timeouts, 1);
            if (!(cqe_flags & IO_URING_CQE_F_MORE) &&
                ring_stats->pending)
                __sync_fetch_and_sub(&ring_stats->pending, 1);
            __sync_fetch_and_add(&ring_stats->total_ns,
                                 duration_ns);
            update_peak(&ring_stats->maximum_ns, duration_ns);
            if (io_wq_queue_ns) {
                __sync_fetch_and_add(
                    &ring_stats->io_wq_queue_total_ns,
                    io_wq_queue_ns);
                update_peak(
                    &ring_stats->io_wq_queue_maximum_ns,
                    io_wq_queue_ns);
            }
        }
    }

    if (result < 0) {
        result_key.result = result;
        result_key.opcode = saved.opcode;
        result_count = bpf_map_lookup_elem(&io_uring_results,
                                           &result_key);
        if (!result_count) {
            bpf_map_update_elem(&io_uring_results, &result_key,
                                &initial_result_count, BPF_NOEXIST);
            result_count = bpf_map_lookup_elem(&io_uring_results,
                                               &result_key);
        }
        if (result_count)
            __sync_fetch_and_add(result_count, 1);
    }

    aggregate_key.ring_ctx = saved.ring_ctx;
    aggregate_key.stack_id = saved.stack_id;
    aggregate_key.fd = saved.fd;
    aggregate_key.opcode = saved.opcode;
    aggregate = bpf_map_lookup_elem(&io_uring_aggregates,
                                    &aggregate_key);
    if (!aggregate) {
        bpf_map_update_elem(&io_uring_aggregates, &aggregate_key,
                            &initial_aggregate, BPF_NOEXIST);
        aggregate = bpf_map_lookup_elem(&io_uring_aggregates,
                                        &aggregate_key);
    }
    if (aggregate) {
        __sync_fetch_and_add(&aggregate->count, 1);
        if (is_error)
            __sync_fetch_and_add(&aggregate->errors, 1);
        __sync_fetch_and_add(&aggregate->total_ns, duration_ns);
        update_peak(&aggregate->maximum_ns, duration_ns);
        if (io_uring_min_latency_ns &&
            duration_ns >= io_uring_min_latency_ns)
            __sync_fetch_and_add(&aggregate->slow_count, 1);
        if (saved.deferred)
            __sync_fetch_and_add(&aggregate->deferred_count, 1);
        if (saved.io_wq)
            __sync_fetch_and_add(&aggregate->io_wq_count, 1);
        if (io_wq_queue_ns) {
            __sync_fetch_and_add(
                &aggregate->io_wq_queue_total_ns,
                io_wq_queue_ns);
            update_peak(&aggregate->io_wq_queue_maximum_ns,
                        io_wq_queue_ns);
        }
    }

    if ((io_uring_errors_only && !is_error) ||
        (io_uring_min_latency_ns &&
         duration_ns < io_uring_min_latency_ns)) {
        if (!(cqe_flags & IO_URING_CQE_F_MORE))
            bpf_map_delete_elem(&io_uring_requests, &request_key);
        return 0;
    }

    event = bpf_ringbuf_reserve(&io_uring_events, sizeof(*event), 0);
    if (!event) {
        counters = bpf_map_lookup_elem(&io_uring_counters, &zero);
        if (counters)
            __sync_fetch_and_add(&counters->dropped_events, 1);
        if (!(cqe_flags & IO_URING_CQE_F_MORE))
            bpf_map_delete_elem(&io_uring_requests, &request_key);
        return 0;
    }

    current_pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = now;
    event->submit_ns = saved.submit_ns;
    event->duration_ns = duration_ns;
    event->defer_delay_ns = defer_delay_ns;
    event->io_wq_queue_ns = io_wq_queue_ns;
    event->after_io_wq_ns = after_io_wq_ns;
    event->ring_ctx = saved.ring_ctx;
    event->request = request_key;
    event->user_data = BPF_CORE_READ(completion, user_data);
    event->request_flags = saved.request_flags;
    event->submit_pid = saved.pid;
    event->submit_tid = saved.tid;
    event->submit_global_pid = saved.global_pid;
    event->submit_global_tid = saved.global_tid;
    event->complete_global_pid = current_pid_tgid >> 32;
    event->complete_global_tid = (u32)current_pid_tgid;
    event->fd = saved.fd;
    event->result = result;
    event->cqe_flags = cqe_flags;
    event->stack_id = saved.stack_id;
    event->opcode = saved.opcode;
    event->sq_thread = saved.sq_thread;
    event->deferred = saved.deferred;
    event->io_wq = saved.io_wq;
    event->io_wq_hashed = saved.io_wq_hashed;
    event->poll_armed = saved.poll_armed;
    event->reserved = 0;
    __builtin_memcpy(event->submit_comm, saved.comm,
                     sizeof(event->submit_comm));
    bpf_get_current_comm(event->complete_comm,
                         sizeof(event->complete_comm));
    bpf_ringbuf_submit(event, 0);

    if (!(cqe_flags & IO_URING_CQE_F_MORE))
        bpf_map_delete_elem(&io_uring_requests, &request_key);
    return 0;
}

SEC("uprobe")
int trace_io_uring_callback(struct pt_regs *ctx)
{
    struct io_uring_completion_key key = {0};
    struct io_uring_completion_context *completion;
    struct io_uring_callback_event *event;
    u64 pid_tgid;
    u64 now;
    u32 global_pid;
    u32 global_tid;
    u32 pid;
    u32 tid;
    u32 zero = 0;
    s32 pidns_error;
    struct io_uring_counters *counters;

    if (!enable_io_uring_callback ||
        !get_process_info(&pid_tgid, &global_pid, &global_tid,
                          &pid, &tid, &pidns_error))
        return 0;
    key.global_pid = global_pid;
    key.user_data =
        read_uprobe_argument(ctx, io_uring_callback_arg);
    completion = bpf_map_lookup_elem(&io_uring_completions, &key);
    counters = bpf_map_lookup_elem(&io_uring_counters, &zero);
    if (!completion) {
        if (counters)
            __sync_fetch_and_add(&counters->callback_unmatched, 1);
        return 0;
    }
    if (counters)
        __sync_fetch_and_add(&counters->callback_matched, 1);
    now = bpf_ktime_get_ns();
    event = bpf_ringbuf_reserve(&io_uring_callback_events,
                                sizeof(*event), 0);
    if (!event) {
        if (counters)
            __sync_fetch_and_add(&counters->callback_dropped, 1);
        return 0;
    }
    event->timestamp_ns = now;
    event->completion_ns = completion->completion_ns;
    event->callback_delay_ns =
        now >= completion->completion_ns ?
            now - completion->completion_ns : 0;
    event->request_duration_ns = completion->duration_ns;
    event->ring_ctx = completion->ring_ctx;
    event->request = completion->request;
    event->user_data = key.user_data;
    event->pid = pid;
    event->tid = tid;
    event->global_pid = global_pid;
    event->global_tid = global_tid;
    event->result = completion->result;
    event->cqe_flags = completion->cqe_flags;
    event->stack_id = bpf_get_stackid(ctx, &io_uring_stacks,
                                      BPF_F_USER_STACK);
    event->opcode = completion->opcode;
    __builtin_memset(event->reserved, 0, sizeof(event->reserved));
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&io_uring_completions, &key);
    return 0;
}

#endif
