// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_EPOLL_BPF_PROGS_H
#define CALLWEAVE_EPOLL_BPF_PROGS_H

#define CW_EPOLL_CTL_ADD 1
#define CW_EPOLL_CTL_DEL 2
#define CW_EPOLL_CTL_MOD 3
#define CW_EINTR 4
#define CW_EAGAIN 11
#define CW_EINPROGRESS 115
#define CW_EPOLL_IN (1U << 0)
#define CW_EPOLL_PRI (1U << 1)
#define CW_EPOLL_ERR (1U << 3)
#define CW_EPOLL_HUP (1U << 4)
#define CW_EPOLL_RDHUP (1U << 13)
#define CW_EPOLL_ONESHOT (1U << 30)
#define CW_EPOLL_ET (1U << 31)
#define CW_EPOLL_EXCLUSIVE (1U << 28)
#define CW_MSG_PEEK 2
#define CW_F_DUPFD 0
#define CW_F_DUPFD_CLOEXEC 1030

#if defined(__TARGET_ARCH_x86)
struct cw_userspace_epoll_event {
    __u32 events;
    __u64 data;
} __attribute__((packed));
#else
struct cw_userspace_epoll_event {
    __u32 events;
    __u64 data;
};
#endif

struct cw_userspace_iovec {
    __u64 base;
    __u64 length;
};

struct cw_userspace_msghdr {
    __u64 name;
    __u32 name_length;
    __u32 pad;
    __u64 iov;
    __u64 iov_length;
    __u64 control;
    __u64 control_length;
    __u32 flags;
    __u32 pad2;
};

static __always_inline bool cw_is_epoll_wait_syscall(
    __s32 syscall_nr, __u32 *wait_kind)
{
    if (syscall_nr == cw_epoll_cfg.wait_syscall_nr) {
        *wait_kind = CW_EPOLL_WAIT;
        return true;
    }
    if (syscall_nr == cw_epoll_cfg.pwait_syscall_nr) {
        *wait_kind = CW_EPOLL_PWAIT;
        return true;
    }
    if (syscall_nr == cw_epoll_cfg.pwait2_syscall_nr) {
        *wait_kind = CW_EPOLL_PWAIT2;
        return true;
    }
    return false;
}

static __always_inline __u32 cw_epoll_io_operation(__s32 syscall_nr)
{
    __u32 index;

#pragma unroll
    for (index = 0; index < CW_EPOLL_MAX_IO_SYSCALLS; index++) {
        if (index >= cw_epoll_cfg.io_syscall_count)
            break;
        if (cw_epoll_cfg.io_syscalls[index].syscall_nr == syscall_nr)
            return cw_epoll_cfg.io_syscalls[index].operation;
    }
    return CW_EPOLL_IO_NONE;
}

static __attribute__((noinline)) void cw_epoll_finish_dispatch_batch(
    __u64 pid_tgid, __u64 now);
static __attribute__((noinline)) void cw_epoll_record_io(
    void *stack_context, struct pt_regs *registers,
    __u64 pid_tgid, __u32 pid, __u32 operation);
static __attribute__((noinline)) void cw_epoll_apply_dispatch_wake(
    const struct cw_epoll_dispatch_key *key,
    struct cw_epoll_dispatch_item *item);

static __always_inline __u32 cw_epoll_fd_generation(
    __u32 pid, __s32 fd)
{
    struct cw_epoll_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    __u32 initial = 1;
    __u32 *generation =
        bpf_map_lookup_elem(&epoll_fd_generations, &key);

    if (generation)
        return *generation;
    bpf_map_update_elem(
        &epoll_fd_generations, &key, &initial, BPF_NOEXIST);
    generation = bpf_map_lookup_elem(&epoll_fd_generations, &key);
    return generation ? *generation : 1;
}

static __always_inline void cw_epoll_advance_fd_generation(
    __u32 pid, __s32 fd)
{
    struct cw_epoll_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    __u32 initial = 2;
    __u32 *generation =
        bpf_map_lookup_elem(&epoll_fd_generations, &key);

    if (generation)
        __sync_fetch_and_add(generation, 1);
    else
        bpf_map_update_elem(
            &epoll_fd_generations, &key, &initial, BPF_ANY);
}

static __attribute__((noinline)) void cw_epoll_record_ctl(
    struct pt_regs *registers, __u64 pid_tgid, __u32 pid)
{
    struct cw_epoll_ctl_state state = {
        .pid = pid,
        .epoll_fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers),
        .operation =
            (__s32)PT_REGS_PARM2_CORE_SYSCALL(registers),
        .fd = (__s32)PT_REGS_PARM3_CORE_SYSCALL(registers),
    };
    const struct cw_userspace_epoll_event *event =
        (const void *)PT_REGS_PARM4_CORE_SYSCALL(registers);
    struct cw_userspace_epoll_event copied = {0};

    state.epoll_generation =
        cw_epoll_fd_generation(pid, state.epoll_fd);
    state.fd_generation =
        cw_epoll_fd_generation(pid, state.fd);
    if ((state.operation == CW_EPOLL_CTL_ADD ||
         state.operation == CW_EPOLL_CTL_MOD) &&
        event &&
        !bpf_probe_read_user(&copied, sizeof(copied), event)) {
        state.events = copied.events;
        state.data = copied.data;
    }
    bpf_map_update_elem(&epoll_ctl_states, &pid_tgid, &state, BPF_ANY);
}

static __always_inline void cw_epoll_record_wait(
    void *stack_context, struct pt_regs *registers, __u64 pid_tgid,
    __u32 global_pid, __u32 global_tid, __u32 pid, __u32 tid,
    __u32 wait_kind)
{
    struct cw_epoll_loop_key loop_key = {
        .global_pid = global_pid,
        .global_tid = global_tid,
        .epoll_fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers),
    };
    struct cw_epoll_loop_stats *known_loop;
    struct cw_epoll_instance_key instance_key;
    struct cw_epoll_instance_stats initial_instance = {0};
    struct cw_epoll_instance_stats *instance;
    struct cw_epoll_wait_state state = {
        .start_ns = bpf_ktime_get_ns(),
        .events_address =
            PT_REGS_PARM2_CORE_SYSCALL(registers),
        .pid = pid,
        .tid = tid,
        .global_pid = global_pid,
        .global_tid = global_tid,
        .epoll_fd = loop_key.epoll_fd,
        .max_events =
            (__u32)PT_REGS_PARM3_CORE_SYSCALL(registers),
        .timeout_ms = -2,
        .stack_id = -1,
        .wait_kind = wait_kind,
    };

    state.epoll_generation =
        cw_epoll_fd_generation(pid, state.epoll_fd);
    loop_key.epoll_generation = state.epoll_generation;
    known_loop = bpf_map_lookup_elem(&epoll_loop_stats, &loop_key);
    instance_key.pid = pid;
    instance_key.epoll_fd = state.epoll_fd;
    instance_key.epoll_generation = state.epoll_generation;
    instance_key.reserved = 0;
    bpf_map_update_elem(
        &epoll_instance_stats, &instance_key,
        &initial_instance, BPF_NOEXIST);
    instance = bpf_map_lookup_elem(
        &epoll_instance_stats, &instance_key);
    if (instance) {
        __u64 active =
            __sync_add_and_fetch(&instance->active_waiters, 1);

        __sync_fetch_and_add(&instance->calls, 1);
        update_peak(&instance->peak_waiters, active);
    }
    if (wait_kind != CW_EPOLL_PWAIT2)
        state.timeout_ms =
            (__s32)PT_REGS_PARM4_CORE_SYSCALL(registers);
    bpf_get_current_comm(state.comm, sizeof(state.comm));
    if (known_loop)
        state.stack_id = known_loop->stack_id;
    else
        state.stack_id = bpf_get_stackid(
            stack_context, &epoll_stacks, BPF_F_USER_STACK);
    bpf_map_update_elem(&epoll_wait_states, &pid_tgid, &state, BPF_ANY);
}

SEC("raw_tp/sys_enter")
int trace_epoll_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *registers = (struct pt_regs *)ctx->args[0];
    __s32 syscall_nr = (__s32)ctx->args[1];
    __u64 pid_tgid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 pid;
    __u32 tid;
    __u32 wait_kind = 0;
    __u32 io_operation;
    __s32 pidns_error;
    bool wait_syscall;

    if (!cw_epoll_capture_active())
        return 0;
    wait_syscall =
        cw_is_epoll_wait_syscall(syscall_nr, &wait_kind);
    io_operation = cw_epoll_io_operation(syscall_nr);
    if (syscall_nr != cw_epoll_cfg.ctl_syscall_nr &&
        !wait_syscall && !io_operation)
        return 0;
    if (!get_process_info(&pid_tgid, &global_pid, &global_tid,
                          &pid, &tid, &pidns_error))
        return 0;
    if (syscall_nr == cw_epoll_cfg.ctl_syscall_nr)
        cw_epoll_record_ctl(registers, pid_tgid, pid);
    else if (wait_syscall) {
        cw_epoll_finish_dispatch_batch(
            pid_tgid, bpf_ktime_get_ns());
        cw_epoll_record_wait(ctx, registers, pid_tgid, global_pid,
                             global_tid, pid, tid, wait_kind);
    } else {
        cw_epoll_record_io(
            ctx, registers, pid_tgid, pid, io_operation);
    }
    return 0;
}

static __attribute__((noinline)) void cw_epoll_apply_ctl(
    const struct cw_epoll_ctl_state *state, __u64 pid_tgid)
{
    struct cw_epoll_resource_key resource_key = {
        .pid = state->pid,
        .epoll_fd = state->epoll_fd,
        .epoll_generation = state->epoll_generation,
        .fd = state->fd,
        .fd_generation = state->fd_generation,
    };
    struct cw_epoll_registration *old_registration;
    struct cw_epoll_registration registration = {
        .data = state->data,
        .events = state->events,
    };
    struct cw_epoll_token_key token_key = {
        .data = state->data,
        .pid = state->pid,
        .epoll_fd = state->epoll_fd,
        .epoll_generation = state->epoll_generation,
    };
    struct cw_epoll_token_value token = {
        .fd = state->fd,
        .fd_generation = state->fd_generation,
    };
    struct cw_epoll_token_value *existing_token;
    struct cw_epoll_resource_stats *initial_stats;
    struct cw_epoll_resource_stats *stats;
    __u32 zero = 0;
    bool was_oneshot = false;

    old_registration =
        bpf_map_lookup_elem(&epoll_registrations, &resource_key);
    if (old_registration &&
        (old_registration->events & CW_EPOLL_ONESHOT))
        was_oneshot = true;
    if (old_registration &&
        (state->operation == CW_EPOLL_CTL_DEL ||
         old_registration->data != state->data)) {
        struct cw_epoll_token_key old_token_key = {
            .data = old_registration->data,
            .pid = state->pid,
            .epoll_fd = state->epoll_fd,
            .epoll_generation = state->epoll_generation,
        };
        struct cw_epoll_token_value *old_token =
            bpf_map_lookup_elem(&epoll_tokens, &old_token_key);

        if (old_token && old_token->fd == state->fd &&
            old_token->fd_generation == state->fd_generation)
            bpf_map_delete_elem(&epoll_tokens, &old_token_key);
    }
    stats = bpf_map_lookup_elem(&epoll_resource_stats, &resource_key);
    if (!stats) {
        initial_stats = bpf_map_lookup_elem(
            &epoll_resource_scratch, &zero);
        if (initial_stats) {
            __builtin_memset(
                initial_stats, 0, sizeof(*initial_stats));
            initial_stats->dispatch_stack_id = -1;
            initial_stats->callback_stack_id = -1;
            bpf_map_update_elem(
                &epoll_resource_stats, &resource_key,
                initial_stats, BPF_NOEXIST);
        }
        stats = bpf_map_lookup_elem(&epoll_resource_stats, &resource_key);
    }
    if (state->operation == CW_EPOLL_CTL_DEL) {
        bpf_map_delete_elem(&epoll_registrations, &resource_key);
        if (stats)
            stats->active = 0;
        return;
    }

    existing_token = bpf_map_lookup_elem(&epoll_tokens, &token_key);
    if (existing_token && existing_token->fd != state->fd) {
        token.fd = -1;
        token.ambiguous = 1;
    }
    bpf_map_update_elem(&epoll_tokens, &token_key, &token, BPF_ANY);
    bpf_map_update_elem(&epoll_registrations, &resource_key,
                        &registration, BPF_ANY);
    if (stats) {
        stats->data = state->data;
        stats->interest_events = state->events;
        stats->active = 1;
        __sync_fetch_and_add(&stats->registrations, 1);
    }
    if (state->operation == CW_EPOLL_CTL_ADD &&
        state->fd_generation > 1) {
        struct cw_epoll_counters *counters =
            bpf_map_lookup_elem(&epoll_counters, &zero);

        if (counters)
            __sync_fetch_and_add(&counters->fd_reuses, 1);
    }
    if (state->operation == CW_EPOLL_CTL_ADD &&
        (state->events & CW_EPOLL_EXCLUSIVE)) {
        struct cw_epoll_instance_key instance_key = {
            .pid = state->pid,
            .epoll_fd = state->epoll_fd,
            .epoll_generation = state->epoll_generation,
        };
        struct cw_epoll_instance_stats initial_instance = {
            .exclusive_resources = 1,
        };
        struct cw_epoll_instance_stats *instance =
            bpf_map_lookup_elem(
                &epoll_instance_stats, &instance_key);

        if (!instance)
            bpf_map_update_elem(
                &epoll_instance_stats, &instance_key,
                &initial_instance, BPF_NOEXIST);
        else
            __sync_fetch_and_add(&instance->exclusive_resources, 1);
    }
    if (state->operation == CW_EPOLL_CTL_MOD) {
        struct cw_epoll_dispatch_key dispatch_key = {
            .pid_tgid = pid_tgid,
            .fd = state->fd,
        };
        struct cw_epoll_dispatch_candidate *candidate =
            bpf_map_lookup_elem(
                &epoll_dispatch_candidates, &dispatch_key);

        if (candidate)
            candidate->item.flags |= CW_EPOLL_DISPATCH_REARMED;
        if (stats &&
            (was_oneshot ||
             (state->events & CW_EPOLL_ONESHOT)))
            __sync_fetch_and_add(&stats->oneshot_rearms, 1);
    }
}

static __always_inline struct cw_epoll_loop_stats *
cw_epoll_get_loop_stats(const struct cw_epoll_wait_state *state,
                        const struct cw_epoll_loop_key *key)
{
    struct cw_epoll_loop_stats initial = {
        .first_ns = state->start_ns,
        .pid = state->pid,
        .tid = state->tid,
        .stack_id = state->stack_id,
    };
    struct cw_epoll_loop_stats *stats;

    __builtin_memcpy(initial.comm, state->comm, sizeof(initial.comm));
    stats = bpf_map_lookup_elem(&epoll_loop_stats, key);
    if (stats)
        return stats;
    bpf_map_update_elem(&epoll_loop_stats, key, &initial, BPF_NOEXIST);
    return bpf_map_lookup_elem(&epoll_loop_stats, key);
}

static __attribute__((noinline)) void cw_epoll_batch_add_fd(
    struct cw_epoll_dispatch_batch *batch, int fd)
{
    __u32 count = batch->count;

    /*
     * epoll reports a registered item at most once in one wait result.  A
     * bounded direct append is therefore sufficient and avoids two search
     * loops whose count-dependent branches are expensive for the verifier.
     */
    if (count >= CW_EPOLL_MAX_READY)
        return;
    batch->fds[count] = fd;
    batch->count = count + 1;
}

/*
 * Keep the branch-heavy token/resource/dispatch bookkeeping outside the
 * bounded ready-event loop.  Otherwise the verifier explores the complete
 * branch tree once per possible array element and can hit its instruction
 * complexity limit even though the generated BPF bytecode is small.
 *
 * Return -1 when the userspace event cannot be read, 1 when event.data could
 * not be resolved to an FD, and 0 for a resolved event.
 */
static __attribute__((noinline)) int cw_epoll_process_one_ready_event(
    struct cw_epoll_event *event,
    const struct cw_epoll_wait_state *state,
    __u32 index, __u64 timestamp_ns)
{
    const struct cw_userspace_epoll_event *events =
        (const void *)state->events_address;
    struct cw_userspace_epoll_event copied = {0};
    struct cw_epoll_token_key token_key = {
        .pid = state->pid,
        .epoll_fd = state->epoll_fd,
        .epoll_generation = state->epoll_generation,
    };
    struct cw_epoll_token_value *token;

    if (index >= CW_EPOLL_MAX_READY)
        return -1;
    if (bpf_probe_read_user(&copied, sizeof(copied), &events[index]))
        return -1;
    if (event) {
        event->ready[index].events = copied.events;
        event->ready[index].data = copied.data;
        event->ready[index].fd = -1;
    }

    token_key.data = copied.data;
    token = bpf_map_lookup_elem(&epoll_tokens, &token_key);
    if (token && !token->ambiguous && token->fd >= 0) {
        struct cw_epoll_resource_key resource_key = {
            .pid = state->pid,
            .epoll_fd = state->epoll_fd,
            .epoll_generation = state->epoll_generation,
            .fd = token->fd,
            .fd_generation = token->fd_generation,
        };
        struct cw_epoll_resource_stats *resource_stats =
            bpf_map_lookup_elem(&epoll_resource_stats, &resource_key);
        struct cw_epoll_dispatch_key dispatch_key = {
            .pid_tgid =
                ((__u64)state->global_pid << 32) |
                state->global_tid,
            .fd = token->fd,
        };
        struct cw_epoll_dispatch_candidate initial_candidate = {
            .item = {
                .data = copied.data,
                .ready_ns = timestamp_ns,
                .ready_events = copied.events,
                .fd = token->fd,
                .epoll_generation = state->epoll_generation,
                .fd_generation = token->fd_generation,
                .first_operation = CW_EPOLL_IO_NONE,
                .last_operation = CW_EPOLL_IO_NONE,
                .stack_id = -1,
            },
        };
        struct cw_epoll_dispatch_candidate *candidate;
        struct cw_epoll_dispatch_batch *batch;

        if (event)
            event->ready[index].fd = token->fd;
        if (resource_stats) {
            __sync_fetch_and_add(&resource_stats->ready_count, 1);
            __sync_fetch_and_or(&resource_stats->observed_events,
                                copied.events);
            resource_stats->last_ready_ns = timestamp_ns;
            initial_candidate.item.interest_events =
                resource_stats->interest_events;
            initial_candidate.oneshot_rearms_at_ready =
                resource_stats->oneshot_rearms;
        }
        if ((initial_candidate.item.interest_events & CW_EPOLL_ET) &&
            (copied.events & (CW_EPOLL_IN | CW_EPOLL_PRI)))
            initial_candidate.item.flags |=
                CW_EPOLL_DISPATCH_ET_CANDIDATE;
        if (initial_candidate.item.interest_events & CW_EPOLL_ONESHOT)
            initial_candidate.item.flags |=
                CW_EPOLL_DISPATCH_ONESHOT_CANDIDATE;
        bpf_map_update_elem(
            &epoll_dispatch_candidates, &dispatch_key,
            &initial_candidate, BPF_NOEXIST);
        candidate = bpf_map_lookup_elem(
            &epoll_dispatch_candidates, &dispatch_key);
        if (candidate)
            candidate->item.ready_events |= copied.events;
        batch = bpf_map_lookup_elem(
            &epoll_dispatch_batches, &dispatch_key.pid_tgid);
        if (batch && batch->count < CW_EPOLL_MAX_READY)
            cw_epoll_batch_add_fd(batch, token->fd);
        return 0;
    }
    return 1;
}

static __attribute__((noinline)) __u32 cw_epoll_process_ready_events(
    struct cw_epoll_event *event,
    const struct cw_epoll_wait_state *state,
    __u32 ready_count, __u64 timestamp_ns)
{
    __u32 index;
    __u32 captured = 0;
    __u32 unresolved = 0;

#pragma clang loop unroll(disable)
    for (index = 0; index < CW_EPOLL_MAX_READY; index++) {
        int status;

        if (index >= ready_count)
            break;
        status = cw_epoll_process_one_ready_event(
            event, state, index, timestamp_ns);
        if (status < 0)
            break;
        unresolved += (__u32)status;
        captured++;
    }
    if (event) {
        event->captured_events = captured;
        event->unresolved_events = unresolved;
    }
    return unresolved;
}

static __attribute__((noinline)) void cw_epoll_finish_wait(
    const struct cw_epoll_wait_state *state, __s64 result)
{
    struct cw_epoll_loop_key loop_key = {
        .global_pid = state->global_pid,
        .global_tid = state->global_tid,
        .epoll_fd = state->epoll_fd,
        .epoll_generation = state->epoll_generation,
    };
    struct cw_epoll_loop_stats *loop_stats =
        cw_epoll_get_loop_stats(state, &loop_key);
    struct cw_epoll_counters *counters;
    struct cw_epoll_event *event;
    __u64 now = bpf_ktime_get_ns();
    __u64 wait_ns = now > state->start_ns ?
        now - state->start_ns : 0;
    __u32 ready_count = result > 0 ? (__u32)result : 0;
    __u32 unresolved = 0;
    __u32 zero = 0;
    struct cw_epoll_instance_key instance_key = {
        .pid = state->pid,
        .epoll_fd = state->epoll_fd,
        .epoll_generation = state->epoll_generation,
    };
    struct cw_epoll_instance_stats *instance =
        bpf_map_lookup_elem(&epoll_instance_stats, &instance_key);
    bool emit_detail =
        result < 0 || wait_ns >= cw_epoll_cfg.min_wait_ns;

    counters = bpf_map_lookup_elem(&epoll_counters, &zero);
    if (instance && instance->active_waiters)
        __sync_fetch_and_sub(&instance->active_waiters, 1);
    if (counters)
        __sync_fetch_and_add(&counters->calls, 1);
    if (loop_stats) {
        loop_stats->last_ns = now;
        loop_stats->stack_id = state->stack_id;
        __sync_fetch_and_add(&loop_stats->calls, 1);
        __sync_fetch_and_add(&loop_stats->total_wait_ns, wait_ns);
        update_peak(&loop_stats->maximum_wait_ns, wait_ns);
    }

    if (result > 0) {
        struct cw_epoll_dispatch_batch batch = {
            .ready_ns = now,
            .pid = state->pid,
            .tid = state->tid,
            .global_pid = state->global_pid,
            .global_tid = state->global_tid,
            .epoll_fd = state->epoll_fd,
            .epoll_generation = state->epoll_generation,
        };
        __u64 pid_tgid =
            ((__u64)state->global_pid << 32) | state->global_tid;

        __builtin_memcpy(batch.comm, state->comm, sizeof(batch.comm));
        bpf_map_update_elem(
            &epoll_dispatch_batches, &pid_tgid, &batch, BPF_ANY);
        if (counters) {
            __sync_fetch_and_add(&counters->ready_returns, 1);
            __sync_fetch_and_add(&counters->ready_events, ready_count);
        }
        if (instance) {
            __sync_fetch_and_add(&instance->ready_returns, 1);
            __sync_fetch_and_add(&instance->ready_events, ready_count);
        }
        if (loop_stats) {
            __sync_fetch_and_add(&loop_stats->ready_returns, 1);
            __sync_fetch_and_add(&loop_stats->ready_events, ready_count);
            update_peak(&loop_stats->maximum_batch, ready_count);
        }
        if (state->max_events && ready_count >= state->max_events) {
            if (counters)
                __sync_fetch_and_add(
                    &counters->saturated_batches, 1);
            if (loop_stats)
                __sync_fetch_and_add(
                    &loop_stats->saturated_batches, 1);
        }
        if (ready_count > CW_EPOLL_MAX_READY) {
            __u64 truncated = ready_count - CW_EPOLL_MAX_READY;

            if (counters)
                __sync_fetch_and_add(
                    &counters->truncated_events, truncated);
            if (loop_stats)
                __sync_fetch_and_add(
                    &loop_stats->truncated_events, truncated);
        }
    } else if (!result) {
        if (counters)
            __sync_fetch_and_add(&counters->timeouts, 1);
        if (loop_stats)
            __sync_fetch_and_add(&loop_stats->timeouts, 1);
    } else if (result == -CW_EINTR) {
        if (counters)
            __sync_fetch_and_add(&counters->interrupted, 1);
        if (loop_stats)
            __sync_fetch_and_add(&loop_stats->interrupted, 1);
    } else {
        if (counters)
            __sync_fetch_and_add(&counters->errors, 1);
        if (loop_stats)
            __sync_fetch_and_add(&loop_stats->errors, 1);
    }

    if (!ready_count && !emit_detail)
        return;
    if (!emit_detail) {
        unresolved = cw_epoll_process_ready_events(
            NULL, state, ready_count, now);
        if (unresolved) {
            if (counters)
                __sync_fetch_and_add(
                    &counters->unresolved_events, unresolved);
            if (loop_stats)
                __sync_fetch_and_add(
                    &loop_stats->unresolved_events, unresolved);
        }
        return;
    }
    event = bpf_ringbuf_reserve(&epoll_events, sizeof(*event), 0);
    if (!event) {
        if (ready_count)
            unresolved = cw_epoll_process_ready_events(
                NULL, state, ready_count, now);
        if (unresolved) {
            if (counters)
                __sync_fetch_and_add(
                    &counters->unresolved_events, unresolved);
            if (loop_stats)
                __sync_fetch_and_add(
                    &loop_stats->unresolved_events, unresolved);
        }
        if (counters)
            __sync_fetch_and_add(&counters->dropped, 1);
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = now;
    event->start_ns = state->start_ns;
    event->wait_ns = wait_ns;
    event->events_address = state->events_address;
    event->pid = state->pid;
    event->tid = state->tid;
    event->global_pid = state->global_pid;
    event->global_tid = state->global_tid;
    event->epoll_fd = state->epoll_fd;
    event->result = (__s32)result;
    event->timeout_ms = state->timeout_ms;
    event->stack_id = state->stack_id;
    event->max_events = state->max_events;
    event->wait_kind = state->wait_kind;
    __builtin_memcpy(event->comm, state->comm, sizeof(event->comm));
    if (ready_count)
        unresolved = cw_epoll_process_ready_events(
            event, state, ready_count, now);
    if (unresolved) {
        if (counters)
            __sync_fetch_and_add(
                &counters->unresolved_events, unresolved);
        if (loop_stats)
            __sync_fetch_and_add(
                &loop_stats->unresolved_events, unresolved);
    }
    bpf_ringbuf_submit(event, 0);
    if (counters)
        __sync_fetch_and_add(&counters->emitted, 1);
}

static __always_inline bool cw_epoll_is_read_operation(__u32 operation)
{
    return operation == CW_EPOLL_IO_READ ||
           operation == CW_EPOLL_IO_READV ||
           operation == CW_EPOLL_IO_RECVFROM ||
           operation == CW_EPOLL_IO_RECVMSG ||
           operation == CW_EPOLL_IO_RECVMMSG ||
           operation == CW_EPOLL_IO_ACCEPT ||
           operation == CW_EPOLL_IO_ACCEPT4 ||
           operation == CW_EPOLL_IO_SPLICE;
}

static __always_inline bool cw_epoll_is_write_operation(__u32 operation)
{
    return operation == CW_EPOLL_IO_WRITE ||
           operation == CW_EPOLL_IO_WRITEV ||
           operation == CW_EPOLL_IO_SENDTO ||
           operation == CW_EPOLL_IO_SENDMSG ||
           operation == CW_EPOLL_IO_SENDMMSG;
}

static __always_inline bool cw_epoll_result_is_bytes(__u32 operation)
{
    return (cw_epoll_is_read_operation(operation) &&
            operation != CW_EPOLL_IO_ACCEPT &&
            operation != CW_EPOLL_IO_ACCEPT4 &&
            operation != CW_EPOLL_IO_RECVMMSG) ||
           (cw_epoll_is_write_operation(operation) &&
            operation != CW_EPOLL_IO_SENDMMSG) ||
           operation == CW_EPOLL_IO_SPLICE;
}

static __always_inline bool cw_epoll_has_direct_size(__u32 operation)
{
    return operation == CW_EPOLL_IO_READ ||
           operation == CW_EPOLL_IO_RECVFROM ||
           operation == CW_EPOLL_IO_WRITE ||
           operation == CW_EPOLL_IO_SENDTO ||
           operation == CW_EPOLL_IO_SPLICE;
}

static __attribute__((noinline)) __u64 cw_epoll_iov_bytes(
    const struct cw_userspace_iovec *iov, __u64 count)
{
    __u64 total = 0;
    __u32 index;

#pragma unroll
    for (index = 0; index < 8; index++) {
        struct cw_userspace_iovec entry = {0};

        if (index >= count)
            break;
        if (bpf_probe_read_user(
                &entry, sizeof(entry), &iov[index]))
            break;
        total += entry.length;
    }
    return total;
}

static __attribute__((noinline)) __u64 cw_epoll_msghdr_bytes(
    const struct cw_userspace_msghdr *address)
{
    struct cw_userspace_msghdr message = {0};

    if (!address ||
        bpf_probe_read_user(
            &message, sizeof(message), address))
        return 0;
    return cw_epoll_iov_bytes(
        (const void *)message.iov, message.iov_length);
}

static __attribute__((noinline)) void cw_epoll_record_io(
    void *stack_context, struct pt_regs *registers,
    __u64 pid_tgid, __u32 pid, __u32 operation)
{
    __s32 fd = (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
    struct cw_epoll_dispatch_key key = {
        .pid_tgid = pid_tgid,
        .fd = fd,
    };
    struct cw_epoll_dispatch_candidate *candidate =
        bpf_map_lookup_elem(&epoll_dispatch_candidates, &key);
    struct cw_epoll_io_state state = {
        .key = key,
        .start_ns = bpf_ktime_get_ns(),
        .pid = pid,
        .operation = operation,
    };

    if (operation == CW_EPOLL_IO_FCNTL_DUP) {
        __u64 command =
            PT_REGS_PARM2_CORE_SYSCALL(registers);

        if (command != CW_F_DUPFD &&
            command != CW_F_DUPFD_CLOEXEC)
            return;
    }
    if (!candidate &&
        operation != CW_EPOLL_IO_CLOSE &&
        operation != CW_EPOLL_IO_DUP &&
        operation != CW_EPOLL_IO_DUP2 &&
        operation != CW_EPOLL_IO_DUP3 &&
        operation != CW_EPOLL_IO_FCNTL_DUP)
        return;
    if (cw_epoll_has_direct_size(operation))
        state.requested_bytes = operation == CW_EPOLL_IO_SPLICE ?
            PT_REGS_PARM5_CORE_SYSCALL(registers) :
            PT_REGS_PARM3_CORE_SYSCALL(registers);
    else if (operation == CW_EPOLL_IO_READV ||
             operation == CW_EPOLL_IO_WRITEV)
        state.requested_bytes = cw_epoll_iov_bytes(
            (const void *)PT_REGS_PARM2_CORE_SYSCALL(registers),
            PT_REGS_PARM3_CORE_SYSCALL(registers));
    else if (operation == CW_EPOLL_IO_RECVMSG ||
             operation == CW_EPOLL_IO_SENDMSG)
        state.requested_bytes = cw_epoll_msghdr_bytes(
            (const void *)PT_REGS_PARM2_CORE_SYSCALL(registers));
    else if (operation == CW_EPOLL_IO_RECVMMSG ||
             operation == CW_EPOLL_IO_SENDMMSG)
        state.requested_bytes =
            PT_REGS_PARM3_CORE_SYSCALL(registers);
    if ((operation == CW_EPOLL_IO_RECVFROM &&
         (PT_REGS_PARM4_CORE_SYSCALL(registers) & CW_MSG_PEEK)) ||
        (operation == CW_EPOLL_IO_RECVMSG &&
         (PT_REGS_PARM3_CORE_SYSCALL(registers) & CW_MSG_PEEK)) ||
        (operation == CW_EPOLL_IO_RECVMMSG &&
         (PT_REGS_PARM4_CORE_SYSCALL(registers) & CW_MSG_PEEK)))
        state.io_flags |= CW_EPOLL_DISPATCH_MSG_PEEK;
    if (candidate &&
        operation != CW_EPOLL_IO_DUP &&
        operation != CW_EPOLL_IO_DUP2 &&
        operation != CW_EPOLL_IO_DUP3 &&
        operation != CW_EPOLL_IO_FCNTL_DUP &&
        !candidate->item.first_io_ns) {
        candidate->item.first_io_ns = state.start_ns;
        candidate->item.first_operation = operation;
        candidate->item.flags |= CW_EPOLL_DISPATCH_CONSUMED;
        candidate->item.stack_id = bpf_get_stackid(
            stack_context, &epoll_stacks, BPF_F_USER_STACK);
    }
    bpf_map_update_elem(
        &epoll_io_states, &pid_tgid, &state, BPF_ANY);
}

static __attribute__((noinline)) void cw_epoll_finish_io(
    const struct cw_epoll_io_state *state, __s64 result)
{
    struct cw_epoll_dispatch_candidate *candidate =
        bpf_map_lookup_elem(
            &epoll_dispatch_candidates, &state->key);
    __u64 now = bpf_ktime_get_ns();
    bool read_operation;
    bool write_operation;

    if (state->operation == CW_EPOLL_IO_CLOSE && !result) {
        struct cw_epoll_counters *counters;
        __u32 zero = 0;

        cw_epoll_advance_fd_generation(
            state->pid, state->key.fd);
        counters = bpf_map_lookup_elem(&epoll_counters, &zero);
        if (counters)
            __sync_fetch_and_add(&counters->fd_closes, 1);
    } else if ((state->operation == CW_EPOLL_IO_DUP ||
                state->operation == CW_EPOLL_IO_DUP2 ||
                state->operation == CW_EPOLL_IO_DUP3 ||
                state->operation == CW_EPOLL_IO_FCNTL_DUP) &&
               result >= 0 &&
               !(state->operation == CW_EPOLL_IO_DUP2 &&
                 (__s32)result == state->key.fd)) {
        struct cw_epoll_counters *counters;
        __u32 zero = 0;

        cw_epoll_advance_fd_generation(
            state->pid, (__s32)result);
        counters = bpf_map_lookup_elem(&epoll_counters, &zero);
        if (counters)
            __sync_fetch_and_add(&counters->fd_duplications, 1);
    }
    if (state->operation == CW_EPOLL_IO_DUP ||
        state->operation == CW_EPOLL_IO_DUP2 ||
        state->operation == CW_EPOLL_IO_DUP3 ||
        state->operation == CW_EPOLL_IO_FCNTL_DUP)
        return;
    if (!candidate)
        return;
    read_operation = cw_epoll_is_read_operation(state->operation);
    write_operation = cw_epoll_is_write_operation(state->operation);
    candidate->item.last_io_ns = now;
    candidate->item.last_operation = state->operation;
    candidate->item.last_result = (__s32)result;
    candidate->item.io_calls++;
    candidate->item.requested_bytes += state->requested_bytes;
    candidate->item.flags |= state->io_flags;
    if (now > state->start_ns)
        candidate->item.total_io_ns += now - state->start_ns;
    if (read_operation)
        candidate->item.read_calls++;
    if (write_operation)
        candidate->item.write_calls++;
    if (result > 0 && cw_epoll_result_is_bytes(state->operation)) {
        if (read_operation)
            candidate->item.bytes_read += result;
        else
            candidate->item.bytes_written += result;
    }
    if (result == -CW_EAGAIN)
        candidate->item.flags |= CW_EPOLL_DISPATCH_EAGAIN;
    if (!result && read_operation &&
        state->operation != CW_EPOLL_IO_ACCEPT &&
        state->operation != CW_EPOLL_IO_ACCEPT4)
        candidate->item.flags |= CW_EPOLL_DISPATCH_EOF;
    if (result >= 0 && read_operation &&
        state->requested_bytes &&
        (__u64)result < state->requested_bytes &&
        !(state->io_flags & CW_EPOLL_DISPATCH_MSG_PEEK))
        candidate->item.flags |= CW_EPOLL_DISPATCH_SHORT_READ;
    if (state->operation == CW_EPOLL_IO_CLOSE && !result)
        candidate->item.flags |= CW_EPOLL_DISPATCH_CLOSED;
    if (result < 0 && result != -CW_EAGAIN &&
        result != -CW_EINTR &&
        !(state->operation == CW_EPOLL_IO_CONNECT &&
          result == -CW_EINPROGRESS))
        candidate->item.io_errors++;
}

static __always_inline bool cw_epoll_is_et_undrained(
    struct cw_epoll_dispatch_item *item)
{
    __u32 completed = CW_EPOLL_DISPATCH_EAGAIN |
                      CW_EPOLL_DISPATCH_SHORT_READ |
                      CW_EPOLL_DISPATCH_EOF |
                      CW_EPOLL_DISPATCH_CLOSED |
                      CW_EPOLL_DISPATCH_REARMED;
    __u32 terminal_events =
        CW_EPOLL_ERR | CW_EPOLL_HUP | CW_EPOLL_RDHUP;

    return (item->flags & CW_EPOLL_DISPATCH_ET_CANDIDATE) &&
           (item->flags & CW_EPOLL_DISPATCH_CONSUMED) &&
           item->read_calls &&
           !(item->flags & completed) &&
           !(item->ready_events & terminal_events);
}

static __always_inline bool cw_epoll_is_oneshot_missing_rearm(
    const struct cw_epoll_dispatch_item *item)
{
    __u32 completed = CW_EPOLL_DISPATCH_REARMED |
                      CW_EPOLL_DISPATCH_CLOSED;

    return (item->flags & CW_EPOLL_DISPATCH_ONESHOT_CANDIDATE) &&
           !(item->flags & completed);
}

static __attribute__((noinline)) void cw_epoll_finish_dispatch_item(
    __u64 pid_tgid, struct cw_epoll_dispatch_batch *active,
    __s32 fd, __u64 now)
{
    struct cw_epoll_dispatch_key dispatch_key = {
        .pid_tgid = pid_tgid,
        .fd = fd,
    };
    struct cw_epoll_dispatch_candidate *candidate =
        bpf_map_lookup_elem(
            &epoll_dispatch_candidates, &dispatch_key);
    struct cw_epoll_resource_key resource_key;
    struct cw_epoll_resource_stats *resource_stats;
    struct cw_epoll_loop_stats *loop_stats;
    struct cw_epoll_counters *counters;
    struct cw_epoll_dispatch_event *event;
    struct cw_epoll_loop_key loop_key;
    __u64 dispatch_ns;
    __u32 zero = 0;
    bool consumed;
    bool emit_detail;

    if (!candidate)
        return;
    cw_epoll_apply_dispatch_wake(
        &dispatch_key, &candidate->item);
    consumed =
        candidate->item.flags & CW_EPOLL_DISPATCH_CONSUMED;
    dispatch_ns = consumed &&
                  candidate->item.first_io_ns >
                      candidate->item.ready_ns ?
        candidate->item.first_io_ns -
            candidate->item.ready_ns :
        (now > candidate->item.ready_ns ?
            now - candidate->item.ready_ns : 0);
    if (cw_epoll_is_et_undrained(&candidate->item))
        candidate->item.flags |= CW_EPOLL_DISPATCH_ET_UNDRAINED;
    if (cw_epoll_is_oneshot_missing_rearm(&candidate->item))
        candidate->item.flags |=
            CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM;

    loop_key.global_pid = active->global_pid;
    loop_key.global_tid = active->global_tid;
    loop_key.epoll_fd = active->epoll_fd;
    loop_key.epoll_generation = active->epoll_generation;
    loop_stats = bpf_map_lookup_elem(&epoll_loop_stats, &loop_key);
    counters = bpf_map_lookup_elem(&epoll_counters, &zero);

    resource_key.pid = active->pid;
    resource_key.epoll_fd = active->epoll_fd;
    resource_key.epoll_generation = candidate->item.epoll_generation;
    resource_key.fd = candidate->item.fd;
    resource_key.fd_generation = candidate->item.fd_generation;
    resource_stats = bpf_map_lookup_elem(
        &epoll_resource_stats, &resource_key);
    if ((candidate->item.flags &
         CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM) &&
        resource_stats &&
        resource_stats->oneshot_rearms >
            candidate->oneshot_rearms_at_ready) {
        candidate->item.flags &=
            ~CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM;
        candidate->item.flags |= CW_EPOLL_DISPATCH_REARMED;
    }
    if (consumed) {
        if (counters)
            __sync_fetch_and_add(&counters->dispatches, 1);
        if (loop_stats) {
            __sync_fetch_and_add(&loop_stats->dispatches, 1);
            __sync_fetch_and_add(
                &loop_stats->total_dispatch_ns, dispatch_ns);
            update_peak(
                &loop_stats->maximum_dispatch_ns, dispatch_ns);
        }
        if (resource_stats) {
            __sync_fetch_and_add(&resource_stats->dispatches, 1);
            __sync_fetch_and_add(
                &resource_stats->total_dispatch_ns, dispatch_ns);
            update_peak(
                &resource_stats->maximum_dispatch_ns, dispatch_ns);
        }
    } else {
        if (counters)
            __sync_fetch_and_add(&counters->unconsumed, 1);
        if (loop_stats)
            __sync_fetch_and_add(&loop_stats->unconsumed, 1);
        if (resource_stats)
            __sync_fetch_and_add(&resource_stats->unconsumed, 1);
    }
    if (counters) {
        if (candidate->item.flags &
            CW_EPOLL_DISPATCH_CALLBACK_COMPLETED)
            __sync_fetch_and_add(
                &counters->evidence_exact, 1);
        else if (consumed)
            __sync_fetch_and_add(
                &counters->evidence_ready_to_io, 1);
        else
            __sync_fetch_and_add(
                &counters->evidence_ready_only, 1);
    }
    if (candidate->item.io_errors) {
        if (counters)
            __sync_fetch_and_add(
                &counters->io_errors,
                candidate->item.io_errors);
        if (loop_stats)
            __sync_fetch_and_add(
                &loop_stats->io_errors,
                candidate->item.io_errors);
    }
    if (candidate->item.flags &
        CW_EPOLL_DISPATCH_ET_UNDRAINED) {
        if (counters)
            __sync_fetch_and_add(
                &counters->potential_et_undrained, 1);
        if (loop_stats)
            __sync_fetch_and_add(
                &loop_stats->potential_et_undrained, 1);
        if (resource_stats)
            __sync_fetch_and_add(
                &resource_stats->potential_et_undrained, 1);
    }
    if (candidate->item.flags &
        CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM) {
        if (counters)
            __sync_fetch_and_add(
                &counters->potential_oneshot_missing_rearm, 1);
        if (loop_stats)
            __sync_fetch_and_add(
                &loop_stats->potential_oneshot_missing_rearm, 1);
        if (resource_stats)
            __sync_fetch_and_add(
                &resource_stats->potential_oneshot_missing_rearm, 1);
    }
    if (resource_stats) {
        if (candidate->item.stack_id >= 0)
            resource_stats->dispatch_stack_id =
                candidate->item.stack_id;
        __sync_fetch_and_add(
            &resource_stats->io_calls,
            candidate->item.io_calls);
        __sync_fetch_and_add(
            &resource_stats->bytes_read,
            candidate->item.bytes_read);
        __sync_fetch_and_add(
            &resource_stats->bytes_written,
            candidate->item.bytes_written);
        __sync_fetch_and_add(
            &resource_stats->io_errors,
            candidate->item.io_errors);
        if (candidate->item.flags & CW_EPOLL_DISPATCH_EAGAIN)
            __sync_fetch_and_add(&resource_stats->eagain, 1);
        if (candidate->item.flags & CW_EPOLL_DISPATCH_CLOSED)
            resource_stats->active = 0;
        if (candidate->item.flags &
            CW_EPOLL_DISPATCH_ONESHOT_CANDIDATE)
            __sync_fetch_and_add(&resource_stats->oneshot_events, 1);
    }

    emit_detail =
        dispatch_ns >= cw_epoll_cfg.min_dispatch_ns ||
        !consumed ||
        candidate->item.io_errors ||
        (candidate->item.flags &
         (CW_EPOLL_DISPATCH_ET_UNDRAINED |
          CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM));
    if (!emit_detail)
        goto done;
    event = bpf_ringbuf_reserve(
        &epoll_dispatch_events, sizeof(*event), 0);
    if (!event) {
        if (counters)
            __sync_fetch_and_add(
                &counters->dispatch_dropped, 1);
        goto done;
    }
    event->timestamp_ns = now;
    event->return_to_wait_ns =
        now > active->ready_ns ? now - active->ready_ns : 0;
    event->cycle_offcpu_ns = active->offcpu_ns;
    event->cycle_blocked_ns = active->blocked_ns;
    event->cycle_runqueue_ns = active->runqueue_ns;
    event->pid = active->pid;
    event->tid = active->tid;
    event->global_pid = active->global_pid;
    event->global_tid = active->global_tid;
    event->epoll_fd = active->epoll_fd;
    event->reserved = 0;
    __builtin_memcpy(
        event->comm, active->comm, sizeof(event->comm));
    __builtin_memcpy(
        &event->item, &candidate->item,
        sizeof(candidate->item));
    bpf_ringbuf_submit(event, 0);
    if (counters)
        __sync_fetch_and_add(
            &counters->dispatch_emitted, 1);

done:
    bpf_map_delete_elem(
        &epoll_dispatch_candidates, &dispatch_key);
}

static __attribute__((noinline)) void cw_epoll_finish_dispatch_batch(
    __u64 pid_tgid, __u64 now)
{
    struct cw_epoll_dispatch_batch *active =
        bpf_map_lookup_elem(&epoll_dispatch_batches, &pid_tgid);
    struct cw_epoll_loop_key loop_key;
    struct cw_epoll_loop_stats *loop_stats;
    __u64 cycle_ns;
    __u32 index;

    if (!active || !active->count)
        return;
    cycle_ns = now > active->ready_ns ?
        now - active->ready_ns : 0;
    loop_key.global_pid = active->global_pid;
    loop_key.global_tid = active->global_tid;
    loop_key.epoll_fd = active->epoll_fd;
    loop_key.epoll_generation = active->epoll_generation;
    loop_stats = bpf_map_lookup_elem(
        &epoll_loop_stats, &loop_key);
    if (loop_stats) {
        __sync_fetch_and_add(&loop_stats->cycles, 1);
        __sync_fetch_and_add(
            &loop_stats->total_cycle_ns, cycle_ns);
        update_peak(&loop_stats->maximum_cycle_ns, cycle_ns);
        __sync_fetch_and_add(
            &loop_stats->cycle_offcpu_ns, active->offcpu_ns);
        __sync_fetch_and_add(
            &loop_stats->cycle_blocked_ns, active->blocked_ns);
        __sync_fetch_and_add(
            &loop_stats->cycle_runqueue_ns, active->runqueue_ns);
    }
#pragma clang loop unroll(disable)
    for (index = 0; index < CW_EPOLL_MAX_READY; index++) {
        if (index >= active->count)
            break;
        cw_epoll_finish_dispatch_item(
            pid_tgid, active, active->fds[index], now);
    }
    bpf_map_delete_elem(&epoll_dispatch_batches, &pid_tgid);
}

SEC("raw_tp/sys_exit")
int trace_epoll_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_epoll_ctl_state *active_ctl;
    struct cw_epoll_wait_state *active_wait;
    struct cw_epoll_io_state *active_io;
    __s64 result = (__s64)ctx->args[1];

    if (!cw_epoll_capture_active())
        return 0;
    active_ctl = bpf_map_lookup_elem(&epoll_ctl_states, &pid_tgid);
    if (active_ctl) {
        struct cw_epoll_ctl_state saved_ctl;

        __builtin_memcpy(&saved_ctl, active_ctl, sizeof(saved_ctl));
        bpf_map_delete_elem(&epoll_ctl_states, &pid_tgid);
        if (!result)
            cw_epoll_apply_ctl(&saved_ctl, pid_tgid);
        return 0;
    }
    active_wait = bpf_map_lookup_elem(&epoll_wait_states, &pid_tgid);
    if (active_wait) {
        struct cw_epoll_wait_state saved_wait;

        __builtin_memcpy(&saved_wait, active_wait, sizeof(saved_wait));
        bpf_map_delete_elem(&epoll_wait_states, &pid_tgid);
        cw_epoll_finish_wait(&saved_wait, result);
        return 0;
    }
    active_io = bpf_map_lookup_elem(&epoll_io_states, &pid_tgid);
    if (active_io) {
        struct cw_epoll_io_state saved_io;

        __builtin_memcpy(&saved_io, active_io, sizeof(saved_io));
        bpf_map_delete_elem(&epoll_io_states, &pid_tgid);
        cw_epoll_finish_io(&saved_io, result);
    }
    return 0;
}

#endif
