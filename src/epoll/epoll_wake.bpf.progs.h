// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_EPOLL_WAKE_BPF_PROGS_H
#define CALLWEAVE_EPOLL_WAKE_BPF_PROGS_H

#define CW_TFD_TIMER_ABSTIME 1U

struct cw_userspace_timespec {
    __s64 seconds;
    __s64 nanoseconds;
};

struct cw_userspace_itimerspec {
    struct cw_userspace_timespec interval;
    struct cw_userspace_timespec value;
};

struct cw_epoll_process_identity {
    __u64 pid_tgid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 pid;
    __u32 tid;
};

static __attribute__((noinline)) void cw_epoll_finish_wake_wait(
    const struct cw_epoll_wait_state *state,
    __u64 pid_tgid, __s64 result);

static __always_inline __u64 cw_epoll_timespec_ns(
    const struct cw_userspace_timespec *value)
{
    if (value->seconds < 0 || value->nanoseconds < 0 ||
        value->nanoseconds >= 1000000000)
        return 0;
    return (__u64)value->seconds * 1000000000ULL +
           (__u64)value->nanoseconds;
}

static __always_inline void cw_epoll_fill_wake_source(
    void *stack_context, struct cw_epoll_wake_source *source,
    __u32 kind, __u32 action, __u32 pid, __u32 tid,
    __u32 global_pid, __u32 global_tid)
{
    __u64 now = bpf_ktime_get_ns();

    source->first_timestamp_ns = now;
    source->timestamp_ns = now;
    source->operations = 1;
    source->kind = kind;
    source->action = action;
    source->source_pid = pid;
    source->source_tid = tid;
    source->source_global_pid = global_pid;
    source->source_global_tid = global_tid;
    source->stack_id = bpf_get_stackid(
        stack_context, &epoll_stacks, BPF_F_USER_STACK);
    bpf_get_current_comm(source->comm, sizeof(source->comm));
}

static __always_inline void cw_epoll_merge_wake_source(
    const struct cw_epoll_fd_key *key,
    const struct cw_epoll_wake_source *source)
{
    struct cw_epoll_wake_source combined = *source;
    struct cw_epoll_wake_source *existing =
        bpf_map_lookup_elem(&epoll_wake_pending, key);

    if (existing && existing->kind == source->kind &&
        existing->action == source->action) {
        combined.first_timestamp_ns =
            existing->first_timestamp_ns;
        combined.operations += existing->operations;
        combined.value += existing->value;
    }
    bpf_map_update_elem(
        &epoll_wake_pending, key, &combined, BPF_ANY);
}

static __always_inline bool cw_epoll_is_wake_write_operation(
    __u32 operation)
{
    return operation == CW_EPOLL_IO_WRITE ||
           operation == CW_EPOLL_IO_WRITEV ||
           operation == CW_EPOLL_IO_SENDTO ||
           operation == CW_EPOLL_IO_SENDMSG ||
           operation == CW_EPOLL_IO_SENDMMSG;
}

static __always_inline void cw_epoll_merge_socketpair_source(
    const struct cw_epoll_socket_key *key,
    const struct cw_epoll_wake_source *source)
{
    struct cw_epoll_wake_source combined = *source;
    struct cw_epoll_wake_source *existing =
        bpf_map_lookup_elem(&epoll_socketpair_pending, key);

    if (existing && existing->kind == source->kind &&
        existing->action == source->action) {
        combined.first_timestamp_ns = existing->first_timestamp_ns;
        combined.operations += existing->operations;
    }
    bpf_map_update_elem(
        &epoll_socketpair_pending, key, &combined, BPF_ANY);
}

static __attribute__((noinline)) void cw_epoll_record_wake_syscall(
    void *stack_context, struct pt_regs *registers,
    __s32 syscall_nr,
    const struct cw_epoll_process_identity *identity)
{
    struct cw_epoll_wake_sys_state state = {
        .pid = identity->pid,
        .fd = -1,
        .target_fd = -1,
        .clock_id = -1,
    };
    __u32 io_operation = cw_epoll_io_operation(syscall_nr);

    if (syscall_nr == cw_epoll_cfg.eventfd_syscall_nr ||
        syscall_nr == cw_epoll_cfg.eventfd2_syscall_nr) {
        state.action = CW_EPOLL_WAKE_SYS_CREATE_EVENTFD;
    } else if (syscall_nr ==
               cw_epoll_cfg.timerfd_create_syscall_nr) {
        state.action = CW_EPOLL_WAKE_SYS_CREATE_TIMERFD;
        state.clock_id =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
    } else if (syscall_nr == cw_epoll_cfg.signalfd_syscall_nr ||
               syscall_nr == cw_epoll_cfg.signalfd4_syscall_nr) {
        const __u64 *mask =
            (const void *)PT_REGS_PARM2_CORE_SYSCALL(registers);
        __u64 mask_size =
            PT_REGS_PARM3_CORE_SYSCALL(registers);

        state.action = CW_EPOLL_WAKE_SYS_CREATE_SIGNALFD;
        state.fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
        if (mask && mask_size >= sizeof(state.signal_mask))
            bpf_probe_read_user(
                &state.signal_mask, sizeof(state.signal_mask), mask);
    } else if (syscall_nr == cw_epoll_cfg.socketpair_syscall_nr) {
        state.action = CW_EPOLL_WAKE_SYS_CREATE_SOCKETPAIR;
        state.user_address =
            PT_REGS_PARM4_CORE_SYSCALL(registers);
    } else if (syscall_nr ==
               cw_epoll_cfg.timerfd_settime_syscall_nr) {
        struct cw_userspace_itimerspec timer = {0};
        const struct cw_userspace_itimerspec *address =
            (const void *)PT_REGS_PARM3_CORE_SYSCALL(registers);
        struct cw_epoll_fd_key key;
        struct cw_epoll_fd_metadata *metadata;

        state.fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
        key.pid = identity->pid;
        key.fd = state.fd;
        metadata = bpf_map_lookup_elem(&epoll_fd_metadata, &key);
        if (!metadata || metadata->kind != CW_EPOLL_WAKE_TIMERFD)
            return;
        state.action = CW_EPOLL_WAKE_SYS_TIMERFD_SETTIME;
        cw_epoll_fill_wake_source(
            stack_context, &state.source,
            CW_EPOLL_WAKE_TIMERFD,
            CW_EPOLL_WAKE_ACTION_TIMERFD_ARM,
            identity->pid, identity->tid,
            identity->global_pid, identity->global_tid);
        if (PT_REGS_PARM2_CORE_SYSCALL(registers) &
            CW_TFD_TIMER_ABSTIME)
            state.source.flags |= CW_EPOLL_WAKE_TIMER_ABSTIME;
        if (address &&
            !bpf_probe_read_user(&timer, sizeof(timer), address)) {
            state.source.timer_initial_ns =
                cw_epoll_timespec_ns(&timer.value);
            state.source.timer_interval_ns =
                cw_epoll_timespec_ns(&timer.interval);
            if (!state.source.timer_initial_ns)
                state.source.flags |= CW_EPOLL_WAKE_TIMER_DISARMED;
        }
    } else if (cw_epoll_is_wake_write_operation(io_operation)) {
        const __u64 *value_address =
            (const void *)PT_REGS_PARM2_CORE_SYSCALL(registers);
        __u64 length =
            PT_REGS_PARM3_CORE_SYSCALL(registers);
        struct cw_epoll_fd_key key;
        struct cw_epoll_fd_metadata *metadata;

        state.fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
        key.pid = identity->pid;
        key.fd = state.fd;
        metadata = bpf_map_lookup_elem(&epoll_fd_metadata, &key);
        if (!metadata)
            return;
        if (metadata->kind == CW_EPOLL_WAKE_EVENTFD &&
            io_operation == CW_EPOLL_IO_WRITE &&
            length >= sizeof(state.source.value) && value_address) {
            state.action = CW_EPOLL_WAKE_SYS_EVENTFD_WRITE;
            cw_epoll_fill_wake_source(
                stack_context, &state.source,
                CW_EPOLL_WAKE_EVENTFD,
                CW_EPOLL_WAKE_ACTION_EVENTFD_WRITE,
                identity->pid, identity->tid,
                identity->global_pid, identity->global_tid);
            bpf_probe_read_user(
                &state.source.value, sizeof(state.source.value),
                value_address);
        } else if (metadata->kind == CW_EPOLL_WAKE_SOCKETPAIR &&
                   metadata->socket_pair_id) {
            state.action = CW_EPOLL_WAKE_SYS_SOCKET_WRITE;
            state.socket_pair_id = metadata->socket_pair_id;
            state.socket_endpoint = metadata->socket_endpoint ^ 1U;
            cw_epoll_fill_wake_source(
                stack_context, &state.source,
                CW_EPOLL_WAKE_SOCKETPAIR,
                CW_EPOLL_WAKE_ACTION_SOCKET_WRITE,
                identity->pid, identity->tid,
                identity->global_pid, identity->global_tid);
        } else {
            return;
        }
    } else if (io_operation == CW_EPOLL_IO_CLOSE) {
        state.action = CW_EPOLL_WAKE_SYS_CLOSE;
        state.fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
    } else if (io_operation == CW_EPOLL_IO_DUP ||
               io_operation == CW_EPOLL_IO_DUP2 ||
               io_operation == CW_EPOLL_IO_DUP3 ||
               io_operation == CW_EPOLL_IO_FCNTL_DUP) {
        if (io_operation == CW_EPOLL_IO_FCNTL_DUP) {
            __u64 command =
                PT_REGS_PARM2_CORE_SYSCALL(registers);

            if (command != CW_F_DUPFD &&
                command != CW_F_DUPFD_CLOEXEC)
                return;
        }
        state.action = CW_EPOLL_WAKE_SYS_DUP;
        state.fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers);
        if (io_operation == CW_EPOLL_IO_DUP2 ||
            io_operation == CW_EPOLL_IO_DUP3)
            state.target_fd =
                (__s32)PT_REGS_PARM2_CORE_SYSCALL(registers);
    } else {
        return;
    }
    bpf_map_update_elem(
        &epoll_wake_sys_states, &identity->pid_tgid,
        &state, BPF_ANY);
}

static __always_inline void cw_epoll_copy_wake_fd(
    __u32 pid, __s32 source_fd, __s32 target_fd)
{
    struct cw_epoll_fd_key source_key = {
        .pid = pid,
        .fd = source_fd,
    };
    struct cw_epoll_fd_key target_key = {
        .pid = pid,
        .fd = target_fd,
    };
    struct cw_epoll_fd_metadata *metadata =
        bpf_map_lookup_elem(&epoll_fd_metadata, &source_key);
    struct cw_epoll_wake_source *pending =
        bpf_map_lookup_elem(&epoll_wake_pending, &source_key);

    if (metadata)
        bpf_map_update_elem(
            &epoll_fd_metadata, &target_key, metadata, BPF_ANY);
    else
        bpf_map_delete_elem(&epoll_fd_metadata, &target_key);
    if (pending)
        bpf_map_update_elem(
            &epoll_wake_pending, &target_key, pending, BPF_ANY);
    else
        bpf_map_delete_elem(&epoll_wake_pending, &target_key);
}

static __attribute__((noinline)) void cw_epoll_finish_wake_syscall(
    const struct cw_epoll_wake_sys_state *state, __s64 result)
{
    struct cw_epoll_fd_key key = {
        .pid = state->pid,
        .fd = state->fd,
    };

    if (state->action == CW_EPOLL_WAKE_SYS_CREATE_SOCKETPAIR &&
        !result && state->user_address) {
        __s32 fds[2] = {-1, -1};

        if (!bpf_probe_read_user(
                fds, sizeof(fds),
                (const void *)state->user_address) &&
            fds[0] >= 0 && fds[1] >= 0) {
            __u64 pair_id = bpf_ktime_get_ns();
            struct cw_epoll_fd_key first_key = {
                .pid = state->pid,
                .fd = fds[0],
            };
            struct cw_epoll_fd_key second_key = {
                .pid = state->pid,
                .fd = fds[1],
            };
            struct cw_epoll_fd_metadata first = {
                .socket_pair_id = pair_id,
                .kind = CW_EPOLL_WAKE_SOCKETPAIR,
                .clock_id = -1,
                .socket_endpoint = 0,
            };
            struct cw_epoll_fd_metadata second = {
                .socket_pair_id = pair_id,
                .kind = CW_EPOLL_WAKE_SOCKETPAIR,
                .clock_id = -1,
                .socket_endpoint = 1,
            };

            bpf_map_update_elem(
                &epoll_fd_metadata, &first_key, &first, BPF_ANY);
            bpf_map_update_elem(
                &epoll_fd_metadata, &second_key, &second, BPF_ANY);
        }
    } else if (state->action == CW_EPOLL_WAKE_SYS_CREATE_EVENTFD &&
        result >= 0) {
        struct cw_epoll_fd_metadata metadata = {
            .kind = CW_EPOLL_WAKE_EVENTFD,
            .clock_id = -1,
        };

        key.fd = (__s32)result;
        bpf_map_update_elem(
            &epoll_fd_metadata, &key, &metadata, BPF_ANY);
    } else if (state->action ==
                   CW_EPOLL_WAKE_SYS_CREATE_TIMERFD &&
               result >= 0) {
        struct cw_epoll_fd_metadata metadata = {
            .kind = CW_EPOLL_WAKE_TIMERFD,
            .clock_id = state->clock_id,
        };

        key.fd = (__s32)result;
        bpf_map_update_elem(
            &epoll_fd_metadata, &key, &metadata, BPF_ANY);
    } else if (state->action ==
                   CW_EPOLL_WAKE_SYS_CREATE_SIGNALFD &&
               result >= 0) {
        struct cw_epoll_fd_metadata metadata = {
            .signal_mask = state->signal_mask,
            .kind = CW_EPOLL_WAKE_SIGNALFD,
            .clock_id = -1,
        };

        key.fd = (__s32)result;
        bpf_map_update_elem(
            &epoll_fd_metadata, &key, &metadata, BPF_ANY);
    } else if (state->action ==
                   CW_EPOLL_WAKE_SYS_TIMERFD_SETTIME &&
               !result) {
        struct cw_epoll_fd_metadata *metadata =
            bpf_map_lookup_elem(&epoll_fd_metadata, &key);

        if (metadata && metadata->kind == CW_EPOLL_WAKE_TIMERFD)
            metadata->timer_source = state->source;
    } else if (state->action ==
                   CW_EPOLL_WAKE_SYS_EVENTFD_WRITE &&
               result == sizeof(__u64)) {
        cw_epoll_merge_wake_source(&key, &state->source);
    } else if (state->action == CW_EPOLL_WAKE_SYS_SOCKET_WRITE &&
               result > 0) {
        struct cw_epoll_socket_key socket_key = {
            .pair_id = state->socket_pair_id,
            .pid = state->pid,
            .endpoint = state->socket_endpoint,
        };

        cw_epoll_merge_socketpair_source(
            &socket_key, &state->source);
    } else if (state->action == CW_EPOLL_WAKE_SYS_CLOSE &&
               !result) {
        bpf_map_delete_elem(&epoll_fd_metadata, &key);
        bpf_map_delete_elem(&epoll_wake_pending, &key);
    } else if (state->action == CW_EPOLL_WAKE_SYS_DUP &&
               result >= 0 &&
               (__s32)result != state->fd) {
        cw_epoll_copy_wake_fd(
            state->pid, state->fd, (__s32)result);
    }
}

static __always_inline void cw_epoll_record_wake_wait(
    struct pt_regs *registers,
    const struct cw_epoll_process_identity *identity)
{
    struct cw_epoll_wait_state state = {
        .events_address =
            PT_REGS_PARM2_CORE_SYSCALL(registers),
        .pid = identity->pid,
        .tid = identity->tid,
        .global_pid = identity->global_pid,
        .global_tid = identity->global_tid,
        .epoll_fd =
            (__s32)PT_REGS_PARM1_CORE_SYSCALL(registers),
        .max_events =
            (__u32)PT_REGS_PARM3_CORE_SYSCALL(registers),
    };

    state.epoll_generation =
        cw_epoll_fd_generation(state.pid, state.epoll_fd);
    bpf_map_update_elem(
        &epoll_wake_wait_states, &identity->pid_tgid,
        &state, BPF_ANY);
}

SEC("raw_tp/sys_enter")
int trace_epoll_wake_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *registers = (struct pt_regs *)ctx->args[0];
    __s32 syscall_nr = (__s32)ctx->args[1];
    __u64 pid_tgid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 pid;
    __u32 tid;
    __u32 io_operation;
    __u32 wait_kind = 0;
    __u32 zero = 0;
    __s32 pidns_error;
    struct cw_epoll_process_identity identity;
    bool wait_syscall;

    if (!cw_epoll_capture_active())
        return 0;
    io_operation = cw_epoll_io_operation(syscall_nr);
    wait_syscall =
        cw_is_epoll_wait_syscall(syscall_nr, &wait_kind);
    if (syscall_nr != cw_epoll_cfg.eventfd_syscall_nr &&
        syscall_nr != cw_epoll_cfg.eventfd2_syscall_nr &&
        syscall_nr != cw_epoll_cfg.timerfd_create_syscall_nr &&
        syscall_nr != cw_epoll_cfg.timerfd_settime_syscall_nr &&
        syscall_nr != cw_epoll_cfg.signalfd_syscall_nr &&
        syscall_nr != cw_epoll_cfg.signalfd4_syscall_nr &&
        syscall_nr != cw_epoll_cfg.socketpair_syscall_nr &&
        !cw_epoll_is_wake_write_operation(io_operation) &&
        io_operation != CW_EPOLL_IO_CLOSE &&
        io_operation != CW_EPOLL_IO_DUP &&
        io_operation != CW_EPOLL_IO_DUP2 &&
        io_operation != CW_EPOLL_IO_DUP3 &&
        io_operation != CW_EPOLL_IO_FCNTL_DUP &&
        !wait_syscall)
        return 0;
    if (!get_process_info(
            &pid_tgid, &global_pid, &global_tid,
            &pid, &tid, &pidns_error))
        return 0;
    bpf_map_update_elem(
        &epoll_target_global, &zero, &global_pid, BPF_ANY);
    identity.pid_tgid = pid_tgid;
    identity.global_pid = global_pid;
    identity.global_tid = global_tid;
    identity.pid = pid;
    identity.tid = tid;
    if (wait_syscall) {
        cw_epoll_record_wake_wait(registers, &identity);
        return 0;
    }
    cw_epoll_record_wake_syscall(
        ctx, registers, syscall_nr, &identity);
    return 0;
}

SEC("raw_tp/sys_exit")
int trace_epoll_wake_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_epoll_wait_state *wait =
        bpf_map_lookup_elem(&epoll_wake_wait_states, &pid_tgid);
    struct cw_epoll_wake_sys_state *state =
        bpf_map_lookup_elem(&epoll_wake_sys_states, &pid_tgid);

    if (!cw_epoll_capture_active())
        return 0;
    if (wait) {
        cw_epoll_finish_wake_wait(
            wait, pid_tgid, (__s64)ctx->args[1]);
        bpf_map_delete_elem(&epoll_wake_wait_states, &pid_tgid);
    }
    if (state) {
        cw_epoll_finish_wake_syscall(
            state, (__s64)ctx->args[1]);
        bpf_map_delete_elem(&epoll_wake_sys_states, &pid_tgid);
    }
    return 0;
}

SEC("raw_tp/signal_generate")
int trace_epoll_signal_generate(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 signal_number = (__u32)ctx->args[0];
    struct task_struct *target =
        (struct task_struct *)ctx->args[2];
    struct bpf_pidns_info sender_pidns = {0};
    __u32 target_global_pid;
    __u32 sender_global_pid;
    __u32 sender_global_tid;
    __u32 *configured_target;
    __u32 zero = 0;
    __u64 sender_pid_tgid;
    struct cw_epoll_wake_source source = {
        .kind = CW_EPOLL_WAKE_SIGNALFD,
        .action = CW_EPOLL_WAKE_ACTION_SIGNAL_SEND,
        .operations = 1,
        .signal_number = signal_number,
        .stack_id = -1,
    };
    struct cw_epoll_wake_source combined;
    struct cw_epoll_wake_source *existing;

    if (!cw_epoll_capture_active() || !target ||
        !signal_number || signal_number > 64)
        return 0;
    configured_target =
        bpf_map_lookup_elem(&epoll_target_global, &zero);
    if (!configured_target || !*configured_target)
        return 0;
    target_global_pid = BPF_CORE_READ(target, tgid);
    if (target_global_pid != *configured_target)
        return 0;
    sender_pid_tgid = bpf_get_current_pid_tgid();
    sender_global_pid = sender_pid_tgid >> 32;
    sender_global_tid = (__u32)sender_pid_tgid;
    source.first_timestamp_ns = bpf_ktime_get_ns();
    source.timestamp_ns = source.first_timestamp_ns;
    source.value = signal_number;
    source.source_pid = sender_global_pid;
    source.source_tid = sender_global_tid;
    source.source_global_pid = sender_global_pid;
    source.source_global_tid = sender_global_tid;
    if (!bpf_get_ns_current_pid_tgid(
            cw_target_cfg.pidns_dev, cw_target_cfg.pidns_ino,
            &sender_pidns, sizeof(sender_pidns))) {
        source.source_pid = sender_pidns.tgid;
        source.source_tid = sender_pidns.pid;
    }
    source.stack_id = bpf_get_stackid(
        ctx, &epoll_stacks, BPF_F_USER_STACK);
    bpf_get_current_comm(source.comm, sizeof(source.comm));
    combined = source;
    existing = bpf_map_lookup_elem(
        &epoll_signal_pending, &target_global_pid);
    if (existing &&
        existing->signal_number == source.signal_number) {
        combined.first_timestamp_ns =
            existing->first_timestamp_ns;
        combined.operations += existing->operations;
    }
    bpf_map_update_elem(
        &epoll_signal_pending, &target_global_pid,
        &combined, BPF_ANY);
    return 0;
}

static __always_inline void cw_epoll_wake_latency(
    struct cw_epoll_wake_source *source, __u64 ready_ns)
{
    if (source->action == CW_EPOLL_WAKE_ACTION_TIMERFD_ARM) {
        __u64 elapsed;
        __u64 scheduled;

        if ((source->flags & CW_EPOLL_WAKE_TIMER_ABSTIME) ||
            !source->timer_initial_ns ||
            ready_ns <= source->timestamp_ns)
            return;
        elapsed = ready_ns - source->timestamp_ns;
        if (elapsed < source->timer_initial_ns)
            return;
        scheduled = source->timer_initial_ns;
        if (source->timer_interval_ns &&
            elapsed > source->timer_initial_ns)
            scheduled +=
                ((elapsed - source->timer_initial_ns) /
                 source->timer_interval_ns) *
                source->timer_interval_ns;
        source->latency_ns = elapsed - scheduled;
        source->flags |= CW_EPOLL_WAKE_LATENCY_VALID;
        return;
    }
    if (source->first_timestamp_ns &&
        ready_ns >= source->first_timestamp_ns) {
        source->latency_ns =
            ready_ns - source->first_timestamp_ns;
        source->flags |= CW_EPOLL_WAKE_LATENCY_VALID;
    }
}

static __attribute__((noinline)) void cw_epoll_correlate_wake_source(
    const struct cw_epoll_wait_state *state, __s32 fd,
    __u64 ready_ns, struct cw_epoll_resource_stats *resource_stats,
    struct cw_epoll_wake_source *result)
{
    struct cw_epoll_fd_key key = {
        .pid = state->pid,
        .fd = fd,
    };
    struct cw_epoll_fd_metadata *metadata =
        bpf_map_lookup_elem(&epoll_fd_metadata, &key);
    struct cw_epoll_wake_source source = {
        .stack_id = -1,
    };
    struct cw_epoll_wake_source *pending;
    struct cw_epoll_counters *counters;
    __u32 zero = 0;

    if (!metadata)
        return;
    source.kind = metadata->kind;
    if (metadata->kind == CW_EPOLL_WAKE_EVENTFD) {
        pending = bpf_map_lookup_elem(&epoll_wake_pending, &key);
        if (pending)
            source = *pending;
        bpf_map_delete_elem(&epoll_wake_pending, &key);
    } else if (metadata->kind == CW_EPOLL_WAKE_TIMERFD) {
        if (metadata->timer_source.action)
            source = metadata->timer_source;
    } else if (metadata->kind == CW_EPOLL_WAKE_SIGNALFD) {
        pending = bpf_map_lookup_elem(
            &epoll_signal_pending, &state->global_pid);
        if (pending && pending->signal_number > 0 &&
            pending->signal_number <= 64 &&
            (metadata->signal_mask &
             (1ULL << (pending->signal_number - 1)))) {
            source = *pending;
            bpf_map_delete_elem(
                &epoll_signal_pending, &state->global_pid);
        }
    } else if (metadata->kind == CW_EPOLL_WAKE_SOCKETPAIR &&
               metadata->socket_pair_id) {
        struct cw_epoll_socket_key socket_key = {
            .pair_id = metadata->socket_pair_id,
            .pid = state->pid,
            .endpoint = metadata->socket_endpoint,
        };

        pending = bpf_map_lookup_elem(
            &epoll_socketpair_pending, &socket_key);
        if (pending)
            source = *pending;
        bpf_map_delete_elem(
            &epoll_socketpair_pending, &socket_key);
    }
    cw_epoll_wake_latency(&source, ready_ns);
    *result = source;
    counters = bpf_map_lookup_elem(&epoll_counters, &zero);
    if (counters) {
        __sync_fetch_and_add(&counters->wake_ready, 1);
        if (source.action)
            __sync_fetch_and_add(
                &counters->wake_attributed, 1);
        if (source.kind == CW_EPOLL_WAKE_EVENTFD)
            __sync_fetch_and_add(
                &counters->eventfd_ready, 1);
        else if (source.kind == CW_EPOLL_WAKE_TIMERFD)
            __sync_fetch_and_add(
                &counters->timerfd_ready, 1);
        else if (source.kind == CW_EPOLL_WAKE_SIGNALFD)
            __sync_fetch_and_add(
                &counters->signalfd_ready, 1);
        else if (source.kind == CW_EPOLL_WAKE_SOCKETPAIR)
            __sync_fetch_and_add(
                &counters->socketpair_ready, 1);
    }
    if (!resource_stats)
        return;
    __sync_fetch_and_add(&resource_stats->wake_ready, 1);
    resource_stats->last_wake = source;
    if (!source.action)
        return;
    __sync_fetch_and_add(
        &resource_stats->wake_attributed, 1);
    if (source.action == CW_EPOLL_WAKE_ACTION_TIMERFD_ARM) {
        if (resource_stats->wake_last_source_timestamp_ns !=
            source.timestamp_ns) {
            resource_stats->wake_last_source_timestamp_ns =
                source.timestamp_ns;
            __sync_fetch_and_add(
                &resource_stats->wake_operations,
                source.operations);
        }
    } else {
        __sync_fetch_and_add(
            &resource_stats->wake_operations,
            source.operations);
    }
    if (source.flags & CW_EPOLL_WAKE_LATENCY_VALID) {
        __sync_fetch_and_add(
            &resource_stats->wake_latency_samples, 1);
        __sync_fetch_and_add(
            &resource_stats->wake_total_latency_ns,
            source.latency_ns);
        update_peak(
            &resource_stats->wake_maximum_latency_ns,
            source.latency_ns);
    }
}

static __attribute__((noinline)) void cw_epoll_process_one_wake_ready(
    const struct cw_epoll_wait_state *state,
    __u64 pid_tgid, __u32 index, __u64 ready_ns)
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

    if (index >= CW_EPOLL_MAX_READY ||
        bpf_probe_read_user(
            &copied, sizeof(copied), &events[index]))
        return;
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
            bpf_map_lookup_elem(
                &epoll_resource_stats, &resource_key);
        struct cw_epoll_dispatch_key dispatch_key = {
            .pid_tgid = pid_tgid,
            .fd = token->fd,
        };
        struct cw_epoll_wake_source source = {
            .stack_id = -1,
        };

        cw_epoll_correlate_wake_source(
            state, token->fd, ready_ns,
            resource_stats, &source);
        if (source.kind)
            bpf_map_update_elem(
                &epoll_dispatch_wakes, &dispatch_key,
                &source, BPF_ANY);
    }
}

static __attribute__((noinline)) void cw_epoll_finish_wake_wait(
    const struct cw_epoll_wait_state *state,
    __u64 pid_tgid, __s64 result)
{
    __u64 ready_ns;
    __u32 ready_count;
    __u32 index;

    if (result <= 0)
        return;
    ready_ns = bpf_ktime_get_ns();
    ready_count = (__u32)result;
    if (ready_count > CW_EPOLL_MAX_READY)
        ready_count = CW_EPOLL_MAX_READY;
#pragma clang loop unroll(disable)
    for (index = 0; index < CW_EPOLL_MAX_READY; index++) {
        if (index >= ready_count)
            break;
        cw_epoll_process_one_wake_ready(
            state, pid_tgid, index, ready_ns);
    }
}

static __attribute__((noinline)) void cw_epoll_apply_dispatch_wake(
    const struct cw_epoll_dispatch_key *key,
    struct cw_epoll_dispatch_item *item)
{
    struct cw_epoll_wake_source *wake =
        bpf_map_lookup_elem(&epoll_dispatch_wakes, key);

    if (!wake)
        return;
    item->wake = *wake;
    bpf_map_delete_elem(&epoll_dispatch_wakes, key);
}

#endif
