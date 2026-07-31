// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_LIBUV_BPF_PROGS_H
#define CALLWEAVE_LIBUV_BPF_PROGS_H

static __always_inline bool cw_libuv_enabled(void)
{
    return cw_epoll_cfg.callback_enabled &&
           cw_epoll_cfg.callback_match ==
               CW_EPOLL_CALLBACK_MATCH_LIBUV &&
           cw_epoll_capture_active();
}

static __always_inline struct cw_libuv_counters *
cw_libuv_get_counters(void)
{
    __u32 zero = 0;

    return bpf_map_lookup_elem(&libuv_counters, &zero);
}

static __always_inline bool cw_libuv_process(
    __u64 *pid_tgid, struct cw_libuv_handle_key *key,
    __u32 *tid, __u32 *global_pid, __u32 *global_tid)
{
    __s32 pidns_error;

    return get_process_info(
        pid_tgid, global_pid, global_tid,
        &key->pid, tid, &pidns_error);
}

static __always_inline int cw_libuv_poll_init_enter(
    struct pt_regs *ctx)
{
    struct cw_libuv_init_state state = {0};
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __u64 pid_tgid;

    if (!cw_libuv_enabled() ||
        !cw_libuv_process(
            &pid_tgid, &state.key, &tid,
            &global_pid, &global_tid))
        return 0;
    state.key.handle = PT_REGS_PARM2(ctx);
    state.fd = (__s32)PT_REGS_PARM3(ctx);
    if (!state.key.handle || state.fd < 0)
        return 0;
    bpf_map_update_elem(
        &libuv_init_states, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uprobe")
int trace_libuv_poll_init_entry(struct pt_regs *ctx)
{
    return cw_libuv_poll_init_enter(ctx);
}

SEC("uprobe")
int trace_libuv_poll_init_socket_entry(struct pt_regs *ctx)
{
    return cw_libuv_poll_init_enter(ctx);
}

static __always_inline int cw_libuv_poll_init_exit(
    struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libuv_init_state *state;
    struct cw_libuv_poll_handle value = {0};
    struct cw_libuv_poll_handle *previous;
    struct cw_libuv_counters *counters;

    if (!cw_libuv_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libuv_init_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0) {
        previous = bpf_map_lookup_elem(
            &libuv_poll_handles, &state->key);
        if (previous)
            value.generation = previous->generation + 1;
        value.fd = state->fd;
        bpf_map_update_elem(
            &libuv_poll_handles, &state->key,
            &value, BPF_ANY);
        counters = cw_libuv_get_counters();
        if (counters)
            __sync_fetch_and_add(
                &counters->initialized, 1);
    }
    bpf_map_delete_elem(&libuv_init_states, &pid_tgid);
    return 0;
}

SEC("uretprobe")
int trace_libuv_poll_init_return(struct pt_regs *ctx)
{
    return cw_libuv_poll_init_exit(ctx);
}

SEC("uretprobe")
int trace_libuv_poll_init_socket_return(struct pt_regs *ctx)
{
    return cw_libuv_poll_init_exit(ctx);
}

SEC("uprobe")
int trace_libuv_poll_start_entry(struct pt_regs *ctx)
{
    struct cw_libuv_start_state state = {0};
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __u64 pid_tgid;

    if (!cw_libuv_enabled() ||
        !cw_libuv_process(
            &pid_tgid, &state.key, &tid,
            &global_pid, &global_tid))
        return 0;
    state.key.handle = PT_REGS_PARM1(ctx);
    state.events = (__u32)PT_REGS_PARM2(ctx);
    state.callback = PT_REGS_PARM3(ctx);
    if (!state.key.handle || !state.callback)
        return 0;
    bpf_map_update_elem(
        &libuv_start_states, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libuv_poll_start_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libuv_start_state *state;
    struct cw_libuv_poll_handle *handle;
    struct cw_libuv_registration_event *event;
    struct cw_libuv_counters *counters;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 pidns_error;

    if (!cw_libuv_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libuv_start_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) != 0)
        goto done;
    handle = bpf_map_lookup_elem(
        &libuv_poll_handles, &state->key);
    if (!handle)
        goto done;
    handle->callback = state->callback;
    handle->events = state->events;
    handle->active = 1;
    counters = cw_libuv_get_counters();
    if (counters)
        __sync_fetch_and_add(&counters->started, 1);
    event = bpf_ringbuf_reserve(
        &libuv_registration_events, sizeof(*event), 0);
    if (!event) {
        if (counters)
            __sync_fetch_and_add(
                &counters->registrations_dropped, 1);
        goto done;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->handle = state->key.handle;
    event->callback = state->callback;
    event->pid = state->key.pid;
    event->events = state->events;
    event->fd = handle->fd;
    event->generation = handle->generation;
    if (get_process_info(
            &pid_tgid, &global_pid, &global_tid,
            &event->pid, &tid, &pidns_error)) {
        event->tid = tid;
        event->global_pid = global_pid;
        event->global_tid = global_tid;
    }
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    if (counters)
        __sync_fetch_and_add(
            &counters->registrations_emitted, 1);
done:
    bpf_map_delete_elem(&libuv_start_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libuv_poll_stop_entry(struct pt_regs *ctx)
{
    struct cw_libuv_stop_state state = {0};
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __u64 pid_tgid;

    if (!cw_libuv_enabled() ||
        !cw_libuv_process(
            &pid_tgid, &state.key, &tid,
            &global_pid, &global_tid))
        return 0;
    state.key.handle = PT_REGS_PARM1(ctx);
    if (!state.key.handle)
        return 0;
    bpf_map_update_elem(
        &libuv_stop_states, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libuv_poll_stop_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libuv_stop_state *state;
    struct cw_libuv_poll_handle *handle;
    struct cw_libuv_counters *counters;

    if (!cw_libuv_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libuv_stop_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0) {
        handle = bpf_map_lookup_elem(
            &libuv_poll_handles, &state->key);
        if (handle)
            handle->active = 0;
        counters = cw_libuv_get_counters();
        if (counters)
            __sync_fetch_and_add(&counters->stopped, 1);
    }
    bpf_map_delete_elem(&libuv_stop_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libuv_close_entry(struct pt_regs *ctx)
{
    struct cw_libuv_handle_key key = {0};
    struct cw_libuv_counters *counters;
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __u64 pid_tgid;

    if (!cw_libuv_enabled() ||
        !cw_libuv_process(
            &pid_tgid, &key, &tid,
            &global_pid, &global_tid))
        return 0;
    key.handle = PT_REGS_PARM1(ctx);
    if (!key.handle ||
        bpf_map_delete_elem(&libuv_poll_handles, &key))
        return 0;
    counters = cw_libuv_get_counters();
    if (counters)
        __sync_fetch_and_add(&counters->closed, 1);
    return 0;
}

#endif
