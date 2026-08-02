// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_LIBEVENT_BPF_PROGS_H
#define CALLWEAVE_LIBEVENT_BPF_PROGS_H

static __always_inline bool cw_libevent_enabled(void)
{
    return cw_epoll_cfg.callback_enabled &&
           cw_epoll_cfg.callback_match ==
               CW_EPOLL_CALLBACK_MATCH_LIBEVENT &&
           cw_epoll_capture_active();
}

static __always_inline struct cw_libevent_counters *
cw_libevent_get_counters(void)
{
    __u32 zero = 0;

    return bpf_map_lookup_elem(&libevent_counters, &zero);
}

static __always_inline bool cw_libevent_process(
    __u64 *pid_tgid, struct cw_libevent_key *key)
{
    __u32 tid;
    __u32 global_pid;
    __u32 global_tid;
    __s32 pidns_error;

    return get_process_info(
        pid_tgid, &global_pid, &global_tid,
        &key->pid, &tid, &pidns_error);
}

static __always_inline __u32 cw_libevent_kind(__s32 fd, __u32 events)
{
    if (events & CW_LIBEVENT_EV_SIGNAL)
        return CW_LIBEVENT_KIND_SIGNAL;
    if (events & (CW_LIBEVENT_EV_READ | CW_LIBEVENT_EV_WRITE))
        return fd >= 0 ? CW_LIBEVENT_KIND_IO :
                         CW_LIBEVENT_KIND_UNKNOWN;
    if ((events & CW_LIBEVENT_EV_TIMEOUT) ||
        (fd < 0 && !(events &
            (CW_LIBEVENT_EV_READ | CW_LIBEVENT_EV_WRITE))))
        return CW_LIBEVENT_KIND_TIMER;
    return CW_LIBEVENT_KIND_UNKNOWN;
}

static __always_inline void cw_libevent_count_kind(
    struct cw_libevent_counters *counters, __u32 kind,
    __u32 events)
{
    if (!counters)
        return;
    if (kind == CW_LIBEVENT_KIND_IO)
        __sync_fetch_and_add(&counters->io_events, 1);
    else if (kind == CW_LIBEVENT_KIND_TIMER)
        __sync_fetch_and_add(&counters->timer_events, 1);
    else if (kind == CW_LIBEVENT_KIND_SIGNAL)
        __sync_fetch_and_add(&counters->signal_events, 1);
    else
        __sync_fetch_and_add(
            &counters->unsupported_events, 1);
    if (events & CW_LIBEVENT_EV_PERSIST)
        __sync_fetch_and_add(
            &counters->persistent_events, 1);
    else
        __sync_fetch_and_add(
            &counters->oneshot_events, 1);
}

static __always_inline void cw_libevent_emit(
    const struct cw_libevent_key *key,
    const struct cw_libevent_registration *registration,
    __u32 action, __u32 object_kind,
    __u32 callback_role)
{
    struct cw_libevent_registration_event *event;
    struct cw_libevent_counters *counters =
        cw_libevent_get_counters();
    __u64 pid_tgid;
    __u32 global_pid;
    __u32 global_tid;
    __u32 pid;
    __u32 tid;
    __s32 pidns_error;

    event = bpf_ringbuf_reserve(
        &libevent_registration_events, sizeof(*event), 0);
    if (!event) {
        if (counters)
            __sync_fetch_and_add(
                &counters->registrations_dropped, 1);
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event = key->event;
    event->callback = registration->callback;
    event->callback_arg = registration->callback_arg;
    event->pid = key->pid;
    event->fd = registration->fd;
    event->events = registration->events;
    event->generation = registration->generation;
    event->action = action;
    event->kind = registration->kind;
    event->object_kind = object_kind;
    event->callback_role = callback_role;
    if (get_process_info(
            &pid_tgid, &global_pid, &global_tid,
            &pid, &tid, &pidns_error)) {
        event->pid = pid;
        event->tid = tid;
        event->global_pid = global_pid;
        event->global_tid = global_tid;
    }
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    if (counters)
        __sync_fetch_and_add(
            &counters->registrations_emitted, 1);
}

static __always_inline void cw_libevent_store_definition(
    struct cw_libevent_definition_state *state, __u64 event_address,
    bool created)
{
    struct cw_libevent_registration registration = {0};
    struct cw_libevent_counters *counters =
        cw_libevent_get_counters();
    __u32 *previous_generation;
    __u32 generation = 1;

    state->key.event = event_address;
    previous_generation = bpf_map_lookup_elem(
        &libevent_generations, &state->key);
    if (previous_generation)
        generation = *previous_generation + 1;
    bpf_map_update_elem(
        &libevent_generations, &state->key,
        &generation, BPF_ANY);
    registration.callback = state->callback;
    registration.callback_arg = state->callback_arg;
    registration.fd = state->fd;
    registration.events = state->events;
    registration.generation = generation;
    registration.kind = cw_libevent_kind(
        state->fd, state->events);
    bpf_map_update_elem(
        &libevent_registrations, &state->key,
        &registration, BPF_ANY);
    if (counters) {
        if (created)
            __sync_fetch_and_add(&counters->created, 1);
        else
            __sync_fetch_and_add(&counters->assigned, 1);
    }
    cw_libevent_count_kind(
        counters, registration.kind, registration.events);
    cw_libevent_emit(
        &state->key, &registration, CW_LIBEVENT_DEFINED,
        CW_LIBEVENT_OBJECT_EVENT, CW_LIBEVENT_CALLBACK_EVENT);
}

SEC("uprobe")
int trace_libevent_new_entry(struct pt_regs *ctx)
{
    struct cw_libevent_definition_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.fd = (__s32)PT_REGS_PARM2(ctx);
    state.events = (__u32)PT_REGS_PARM3(ctx);
    state.callback = PT_REGS_PARM4(ctx);
    state.callback_arg = PT_REGS_PARM5(ctx);
    if (!state.callback)
        return 0;
    bpf_map_update_elem(
        &libevent_new_states, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libevent_new_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_definition_state *state;
    __u64 event_address;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(&libevent_new_states, &pid_tgid);
    if (!state)
        return 0;
    event_address = (__u64)PT_REGS_RC(ctx);
    if (event_address)
        cw_libevent_store_definition(state, event_address, true);
    bpf_map_delete_elem(&libevent_new_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_assign_entry(struct pt_regs *ctx)
{
    struct cw_libevent_definition_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.key.event = PT_REGS_PARM1(ctx);
    state.fd = (__s32)PT_REGS_PARM3(ctx);
    state.events = (__u32)PT_REGS_PARM4(ctx);
    state.callback = PT_REGS_PARM5(ctx);
    state.callback_arg = PT_REGS_PARM6(ctx);
    if (!state.key.event || !state.callback)
        return 0;
    bpf_map_update_elem(
        &libevent_assign_states, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libevent_assign_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_definition_state *state;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libevent_assign_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0)
        cw_libevent_store_definition(
            state, state->key.event, false);
    bpf_map_delete_elem(&libevent_assign_states, &pid_tgid);
    return 0;
}

static __always_inline int cw_libevent_operation_enter(
    struct pt_regs *ctx, void *map)
{
    struct cw_libevent_operation_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.key.event = PT_REGS_PARM1(ctx);
    if (state.key.event)
        bpf_map_update_elem(map, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uprobe")
int trace_libevent_add_entry(struct pt_regs *ctx)
{
    return cw_libevent_operation_enter(ctx, &libevent_add_states);
}

SEC("uretprobe")
int trace_libevent_add_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_operation_state *state;
    struct cw_libevent_registration *registration;
    struct cw_libevent_counters *counters;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(&libevent_add_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) != 0)
        goto done;
    registration = bpf_map_lookup_elem(
        &libevent_registrations, &state->key);
    counters = cw_libevent_get_counters();
    if (!registration) {
        if (counters)
            __sync_fetch_and_add(
                &counters->definitions_missing, 1);
        goto done;
    }
    registration->active = 1;
    if (counters)
        __sync_fetch_and_add(&counters->added, 1);
    cw_libevent_emit(
        &state->key, registration, CW_LIBEVENT_ACTIVATED,
        CW_LIBEVENT_OBJECT_EVENT, CW_LIBEVENT_CALLBACK_EVENT);
done:
    bpf_map_delete_elem(&libevent_add_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_del_entry(struct pt_regs *ctx)
{
    return cw_libevent_operation_enter(ctx, &libevent_del_states);
}

SEC("uretprobe")
int trace_libevent_del_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_operation_state *state;
    struct cw_libevent_registration *registration;
    struct cw_libevent_counters *counters;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(&libevent_del_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0) {
        registration = bpf_map_lookup_elem(
            &libevent_registrations, &state->key);
        if (registration)
            registration->active = 0;
        counters = cw_libevent_get_counters();
        if (counters)
            __sync_fetch_and_add(&counters->deleted, 1);
    }
    bpf_map_delete_elem(&libevent_del_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_free_entry(struct pt_regs *ctx)
{
    struct cw_libevent_key key = {0};
    struct cw_libevent_counters *counters;
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &key))
        return 0;
    key.event = PT_REGS_PARM1(ctx);
    if (!key.event ||
        bpf_map_delete_elem(&libevent_registrations, &key))
        return 0;
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(&counters->freed, 1);
    return 0;
}

static __always_inline __u32 cw_libevent_next_generation(
    const struct cw_libevent_key *key)
{
    __u32 *previous = bpf_map_lookup_elem(
        &libevent_generations, key);
    __u32 generation = previous ? *previous + 1 : 1;

    bpf_map_update_elem(
        &libevent_generations, key, &generation, BPF_ANY);
    return generation;
}

static __always_inline void cw_libevent_emit_high_level(
    const struct cw_libevent_key *key, __u64 callback,
    __s32 fd, __u32 generation, __u32 action,
    __u32 object_kind, __u32 callback_role)
{
    struct cw_libevent_registration registration = {
        .callback = callback,
        .fd = fd,
        .generation = generation,
        .active = action == CW_LIBEVENT_ACTIVATED,
        .kind = fd >= 0 ? CW_LIBEVENT_KIND_IO :
                          CW_LIBEVENT_KIND_UNKNOWN,
    };
    struct cw_libevent_counters *counters;

    if (!callback)
        return;
    cw_libevent_emit(
        key, &registration, action,
        object_kind, callback_role);
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(
            &counters->high_level_callbacks_emitted, 1);
}

static __attribute__((noinline)) void cw_libevent_emit_bufferevent_callbacks(
    const struct cw_libevent_key *key,
    const struct cw_libevent_bufferevent *bufferevent,
    __u32 action)
{
    cw_libevent_emit_high_level(
        key, bufferevent->read_callback, bufferevent->fd,
        bufferevent->generation, action,
        CW_LIBEVENT_OBJECT_BUFFEREVENT,
        CW_LIBEVENT_CALLBACK_READ);
    cw_libevent_emit_high_level(
        key, bufferevent->write_callback, bufferevent->fd,
        bufferevent->generation, action,
        CW_LIBEVENT_OBJECT_BUFFEREVENT,
        CW_LIBEVENT_CALLBACK_WRITE);
    cw_libevent_emit_high_level(
        key, bufferevent->event_callback, bufferevent->fd,
        bufferevent->generation, action,
        CW_LIBEVENT_OBJECT_BUFFEREVENT,
        CW_LIBEVENT_CALLBACK_STATUS);
}

SEC("uprobe")
int trace_libevent_bufferevent_socket_new_entry(struct pt_regs *ctx)
{
    struct cw_libevent_bufferevent_new_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.fd = (__s32)PT_REGS_PARM2(ctx);
    state.options = (__u32)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(
        &libevent_bufferevent_new_states,
        &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libevent_bufferevent_socket_new_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_bufferevent_new_state *state;
    struct cw_libevent_bufferevent value = {0};
    struct cw_libevent_counters *counters;
    __u64 handle;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libevent_bufferevent_new_states, &pid_tgid);
    if (!state)
        return 0;
    handle = (__u64)PT_REGS_RC(ctx);
    if (!handle)
        goto done;
    state->key.event = handle;
    value.fd = state->fd;
    value.generation = cw_libevent_next_generation(&state->key);
    bpf_map_update_elem(
        &libevent_bufferevents, &state->key, &value, BPF_ANY);
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(
            &counters->bufferevents_created, 1);
done:
    bpf_map_delete_elem(
        &libevent_bufferevent_new_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_bufferevent_setcb_entry(struct pt_regs *ctx)
{
    struct cw_libevent_key key = {0};
    struct cw_libevent_bufferevent *bufferevent;
    struct cw_libevent_counters *counters;
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &key))
        return 0;
    key.event = PT_REGS_PARM1(ctx);
    bufferevent = bpf_map_lookup_elem(
        &libevent_bufferevents, &key);
    if (!bufferevent)
        return 0;
    bufferevent->read_callback = PT_REGS_PARM2(ctx);
    bufferevent->write_callback = PT_REGS_PARM3(ctx);
    bufferevent->event_callback = PT_REGS_PARM4(ctx);
    bufferevent->callback_arg = PT_REGS_PARM5(ctx);
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(
            &counters->bufferevents_callbacks_set, 1);
    cw_libevent_emit_bufferevent_callbacks(
        &key, bufferevent, CW_LIBEVENT_DEFINED);
    return 0;
}

SEC("uprobe")
int trace_libevent_bufferevent_setfd_entry(struct pt_regs *ctx)
{
    struct cw_libevent_bufferevent_fd_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.key.event = PT_REGS_PARM1(ctx);
    state.fd = (__s32)PT_REGS_PARM2(ctx);
    if (state.key.event)
        bpf_map_update_elem(
            &libevent_bufferevent_fd_states,
            &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libevent_bufferevent_setfd_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_bufferevent_fd_state *state;
    struct cw_libevent_bufferevent *bufferevent;
    struct cw_libevent_counters *counters;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libevent_bufferevent_fd_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0) {
        bufferevent = bpf_map_lookup_elem(
            &libevent_bufferevents, &state->key);
        if (bufferevent) {
            bufferevent->fd = state->fd;
            counters = cw_libevent_get_counters();
            if (counters)
                __sync_fetch_and_add(
                    &counters->bufferevents_fd_set, 1);
            if (bufferevent->active)
                cw_libevent_emit_bufferevent_callbacks(
                    &state->key, bufferevent,
                    CW_LIBEVENT_ACTIVATED);
        }
    }
    bpf_map_delete_elem(
        &libevent_bufferevent_fd_states, &pid_tgid);
    return 0;
}

static __always_inline int cw_libevent_bufferevent_toggle_enter(
    struct pt_regs *ctx, void *map)
{
    struct cw_libevent_bufferevent_toggle_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.key.event = PT_REGS_PARM1(ctx);
    state.events = (__u32)PT_REGS_PARM2(ctx);
    if (state.key.event)
        bpf_map_update_elem(map, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uprobe")
int trace_libevent_bufferevent_enable_entry(struct pt_regs *ctx)
{
    return cw_libevent_bufferevent_toggle_enter(
        ctx, &libevent_bufferevent_enable_states);
}

SEC("uretprobe")
int trace_libevent_bufferevent_enable_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_bufferevent_toggle_state *state;
    struct cw_libevent_bufferevent *bufferevent;
    struct cw_libevent_counters *counters;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libevent_bufferevent_enable_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0) {
        bufferevent = bpf_map_lookup_elem(
            &libevent_bufferevents, &state->key);
        if (bufferevent) {
            bufferevent->enabled_events |= state->events;
            bufferevent->active = bufferevent->enabled_events != 0;
            counters = cw_libevent_get_counters();
            if (counters)
                __sync_fetch_and_add(
                    &counters->bufferevents_enabled, 1);
            cw_libevent_emit_bufferevent_callbacks(
                &state->key, bufferevent,
                CW_LIBEVENT_ACTIVATED);
        }
    }
    bpf_map_delete_elem(
        &libevent_bufferevent_enable_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_bufferevent_disable_entry(struct pt_regs *ctx)
{
    return cw_libevent_bufferevent_toggle_enter(
        ctx, &libevent_bufferevent_disable_states);
}

SEC("uretprobe")
int trace_libevent_bufferevent_disable_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_bufferevent_toggle_state *state;
    struct cw_libevent_bufferevent *bufferevent;
    struct cw_libevent_counters *counters;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libevent_bufferevent_disable_states, &pid_tgid);
    if (!state)
        return 0;
    if ((__s64)PT_REGS_RC(ctx) == 0) {
        bufferevent = bpf_map_lookup_elem(
            &libevent_bufferevents, &state->key);
        if (bufferevent) {
            bufferevent->enabled_events &= ~state->events;
            bufferevent->active = bufferevent->enabled_events != 0;
        }
        counters = cw_libevent_get_counters();
        if (counters)
            __sync_fetch_and_add(
                &counters->bufferevents_disabled, 1);
    }
    bpf_map_delete_elem(
        &libevent_bufferevent_disable_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_bufferevent_free_entry(struct pt_regs *ctx)
{
    struct cw_libevent_key key = {0};
    struct cw_libevent_counters *counters;
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &key))
        return 0;
    key.event = PT_REGS_PARM1(ctx);
    if (!key.event ||
        bpf_map_delete_elem(&libevent_bufferevents, &key))
        return 0;
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(
            &counters->bufferevents_freed, 1);
    return 0;
}

SEC("uprobe")
int trace_libevent_listener_new_entry(struct pt_regs *ctx)
{
    struct cw_libevent_listener_new_state state = {0};
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &state.key))
        return 0;
    state.callback = PT_REGS_PARM2(ctx);
    state.callback_arg = PT_REGS_PARM3(ctx);
    state.fd = (__s32)PT_REGS_PARM6(ctx);
    if (!state.callback || state.fd < 0)
        return 0;
    bpf_map_update_elem(
        &libevent_listener_new_states,
        &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_libevent_listener_new_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cw_libevent_listener_new_state *state;
    struct cw_libevent_listener value = {0};
    struct cw_libevent_counters *counters;
    __u64 handle;

    if (!cw_libevent_enabled())
        return 0;
    state = bpf_map_lookup_elem(
        &libevent_listener_new_states, &pid_tgid);
    if (!state)
        return 0;
    handle = (__u64)PT_REGS_RC(ctx);
    if (!handle)
        goto done;
    state->key.event = handle;
    value.callback = state->callback;
    value.callback_arg = state->callback_arg;
    value.fd = state->fd;
    value.generation = cw_libevent_next_generation(&state->key);
    value.active = 1;
    bpf_map_update_elem(
        &libevent_listeners, &state->key, &value, BPF_ANY);
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(&counters->listeners_created, 1);
    cw_libevent_emit_high_level(
        &state->key, value.callback, value.fd,
        value.generation, CW_LIBEVENT_ACTIVATED,
        CW_LIBEVENT_OBJECT_LISTENER,
        CW_LIBEVENT_CALLBACK_ACCEPT);
done:
    bpf_map_delete_elem(
        &libevent_listener_new_states, &pid_tgid);
    return 0;
}

SEC("uprobe")
int trace_libevent_listener_free_entry(struct pt_regs *ctx)
{
    struct cw_libevent_key key = {0};
    struct cw_libevent_counters *counters;
    __u64 pid_tgid;

    if (!cw_libevent_enabled() ||
        !cw_libevent_process(&pid_tgid, &key))
        return 0;
    key.event = PT_REGS_PARM1(ctx);
    if (!key.event ||
        bpf_map_delete_elem(&libevent_listeners, &key))
        return 0;
    counters = cw_libevent_get_counters();
    if (counters)
        __sync_fetch_and_add(&counters->listeners_freed, 1);
    return 0;
}

#endif
