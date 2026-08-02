// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "core/core_config.h"
#include "async/async_config.h"
#include "epoll/epoll_config.h"
#include "epoll/epoll.h"
#include "epoll/epoll_shared.h"
#include "io_uring/io_uring_config.h"
#include "callweave.skel.h"
#include "callweave_internal.h"
#include "libevent/libevent.h"
#include "runtime/runtime_adapter.h"

static int attach_named(
    struct bpf_program *program, struct bpf_link **link,
    const char *path, const char *function, bool return_probe)
{
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
        .func_name = function,
        .retprobe = return_probe,
    };
    int error;

    *link = bpf_program__attach_uprobe_opts(
        program, -1, path, 0, &options);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return 0;
    *link = NULL;
    return error;
}

static int attach_api(
    struct cw_libevent_runtime *runtime,
    struct bpf_program *entry_program,
    struct bpf_program *return_program,
    const char *function)
{
    struct bpf_link *entry = NULL;
    struct bpf_link *return_link = NULL;
    int error;

    error = attach_named(
        entry_program, &entry, runtime->module_path,
        function, false);
    if (error)
        goto failed;
    if (return_program) {
        error = attach_named(
            return_program, &return_link,
            runtime->module_path, function, true);
        if (error)
            goto failed;
    }
    runtime->api_links[runtime->api_link_count++] = entry;
    if (return_link)
        runtime->api_links[runtime->api_link_count++] =
            return_link;
    return 0;

failed:
    bpf_link__destroy(return_link);
    bpf_link__destroy(entry);
    fprintf(
        stderr,
        "failed to attach libevent API probe %s in %s: %s\n",
        function, runtime->module_path, strerror(-error));
    return error;
}

int cw_libevent_attach(
    struct cw_libevent_runtime *runtime,
    struct callweave_bpf *skeleton,
    pid_t pid, const char *module_path)
{
    int error;

    if (!runtime || !skeleton || pid <= 0 ||
        !module_path || !module_path[0])
        return -EINVAL;
    memset(runtime, 0, sizeof(*runtime));
    runtime->pid = pid;
    if (snprintf(
            runtime->module_path,
            sizeof(runtime->module_path), "%s",
            module_path) >=
        (int)sizeof(runtime->module_path))
        return -ENAMETOOLONG;
    cw_runtime_callback_registry_init(
        &runtime->callback_registry, pid, "libevent",
        runtime->module_path, false,
        skeleton->progs.trace_epoll_callback_entry,
        skeleton->progs.trace_epoll_callback_return);

    error = attach_api(
        runtime, skeleton->progs.trace_libevent_new_entry,
        skeleton->progs.trace_libevent_new_return,
        "event_new");
    if (error)
        goto failed;
    error = attach_api(
        runtime, skeleton->progs.trace_libevent_assign_entry,
        skeleton->progs.trace_libevent_assign_return,
        "event_assign");
    if (error)
        goto failed;
    error = attach_api(
        runtime, skeleton->progs.trace_libevent_add_entry,
        skeleton->progs.trace_libevent_add_return,
        "event_add");
    if (error)
        goto failed;
    error = attach_api(
        runtime, skeleton->progs.trace_libevent_del_entry,
        skeleton->progs.trace_libevent_del_return,
        "event_del");
    if (error)
        goto failed;
    error = attach_api(
        runtime, skeleton->progs.trace_libevent_free_entry,
        NULL, "event_free");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libevent_bufferevent_socket_new_entry,
        skeleton->progs.trace_libevent_bufferevent_socket_new_return,
        "bufferevent_socket_new");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libevent_bufferevent_setcb_entry,
        NULL, "bufferevent_setcb");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libevent_bufferevent_setfd_entry,
        skeleton->progs.trace_libevent_bufferevent_setfd_return,
        "bufferevent_setfd");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libevent_bufferevent_enable_entry,
        skeleton->progs.trace_libevent_bufferevent_enable_return,
        "bufferevent_enable");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libevent_bufferevent_disable_entry,
        skeleton->progs.trace_libevent_bufferevent_disable_return,
        "bufferevent_disable");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libevent_bufferevent_free_entry,
        NULL, "bufferevent_free");
    if (error)
        goto failed;
    error = attach_api(
        runtime, skeleton->progs.trace_libevent_listener_new_entry,
        skeleton->progs.trace_libevent_listener_new_return,
        "evconnlistener_new");
    if (error)
        goto failed;
    error = attach_api(
        runtime, skeleton->progs.trace_libevent_listener_free_entry,
        NULL, "evconnlistener_free");
    if (error)
        goto failed;
    return 0;

failed:
    cw_libevent_destroy(runtime);
    return error;
}

static struct cw_libevent_registration_record *remember_registration(
    struct cw_libevent_runtime *runtime,
    const struct cw_libevent_registration_event *event)
{
    struct cw_libevent_registration_record *items;
    size_t capacity;
    size_t index;

    for (index = 0; index < runtime->registration_count; index++) {
        struct cw_libevent_registration_record *registration =
            &runtime->registrations[index];

        if (registration->event == event->event &&
            registration->generation == event->generation) {
            registration->fd = event->fd;
            registration->events = event->events;
            registration->kind = event->kind;
            registration->object_kind = event->object_kind;
            registration->callback_role = event->callback_role;
            if (event->action == CW_LIBEVENT_ACTIVATED)
                registration->active = true;
            return registration;
        }
    }
    if (runtime->registration_count ==
        runtime->registration_capacity) {
        capacity = runtime->registration_capacity ?
            runtime->registration_capacity * 2 : 8;
        items = realloc(
            runtime->registrations,
            capacity * sizeof(*items));
        if (!items)
            return NULL;
        runtime->registrations = items;
        runtime->registration_capacity = capacity;
    }
    items = &runtime->registrations[runtime->registration_count++];
    memset(items, 0, sizeof(*items));
    items->event = event->event;
    items->generation = event->generation;
    items->fd = event->fd;
    items->events = event->events;
    items->kind = event->kind;
    items->object_kind = event->object_kind;
    items->callback_role = event->callback_role;
    items->active = event->action == CW_LIBEVENT_ACTIVATED;
    return items;
}

int cw_libevent_handle_registration(
    void *context, void *data, size_t data_size)
{
    struct cw_libevent_runtime *runtime = context;
    const struct cw_libevent_registration_event *event = data;

    if (!runtime || !event || data_size < sizeof(*event))
        return -EINVAL;
    (void)remember_registration(runtime, event);
    (void)cw_runtime_register_callback(
        &runtime->callback_registry, event->callback,
        event->event, event->fd);
    return 0;
}

void cw_libevent_refresh_epoll(
    struct cw_libevent_runtime *runtime,
    struct output_options *output)
{
    size_t index;

    if (!runtime || !output)
        return;
    for (index = 0; index < runtime->registration_count; index++) {
        struct cw_libevent_registration_record *registration =
            &runtime->registrations[index];

        if (registration->seeded || !registration->active ||
            registration->kind != CW_LIBEVENT_KIND_IO ||
            registration->fd < 0)
            continue;
        if (!cw_epoll_seed_runtime_fd(
                output, (uint32_t)runtime->pid,
                registration->fd))
            continue;
        registration->seeded = true;
        output->libevent_fallback_tokens++;
    }
}

static const char *attribution_mode(
    const struct cw_epoll_counters *counters)
{
    if (counters->evidence_exact &&
        (counters->evidence_ready_to_io ||
         counters->evidence_ready_only))
        return "mixed exact/fallback";
    if (counters->evidence_exact)
        return "exact callback";
    if (counters->evidence_ready_to_io)
        return "ready-to-I/O fallback";
    if (counters->evidence_ready_only)
        return "ready-only";
    return "no classified ready paths";
}

static void read_attribution(
    int map_fd, struct cw_epoll_counters *counters,
    uint64_t *classified, uint64_t *pending)
{
    uint64_t correlatable;
    uint32_t zero = 0;

    memset(counters, 0, sizeof(*counters));
    if (map_fd >= 0)
        (void)bpf_map_lookup_elem(map_fd, &zero, counters);
    *classified = counters->evidence_exact +
        counters->evidence_ready_to_io +
        counters->evidence_ready_only;
    correlatable =
        counters->ready_events > counters->unresolved_events ?
            counters->ready_events - counters->unresolved_events : 0;
    *pending = correlatable > *classified ?
        correlatable - *classified : 0;
}

void cw_libevent_print_summary(
    const struct cw_libevent_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream)
{
    struct cw_libevent_counters counters = {0};
    struct cw_epoll_counters attribution;
    uint64_t classified;
    uint64_t pending;
    double exact_percent;
    uint32_t zero = 0;

    if (!runtime || !stream)
        return;
    if (counters_map_fd >= 0)
        (void)bpf_map_lookup_elem(
            counters_map_fd, &zero, &counters);
    read_attribution(
        epoll_counters_map_fd, &attribution,
        &classified, &pending);
    exact_percent = classified ?
        (double)attribution.evidence_exact * 100.0 /
            (double)classified : 0.0;
    fprintf(
        stream,
        "\nlibevent adapter health\n"
        "  Module              : %s\n"
        "  Event lifecycle     : created=%llu assigned=%llu "
        "added=%llu deleted=%llu freed=%llu\n"
        "  Event kinds         : I/O=%llu timer=%llu signal=%llu "
        "unsupported=%llu\n"
        "  Trigger policy      : persistent=%llu one-shot=%llu\n"
        "  Callback discovery  : records=%llu dropped=%llu "
        "unique-user=%zu runtime-internal=%zu instrumented=%zu "
        "attach-failed=%llu\n"
        "  Missing definitions : %llu "
        "(usually created before attach)\n"
        "  Bufferevent API     : created=%llu setcb=%llu setfd=%llu "
        "enabled=%llu disabled=%llu freed=%llu\n"
        "  Listener            : created=%llu freed=%llu\n"
        "  High-level discovery: %llu records "
        "(not callback invocations)\n",
        runtime->module_path,
        (unsigned long long)counters.created,
        (unsigned long long)counters.assigned,
        (unsigned long long)counters.added,
        (unsigned long long)counters.deleted,
        (unsigned long long)counters.freed,
        (unsigned long long)counters.io_events,
        (unsigned long long)counters.timer_events,
        (unsigned long long)counters.signal_events,
        (unsigned long long)counters.unsupported_events,
        (unsigned long long)counters.persistent_events,
        (unsigned long long)counters.oneshot_events,
        (unsigned long long)counters.registrations_emitted,
        (unsigned long long)counters.registrations_dropped,
        cw_runtime_user_callback_count(
            &runtime->callback_registry),
        cw_runtime_internal_callback_count(
            &runtime->callback_registry),
        cw_runtime_attached_callback_count(
            &runtime->callback_registry),
        (unsigned long long)
            runtime->callback_registry.attach_failures,
        (unsigned long long)counters.definitions_missing,
        (unsigned long long)counters.bufferevents_created,
        (unsigned long long)counters.bufferevents_callbacks_set,
        (unsigned long long)counters.bufferevents_fd_set,
        (unsigned long long)counters.bufferevents_enabled,
        (unsigned long long)counters.bufferevents_disabled,
        (unsigned long long)counters.bufferevents_freed,
        (unsigned long long)counters.listeners_created,
        (unsigned long long)counters.listeners_freed,
        (unsigned long long)counters.high_level_callbacks_emitted);
    fprintf(
        stream,
        "\nlibevent attribution coverage\n"
        "  Mode                : %s\n"
        "  Classified paths    : %llu\n"
        "  Exact               : %llu (%.2f%%)\n"
        "  Ready-to-I/O        : %llu\n"
        "  Ready-only          : %llu\n"
        "  Learned FD tokens   : %llu\n"
        "  Unresolved ready    : %llu\n"
        "  Pending final cycles: %llu\n"
        "  Evidence policy     : exact covers I/O callbacks with a "
        "completed callback boundary; timer and signal callbacks are "
        "classified but are not attributed to an application FD\n"
        "\nlibevent field notes\n"
        "  unmatched callback  : no ready FD could be joined to that "
        "callback; timer/signal callbacks are expected here and this "
        "does not mean a dropped record\n"
        "  pending final cycle : a ready path was still open when the "
        "target or capture stopped; it is separate from dropped data\n"
        "  stale FD lifetime   : a historical FD generation retained "
        "after that FD was closed or reused\n"
        "  user/internal       : unique application callbacks versus "
        "callbacks implemented inside libevent; only instrumented "
        "callbacks receive entry/return probes\n"
        "  setfd               : successful bufferevent_setfd() calls; "
        "zero is normal when the FD was supplied at creation\n"
        "  high-level discovery: bufferevent/listener callback-state "
        "records, not the number of callback executions\n",
        attribution_mode(&attribution),
        (unsigned long long)classified,
        (unsigned long long)attribution.evidence_exact,
        exact_percent,
        (unsigned long long)attribution.evidence_ready_to_io,
        (unsigned long long)attribution.evidence_ready_only,
        (unsigned long long)fallback_tokens,
        (unsigned long long)attribution.unresolved_events,
        (unsigned long long)pending);
}

static int write_json_string(FILE *stream, const char *text)
{
    const unsigned char *cursor =
        (const unsigned char *)text;

    if (fputc('"', stream) == EOF)
        return -1;
    for (; *cursor; cursor++) {
        if (*cursor == '"' || *cursor == '\\') {
            if (fputc('\\', stream) == EOF ||
                fputc(*cursor, stream) == EOF)
                return -1;
        } else if (*cursor == '\n') {
            if (fputs("\\n", stream) == EOF)
                return -1;
        } else if (*cursor == '\r') {
            if (fputs("\\r", stream) == EOF)
                return -1;
        } else if (*cursor == '\t') {
            if (fputs("\\t", stream) == EOF)
                return -1;
        } else if (*cursor < 0x20) {
            if (fprintf(stream, "\\u%04x", *cursor) < 0)
                return -1;
        } else if (fputc(*cursor, stream) == EOF) {
            return -1;
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

int cw_libevent_write_summary_json(
    const struct cw_libevent_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream)
{
    struct cw_libevent_counters counters = {0};
    struct cw_epoll_counters attribution;
    uint64_t classified;
    uint64_t pending;
    uint32_t zero = 0;

    if (!runtime || !stream)
        return -1;
    if (counters_map_fd >= 0)
        (void)bpf_map_lookup_elem(
            counters_map_fd, &zero, &counters);
    read_attribution(
        epoll_counters_map_fd, &attribution,
        &classified, &pending);
    if (fputs(
            "{\"type\":\"libevent_summary\",\"module\":",
            stream) == EOF ||
        write_json_string(stream, runtime->module_path) ||
        fprintf(
            stream,
            ",\"created\":%llu,\"assigned\":%llu,"
            "\"added\":%llu,\"deleted\":%llu,\"freed\":%llu,"
            "\"io_events\":%llu,\"timer_events\":%llu,"
            "\"signal_events\":%llu,\"unsupported_events\":%llu,"
            "\"persistent_events\":%llu,\"oneshot_events\":%llu,"
            "\"registration_events\":%llu,"
            "\"registration_dropped\":%llu,"
            "\"unique_callbacks\":%zu,"
            "\"user_callbacks\":%zu,"
            "\"internal_callbacks\":%zu,"
            "\"callback_attach_failures\":%llu,"
            "\"definitions_missing\":%llu,"
            "\"bufferevents_created\":%llu,"
            "\"bufferevents_callbacks_set\":%llu,"
            "\"bufferevents_fd_set\":%llu,"
            "\"bufferevents_enabled\":%llu,"
            "\"bufferevents_disabled\":%llu,"
            "\"bufferevents_freed\":%llu,"
            "\"listeners_created\":%llu,"
            "\"listeners_freed\":%llu,"
            "\"high_level_callback_events\":%llu,"
            "\"attribution_mode\":\"%s\","
            "\"classified_ready_paths\":%llu,"
            "\"evidence_exact\":%llu,"
            "\"evidence_ready_to_io\":%llu,"
            "\"evidence_ready_only\":%llu,"
            "\"learned_fd_tokens\":%llu,"
            "\"unresolved_ready\":%llu,"
            "\"pending_at_stop\":%llu}\n",
            (unsigned long long)counters.created,
            (unsigned long long)counters.assigned,
            (unsigned long long)counters.added,
            (unsigned long long)counters.deleted,
            (unsigned long long)counters.freed,
            (unsigned long long)counters.io_events,
            (unsigned long long)counters.timer_events,
            (unsigned long long)counters.signal_events,
            (unsigned long long)counters.unsupported_events,
            (unsigned long long)counters.persistent_events,
            (unsigned long long)counters.oneshot_events,
            (unsigned long long)counters.registrations_emitted,
            (unsigned long long)counters.registrations_dropped,
            cw_runtime_attached_callback_count(
                &runtime->callback_registry),
            cw_runtime_user_callback_count(
                &runtime->callback_registry),
            cw_runtime_internal_callback_count(
                &runtime->callback_registry),
            (unsigned long long)
                runtime->callback_registry.attach_failures,
            (unsigned long long)counters.definitions_missing,
            (unsigned long long)counters.bufferevents_created,
            (unsigned long long)counters.bufferevents_callbacks_set,
            (unsigned long long)counters.bufferevents_fd_set,
            (unsigned long long)counters.bufferevents_enabled,
            (unsigned long long)counters.bufferevents_disabled,
            (unsigned long long)counters.bufferevents_freed,
            (unsigned long long)counters.listeners_created,
            (unsigned long long)counters.listeners_freed,
            (unsigned long long)counters.high_level_callbacks_emitted,
            attribution_mode(&attribution),
            (unsigned long long)classified,
            (unsigned long long)attribution.evidence_exact,
            (unsigned long long)attribution.evidence_ready_to_io,
            (unsigned long long)attribution.evidence_ready_only,
            (unsigned long long)fallback_tokens,
            (unsigned long long)attribution.unresolved_events,
            (unsigned long long)pending) < 0)
        return -1;
    return 0;
}

void cw_libevent_destroy(struct cw_libevent_runtime *runtime)
{
    if (!runtime)
        return;
    cw_runtime_callback_registry_destroy(
        &runtime->callback_registry);
    while (runtime->api_link_count)
        bpf_link__destroy(
            runtime->api_links[--runtime->api_link_count]);
    free(runtime->registrations);
    runtime->registrations = NULL;
    runtime->registration_count = 0;
    runtime->registration_capacity = 0;
}
