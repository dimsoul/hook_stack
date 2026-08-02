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
#include "libuv/libuv.h"
#include "runtime/runtime_adapter.h"
#include "symbols.h"

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
    struct cw_libuv_runtime *runtime,
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
        "failed to attach libuv API probe %s in %s: %s\n",
        function, runtime->module_path, strerror(-error));
    return error;
}

int cw_libuv_attach(struct cw_libuv_runtime *runtime,
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
        &runtime->callback_registry, pid, "libuv",
        runtime->module_path, true,
        skeleton->progs.trace_epoll_callback_entry,
        skeleton->progs.trace_epoll_callback_return);

    error = attach_api(
        runtime,
        skeleton->progs.trace_libuv_poll_init_entry,
        skeleton->progs.trace_libuv_poll_init_return,
        "uv_poll_init");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libuv_poll_init_socket_entry,
        skeleton->progs.trace_libuv_poll_init_socket_return,
        "uv_poll_init_socket");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libuv_poll_start_entry,
        skeleton->progs.trace_libuv_poll_start_return,
        "uv_poll_start");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libuv_poll_stop_entry,
        skeleton->progs.trace_libuv_poll_stop_return,
        "uv_poll_stop");
    if (error)
        goto failed;
    error = attach_api(
        runtime,
        skeleton->progs.trace_libuv_close_entry,
        NULL, "uv_close");
    if (error)
        goto failed;
    return 0;

failed:
    cw_libuv_destroy(runtime);
    return error;
}

static struct cw_libuv_poll_registration *remember_registration(
    struct cw_libuv_runtime *runtime,
    const struct cw_libuv_registration_event *event)
{
    struct cw_libuv_poll_registration *items;
    size_t capacity;
    size_t index;

    for (index = 0; index < runtime->registration_count; index++) {
        struct cw_libuv_poll_registration *registration =
            &runtime->registrations[index];

        if (registration->handle == event->handle &&
            registration->generation == event->generation) {
            registration->fd = event->fd;
            return registration;
        }
    }
    if (runtime->registration_count ==
        runtime->registration_capacity) {
        capacity = runtime->registration_capacity ?
            runtime->registration_capacity * 2 : 8;
        items = realloc(
            runtime->registrations,
            capacity * sizeof(*runtime->registrations));
        if (!items)
            return NULL;
        runtime->registrations = items;
        runtime->registration_capacity = capacity;
    }
    items = &runtime->registrations[runtime->registration_count++];
    memset(items, 0, sizeof(*items));
    items->handle = event->handle;
    items->generation = event->generation;
    items->fd = event->fd;
    return items;
}

int cw_libuv_handle_registration(
    void *context, void *data, size_t data_size)
{
    struct cw_libuv_runtime *runtime = context;
    const struct cw_libuv_registration_event *event = data;

    if (!runtime || !event ||
        data_size < sizeof(*event))
        return -EINVAL;
    /*
     * A failed dynamic callback attachment is diagnostic, not fatal to the
     * epoll capture. Remembering the callback prevents repeated warnings on
     * every uv_poll_start() for the same address.
     */
    (void)remember_registration(runtime, event);
    (void)cw_runtime_register_callback(
        &runtime->callback_registry, event->callback,
        event->handle, event->fd);
    return 0;
}

void cw_libuv_refresh_epoll(
    struct cw_libuv_runtime *runtime,
    struct output_options *output)
{
    size_t index;

    if (!runtime || !output)
        return;
    for (index = 0; index < runtime->registration_count; index++) {
        struct cw_libuv_poll_registration *registration =
            &runtime->registrations[index];

        if (registration->seeded || registration->fd < 0)
            continue;
        if (!cw_epoll_seed_runtime_fd(
                output, (uint32_t)runtime->pid,
                registration->fd))
            continue;
        registration->seeded = true;
        output->libuv_fallback_tokens++;
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
    *classified =
        counters->evidence_exact +
        counters->evidence_ready_to_io +
        counters->evidence_ready_only;
    correlatable =
        counters->ready_events > counters->unresolved_events ?
            counters->ready_events - counters->unresolved_events : 0;
    *pending = correlatable > *classified ?
        correlatable - *classified : 0;
}

void cw_libuv_print_summary(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream)
{
    struct cw_libuv_counters counters = {0};
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
        "\nlibuv adapter health\n"
        "  Module              : %s\n"
        "  Poll handles        : initialized=%llu started=%llu "
        "stopped=%llu closed=%llu\n"
        "  Callback discovery  : events=%llu dropped=%llu "
        "unique-attached=%zu attach-failed=%llu\n",
        runtime->module_path,
        (unsigned long long)counters.initialized,
        (unsigned long long)counters.started,
        (unsigned long long)counters.stopped,
        (unsigned long long)counters.closed,
        (unsigned long long)counters.registrations_emitted,
        (unsigned long long)counters.registrations_dropped,
        cw_runtime_attached_callback_count(
            &runtime->callback_registry),
        (unsigned long long)
            runtime->callback_registry.attach_failures);
    fprintf(
        stream,
        "\nlibuv attribution coverage\n"
        "  Mode                : %s\n"
        "  Classified paths    : %llu\n"
        "  Exact               : %llu (%.2f%%)\n"
        "  Ready-to-I/O        : %llu "
        "(callback boundary unavailable)\n"
        "  Ready-only          : %llu "
        "(no matching callback completion or I/O)\n"
        "  Learned FD tokens   : %llu "
        "(from observed libuv FDs)\n"
        "  Unresolved ready    : %llu\n"
        "  Pending at stop     : %llu\n"
        "  Evidence policy     : exact requires a completed callback; "
        "fallback paths use kernel-backed FD and I/O correlation\n",
        attribution_mode(&attribution),
        (unsigned long long)classified,
        (unsigned long long)attribution.evidence_exact,
        exact_percent,
        (unsigned long long)
            attribution.evidence_ready_to_io,
        (unsigned long long)
            attribution.evidence_ready_only,
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

int cw_libuv_write_summary_json(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream)
{
    struct cw_libuv_counters counters = {0};
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
            "{\"type\":\"libuv_summary\",\"module\":",
            stream) == EOF ||
        write_json_string(stream, runtime->module_path) ||
        fprintf(
            stream,
            ",\"initialized\":%llu,\"started\":%llu,"
            "\"stopped\":%llu,\"closed\":%llu,"
            "\"registration_events\":%llu,"
            "\"registration_dropped\":%llu,"
            "\"unique_callbacks\":%zu,"
            "\"callback_attach_failures\":%llu,"
            "\"attribution_mode\":\"%s\","
            "\"classified_ready_paths\":%llu,"
            "\"evidence_exact\":%llu,"
            "\"evidence_ready_to_io\":%llu,"
            "\"evidence_ready_only\":%llu,"
            "\"learned_fd_tokens\":%llu,"
            "\"unresolved_ready\":%llu,"
            "\"pending_at_stop\":%llu}\n",
            (unsigned long long)counters.initialized,
            (unsigned long long)counters.started,
            (unsigned long long)counters.stopped,
            (unsigned long long)counters.closed,
            (unsigned long long)counters.registrations_emitted,
            (unsigned long long)counters.registrations_dropped,
            cw_runtime_attached_callback_count(
                &runtime->callback_registry),
            (unsigned long long)
                runtime->callback_registry.attach_failures,
            attribution_mode(&attribution),
            (unsigned long long)classified,
            (unsigned long long)attribution.evidence_exact,
            (unsigned long long)
                attribution.evidence_ready_to_io,
            (unsigned long long)
                attribution.evidence_ready_only,
            (unsigned long long)fallback_tokens,
            (unsigned long long)attribution.unresolved_events,
            (unsigned long long)pending) < 0)
        return -1;
    return 0;
}

void cw_libuv_destroy(struct cw_libuv_runtime *runtime)
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
