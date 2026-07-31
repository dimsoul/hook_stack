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
#include "io_uring/io_uring_config.h"
#include "callweave.skel.h"
#include "libuv/libuv.h"
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
    runtime->callback_entry =
        skeleton->progs.trace_epoll_callback_entry;
    runtime->callback_return =
        skeleton->progs.trace_epoll_callback_return;

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

static struct cw_libuv_callback_attachment *
find_callback(struct cw_libuv_runtime *runtime, uint64_t address)
{
    size_t index;

    for (index = 0; index < runtime->callback_count; index++) {
        if (runtime->callbacks[index].address == address)
            return &runtime->callbacks[index];
    }
    return NULL;
}

static struct cw_libuv_callback_attachment *
append_callback(struct cw_libuv_runtime *runtime)
{
    struct cw_libuv_callback_attachment *items;
    size_t capacity;

    if (runtime->callback_count == runtime->callback_capacity) {
        capacity = runtime->callback_capacity ?
                   runtime->callback_capacity * 2 : 8;
        items = realloc(
            runtime->callbacks,
            capacity * sizeof(*runtime->callbacks));
        if (!items)
            return NULL;
        runtime->callbacks = items;
        runtime->callback_capacity = capacity;
    }
    return &runtime->callbacks[runtime->callback_count++];
}

static int attach_callback(
    struct cw_libuv_runtime *runtime,
    const struct cw_libuv_registration_event *event)
{
    struct cw_libuv_callback_attachment *attachment;
    struct bpf_uprobe_opts entry_options = {
        .sz = sizeof(entry_options),
        .bpf_cookie = event->callback,
    };
    struct bpf_uprobe_opts return_options = {
        .sz = sizeof(return_options),
        .bpf_cookie = event->callback,
        .retprobe = true,
    };
    int error;

    if (find_callback(runtime, event->callback))
        return 0;
    attachment = append_callback(runtime);
    if (!attachment)
        return -ENOMEM;
    memset(attachment, 0, sizeof(*attachment));
    attachment->address = event->callback;
    error = resolve_process_address(
        runtime->pid, event->callback,
        attachment->path, sizeof(attachment->path),
        &attachment->file_offset);
    if (error)
        goto failed;
    attachment->entry = bpf_program__attach_uprobe_opts(
        runtime->callback_entry, runtime->pid,
        attachment->path, attachment->file_offset,
        &entry_options);
    error = attachment->entry ?
            libbpf_get_error(attachment->entry) :
            (errno ? -errno : -EINVAL);
    if (error) {
        attachment->entry = NULL;
        goto failed;
    }
    attachment->return_link =
        bpf_program__attach_uprobe_opts(
            runtime->callback_return, runtime->pid,
            attachment->path, attachment->file_offset,
            &return_options);
    error = attachment->return_link ?
            libbpf_get_error(attachment->return_link) :
            (errno ? -errno : -EINVAL);
    if (error) {
        attachment->return_link = NULL;
        bpf_link__destroy(attachment->entry);
        attachment->entry = NULL;
        goto failed;
    }
    fprintf(
        stderr,
        "libuv: discovered callback 0x%llx for handle "
        "0x%llx/fd %d; attached %s+0x%llx\n",
        (unsigned long long)event->callback,
        (unsigned long long)event->handle,
        event->fd, attachment->path,
        (unsigned long long)attachment->file_offset);
    return 0;

failed:
    runtime->callback_attach_failures++;
    fprintf(
        stderr,
        "warning: cannot attach discovered libuv callback "
        "0x%llx for handle 0x%llx/fd %d: %s\n",
        (unsigned long long)event->callback,
        (unsigned long long)event->handle,
        event->fd, strerror(-error));
    return error;
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
    (void)attach_callback(runtime, event);
    return 0;
}

void cw_libuv_print_summary(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, FILE *stream)
{
    struct cw_libuv_counters counters = {0};
    uint32_t zero = 0;

    if (!runtime || !stream)
        return;
    if (counters_map_fd >= 0)
        (void)bpf_map_lookup_elem(
            counters_map_fd, &zero, &counters);
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
        runtime->callback_count -
            (size_t)runtime->callback_attach_failures,
        (unsigned long long)runtime->callback_attach_failures);
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
    int counters_map_fd, FILE *stream)
{
    struct cw_libuv_counters counters = {0};
    uint32_t zero = 0;

    if (!runtime || !stream)
        return -1;
    if (counters_map_fd >= 0)
        (void)bpf_map_lookup_elem(
            counters_map_fd, &zero, &counters);
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
            "\"callback_attach_failures\":%llu}\n",
            (unsigned long long)counters.initialized,
            (unsigned long long)counters.started,
            (unsigned long long)counters.stopped,
            (unsigned long long)counters.closed,
            (unsigned long long)counters.registrations_emitted,
            (unsigned long long)counters.registrations_dropped,
            runtime->callback_count -
                (size_t)runtime->callback_attach_failures,
            (unsigned long long)
                runtime->callback_attach_failures) < 0)
        return -1;
    return 0;
}

void cw_libuv_destroy(struct cw_libuv_runtime *runtime)
{
    size_t index;

    if (!runtime)
        return;
    for (index = 0; index < runtime->callback_count; index++) {
        bpf_link__destroy(runtime->callbacks[index].return_link);
        bpf_link__destroy(runtime->callbacks[index].entry);
    }
    while (runtime->api_link_count)
        bpf_link__destroy(
            runtime->api_links[--runtime->api_link_count]);
    free(runtime->callbacks);
    runtime->callbacks = NULL;
    runtime->callback_count = 0;
    runtime->callback_capacity = 0;
}
