// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "runtime/runtime_adapter.h"
#include "symbols.h"

void cw_runtime_callback_registry_init(
    struct cw_runtime_callback_registry *registry,
    pid_t pid, const char *runtime_name,
    const char *runtime_module,
    bool attach_runtime_callbacks,
    struct bpf_program *entry_program,
    struct bpf_program *return_program)
{
    if (!registry)
        return;
    memset(registry, 0, sizeof(*registry));
    registry->pid = pid;
    registry->runtime_name = runtime_name;
    registry->runtime_module = runtime_module;
    registry->attach_runtime_callbacks = attach_runtime_callbacks;
    registry->entry_program = entry_program;
    registry->return_program = return_program;
}

static struct cw_runtime_callback_attachment *find_callback(
    struct cw_runtime_callback_registry *registry, uint64_t address)
{
    size_t index;

    for (index = 0; index < registry->callback_count; index++) {
        if (registry->callbacks[index].address == address)
            return &registry->callbacks[index];
    }
    return NULL;
}

static struct cw_runtime_callback_attachment *append_callback(
    struct cw_runtime_callback_registry *registry)
{
    struct cw_runtime_callback_attachment *items;
    size_t capacity;

    if (registry->callback_count == registry->callback_capacity) {
        capacity = registry->callback_capacity ?
            registry->callback_capacity * 2 : 8;
        items = realloc(
            registry->callbacks, capacity * sizeof(*items));
        if (!items)
            return NULL;
        registry->callbacks = items;
        registry->callback_capacity = capacity;
    }
    return &registry->callbacks[registry->callback_count++];
}

int cw_runtime_register_callback(
    struct cw_runtime_callback_registry *registry,
    uint64_t callback, uint64_t object, int fd)
{
    struct cw_runtime_callback_attachment *attachment;
    struct bpf_uprobe_opts entry_options = {
        .sz = sizeof(entry_options),
        .bpf_cookie = callback,
    };
    struct bpf_uprobe_opts return_options = {
        .sz = sizeof(return_options),
        .bpf_cookie = callback,
        .retprobe = true,
    };
    int error;

    if (!registry || !callback || registry->pid <= 0 ||
        !registry->entry_program || !registry->return_program)
        return -EINVAL;
    if (find_callback(registry, callback))
        return 0;
    attachment = append_callback(registry);
    if (!attachment)
        return -ENOMEM;
    memset(attachment, 0, sizeof(*attachment));
    attachment->address = callback;
    error = resolve_process_address(
        registry->pid, callback,
        attachment->path, sizeof(attachment->path),
        &attachment->file_offset);
    if (error)
        goto failed;
    attachment->runtime_owned =
        registry->runtime_module &&
        !strcmp(attachment->path, registry->runtime_module);
    if (attachment->runtime_owned &&
        !registry->attach_runtime_callbacks)
        return 0;
    attachment->entry = bpf_program__attach_uprobe_opts(
        registry->entry_program, registry->pid,
        attachment->path, attachment->file_offset,
        &entry_options);
    error = attachment->entry ?
        libbpf_get_error(attachment->entry) :
        (errno ? -errno : -EINVAL);
    if (error) {
        attachment->entry = NULL;
        goto failed;
    }
    attachment->return_link = bpf_program__attach_uprobe_opts(
        registry->return_program, registry->pid,
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
    attachment->attached = true;
    fprintf(
        stderr,
        "%s: discovered callback 0x%llx for object "
        "0x%llx/fd %d; attached %s+0x%llx\n",
        registry->runtime_name ? registry->runtime_name : "runtime",
        (unsigned long long)callback,
        (unsigned long long)object, fd, attachment->path,
        (unsigned long long)attachment->file_offset);
    return 0;

failed:
    registry->attach_failures++;
    fprintf(
        stderr,
        "warning: cannot attach discovered %s callback "
        "0x%llx for object 0x%llx/fd %d: %s\n",
        registry->runtime_name ? registry->runtime_name : "runtime",
        (unsigned long long)callback,
        (unsigned long long)object, fd, strerror(-error));
    return error;
}

size_t cw_runtime_attached_callback_count(
    const struct cw_runtime_callback_registry *registry)
{
    size_t count = 0;
    size_t index;

    if (!registry)
        return 0;
    for (index = 0; index < registry->callback_count; index++) {
        if (registry->callbacks[index].attached)
            count++;
    }
    return count;
}

size_t cw_runtime_user_callback_count(
    const struct cw_runtime_callback_registry *registry)
{
    size_t count = 0;
    size_t index;

    if (!registry)
        return 0;
    for (index = 0; index < registry->callback_count; index++) {
        if (!registry->callbacks[index].runtime_owned)
            count++;
    }
    return count;
}

size_t cw_runtime_internal_callback_count(
    const struct cw_runtime_callback_registry *registry)
{
    size_t count = 0;
    size_t index;

    if (!registry)
        return 0;
    for (index = 0; index < registry->callback_count; index++) {
        if (registry->callbacks[index].runtime_owned)
            count++;
    }
    return count;
}

void cw_runtime_callback_registry_destroy(
    struct cw_runtime_callback_registry *registry)
{
    size_t index;

    if (!registry)
        return;
    for (index = 0; index < registry->callback_count; index++) {
        bpf_link__destroy(
            registry->callbacks[index].return_link);
        bpf_link__destroy(registry->callbacks[index].entry);
    }
    free(registry->callbacks);
    registry->callbacks = NULL;
    registry->callback_count = 0;
    registry->callback_capacity = 0;
}
