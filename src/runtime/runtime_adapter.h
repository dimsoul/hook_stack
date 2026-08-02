// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_RUNTIME_ADAPTER_H
#define CALLWEAVE_RUNTIME_ADAPTER_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <bpf/libbpf.h>

struct cw_runtime_callback_attachment {
    uint64_t address;
    uint64_t file_offset;
    char path[PATH_MAX];
    struct bpf_link *entry;
    struct bpf_link *return_link;
    bool runtime_owned;
    bool attached;
};

struct cw_runtime_callback_registry {
    pid_t pid;
    const char *runtime_name;
    const char *runtime_module;
    bool attach_runtime_callbacks;
    struct bpf_program *entry_program;
    struct bpf_program *return_program;
    struct cw_runtime_callback_attachment *callbacks;
    size_t callback_count;
    size_t callback_capacity;
    uint64_t attach_failures;
};

void cw_runtime_callback_registry_init(
    struct cw_runtime_callback_registry *registry,
    pid_t pid, const char *runtime_name,
    const char *runtime_module,
    bool attach_runtime_callbacks,
    struct bpf_program *entry_program,
    struct bpf_program *return_program);
int cw_runtime_register_callback(
    struct cw_runtime_callback_registry *registry,
    uint64_t callback, uint64_t object, int fd);
size_t cw_runtime_attached_callback_count(
    const struct cw_runtime_callback_registry *registry);
size_t cw_runtime_user_callback_count(
    const struct cw_runtime_callback_registry *registry);
size_t cw_runtime_internal_callback_count(
    const struct cw_runtime_callback_registry *registry);
void cw_runtime_callback_registry_destroy(
    struct cw_runtime_callback_registry *registry);

#endif
