// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_LIBUV_H
#define CALLWEAVE_LIBUV_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <bpf/libbpf.h>

#include "libuv/libuv_shared.h"

struct callweave_bpf;

struct cw_libuv_callback_attachment {
    uint64_t address;
    uint64_t file_offset;
    char path[PATH_MAX];
    struct bpf_link *entry;
    struct bpf_link *return_link;
};

struct cw_libuv_runtime {
    pid_t pid;
    char module_path[PATH_MAX];
    struct bpf_program *callback_entry;
    struct bpf_program *callback_return;
    struct bpf_link *api_links[9];
    size_t api_link_count;
    struct cw_libuv_callback_attachment *callbacks;
    size_t callback_count;
    size_t callback_capacity;
    uint64_t callback_attach_failures;
};

int cw_libuv_attach(struct cw_libuv_runtime *runtime,
                    struct callweave_bpf *skeleton,
                    pid_t pid, const char *module_path);
int cw_libuv_handle_registration(
    void *context, void *data, size_t data_size);
void cw_libuv_print_summary(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, FILE *stream);
int cw_libuv_write_summary_json(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, FILE *stream);
void cw_libuv_destroy(struct cw_libuv_runtime *runtime);

#endif
