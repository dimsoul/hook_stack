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
#include "runtime/runtime_adapter.h"

struct callweave_bpf;
struct output_options;

struct cw_libuv_poll_registration {
    uint64_t handle;
    uint32_t generation;
    int fd;
    bool seeded;
};

struct cw_libuv_runtime {
    pid_t pid;
    char module_path[PATH_MAX];
    struct cw_runtime_callback_registry callback_registry;
    struct bpf_link *api_links[9];
    size_t api_link_count;
    struct cw_libuv_poll_registration *registrations;
    size_t registration_count;
    size_t registration_capacity;
};

int cw_libuv_attach(struct cw_libuv_runtime *runtime,
                    struct callweave_bpf *skeleton,
                    pid_t pid, const char *module_path);
int cw_libuv_handle_registration(
    void *context, void *data, size_t data_size);
void cw_libuv_refresh_epoll(
    struct cw_libuv_runtime *runtime,
    struct output_options *output);
void cw_libuv_print_summary(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream);
int cw_libuv_write_summary_json(
    const struct cw_libuv_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream);
void cw_libuv_destroy(struct cw_libuv_runtime *runtime);

#endif
