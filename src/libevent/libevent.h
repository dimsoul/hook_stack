// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_LIBEVENT_H
#define CALLWEAVE_LIBEVENT_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <bpf/libbpf.h>

#include "libevent/libevent_shared.h"
#include "runtime/runtime_adapter.h"

struct callweave_bpf;
struct output_options;

struct cw_libevent_registration_record {
    uint64_t event;
    uint32_t generation;
    int fd;
    uint32_t events;
    uint32_t kind;
    uint32_t object_kind;
    uint32_t callback_role;
    bool active;
    bool seeded;
};

struct cw_libevent_runtime {
    pid_t pid;
    char module_path[PATH_MAX];
    struct cw_runtime_callback_registry callback_registry;
    struct bpf_link *api_links[32];
    size_t api_link_count;
    struct cw_libevent_registration_record *registrations;
    size_t registration_count;
    size_t registration_capacity;
};

int cw_libevent_attach(
    struct cw_libevent_runtime *runtime,
    struct callweave_bpf *skeleton,
    pid_t pid, const char *module_path);
int cw_libevent_handle_registration(
    void *context, void *data, size_t data_size);
void cw_libevent_refresh_epoll(
    struct cw_libevent_runtime *runtime,
    struct output_options *output);
void cw_libevent_print_summary(
    const struct cw_libevent_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream);
int cw_libevent_write_summary_json(
    const struct cw_libevent_runtime *runtime,
    int counters_map_fd, int epoll_counters_map_fd,
    uint64_t fallback_tokens, FILE *stream);
void cw_libevent_destroy(struct cw_libevent_runtime *runtime);

#endif
