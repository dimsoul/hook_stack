// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_INTERNAL_H
#define CALLWEAVE_INTERNAL_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <linux/types.h>

#include "core/capture_control.h"
#include "io_uring/io_uring_shared.h"

#define MAX_STACK_DEPTH 128
#define MAX_ASYNC_STACK_DEPTH 127
#define MAX_ASYNC_HOPS 8
#define ASYNC_HOP_ID_MASK 0xffffU
#define ASYNC_TARGET_ARG_SHIFT 16

struct async_hop_config {
    char *source;
    uint32_t source_arg;
    char *target;
    uint32_t target_arg;
};

struct async_hop_stats {
    uint64_t submitted;
    uint64_t started;
    uint64_t completed;
    uint64_t pending;
    uint64_t peak_pending;
    uint64_t active;
    uint64_t peak_active;
    uint64_t queue_total_ns;
    uint64_t work_total_ns;
    uint64_t futex_waits;
    uint64_t futex_wait_ns;
    uint64_t duplicate_keys;
    uint64_t expired;
    uint64_t unmatched_targets;
    uint64_t dropped;
};

struct proc_map {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char perms[5];
    char path[PATH_MAX];
    bool bias_checked;
    uint64_t load_bias;
};

struct map_list {
    struct proc_map *items;
    size_t count;
    size_t capacity;
};

struct io_uring_fd_resource {
    int fd;
    char path[PATH_MAX];
};

struct output_options {
    struct cw_capture_control *control;
    bool show_return_value;
    bool show_duration;
    bool show_attribution;
    bool show_async;
    bool show_discovery;
    int async_stack_map_fd;
    int discovery_stack_map_fd;
    int wait_stack_map_fd;
    int async_hop_stats_map_fd;
    int async_worker_stats_map_fd;
    int io_uring_stack_map_fd;
    int io_uring_counters_map_fd;
    int io_uring_aggregate_map_fd;
    int io_uring_result_map_fd;
    int io_uring_ring_stats_map_fd;
    int io_uring_failure_map_fd;
    int io_uring_link_map_fd;
    const char *io_uring_callback_name;
    const struct async_hop_config *async_hops;
    size_t async_hop_count;
    const char *async_source_name;
    const char *final_target_name;
    const char *target_path;
    uint32_t discovery_target_arg;
    uint64_t min_total_ns;
    uint64_t min_queue_ns;
    uint64_t min_work_ns;
    uint32_t max_events;
    uint32_t emitted_events;
    bool json_output;
    FILE *json_stream;
    FILE *report_stream;
    bool report_first;
    bool export_failed;
    bool io_uring_mode;
    bool io_uring_errors_only;
    uint64_t io_uring_min_latency_ns;
    uint32_t io_uring_top;
    uint32_t diagnostic_interval_ms;
    uint64_t diagnostic_last_ns;
    struct async_hop_stats diagnostic_previous[MAX_ASYNC_HOPS];
    struct map_list *io_uring_maps;
    struct io_uring_fd_resource *io_uring_resources;
    size_t io_uring_resource_count;
    size_t io_uring_resource_capacity;
    uint32_t io_uring_maps_pid;
    pid_t target_pid;
    int target_pidfd;
    bool target_exited;
};

void map_list_free(struct map_list *maps);
int read_process_maps(uint32_t pid, struct map_list *maps);
uint64_t event_realtime_nanoseconds(uint64_t timestamp_ns);
uint64_t monotonic_time_ns(void);
void print_event_time(uint64_t timestamp_ns);
void print_interval(const char *label, uint64_t nanoseconds);
void format_interval(char *buffer, size_t size, uint64_t nanoseconds);
void print_stack_frames(const uint64_t *stack, int32_t stack_size,
                        struct map_list *maps, const char *prefix,
                        const char *candidate_path,
                        char *candidate, size_t candidate_size,
                        struct cw_capture_control *control);

#endif
