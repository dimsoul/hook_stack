// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_REPORT_H
#define CALLWEAVE_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CW_REPORT_MAX_HOPS 8

enum cw_report_work_kind {
    CW_REPORT_WORK_SCHEDULER = 0,
    CW_REPORT_WORK_IN_FLIGHT,
    CW_REPORT_WORK_IO,
};

struct cw_report_hop {
    uint32_t index;
    uint32_t pid;
    uint32_t tid;
    uint32_t target_tid;
    uint32_t target_arg;
    char comm[17];
    const char *source;
    const char *target;
    uint64_t key;
    uint64_t queue_ns;
    uint64_t work_ns;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    uint32_t work_kind;
    uint32_t wait_kind;
    uint32_t wait_operation;
    uint64_t wait_address;
    uint64_t wait_duration_ns;
    uint64_t wait_wake_ns;
    uint32_t waker_pid;
    uint32_t waker_tid;
    char waker_comm[17];
};

struct cw_report_chain {
    const char *kind;
    const char *name;
    uint64_t timestamp_ms;
    uint32_t pid;
    uint32_t tid;
    char comm[17];
    uint64_t duration_ns;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    uint32_t truncated;
    uint32_t hop_count;
    struct cw_report_hop hops[CW_REPORT_MAX_HOPS];
};

struct cw_queue_diagnostic {
    uint32_t index;
    const char *source;
    const char *target;
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
    uint32_t worker_count;
    uint32_t busiest_worker_tid;
    uint64_t busiest_worker_started;
    uint64_t busiest_worker_average_work_ns;
};

int cw_write_chain_json(FILE *stream, const struct cw_report_chain *chain);
int cw_write_queue_diagnostics_json(
    FILE *stream, const struct cw_queue_diagnostic *diagnostics,
    size_t count);
int cw_html_report_begin(FILE *stream);
int cw_html_report_begin_mode(FILE *stream, const char *mode);
int cw_html_report_write(FILE *stream, const struct cw_report_chain *chain,
                         bool *first);
int cw_html_report_end(FILE *stream,
                       const struct cw_queue_diagnostic *diagnostics,
                       size_t count);

#endif
