// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_REPORT_H
#define CALLWEAVE_REPORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CW_REPORT_MAX_HOPS 8

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
};

struct cw_report_chain {
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

int cw_write_chain_json(FILE *stream, const struct cw_report_chain *chain);
int cw_html_report_begin(FILE *stream);
int cw_html_report_write(FILE *stream, const struct cw_report_chain *chain,
                         bool *first);
int cw_html_report_end(FILE *stream);

#endif
