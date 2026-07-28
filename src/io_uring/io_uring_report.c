// SPDX-License-Identifier: MIT

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/io_uring.h>
#include <bpf/bpf.h>

#include "callweave_internal.h"
#include "io_uring.h"
#include "io_uring_internal.h"

struct io_uring_aggregate_row {
    struct io_uring_aggregate_key key;
    struct io_uring_aggregate value;
};

struct io_uring_result_row {
    struct io_uring_result_key key;
    uint64_t count;
};

struct io_uring_error_code_summary {
    int32_t result;
    uint64_t count;
};

struct io_uring_operation_summary {
    uint64_t completions;
    uint64_t errors;
    uint64_t expected_timeouts;
    uint64_t total_ns;
    uint64_t maximum_ns;
    uint64_t deferred;
    uint64_t io_wq;
    uint64_t io_wq_queue_total_ns;
    uint64_t io_wq_queue_maximum_ns;
    int32_t top_error_result;
    uint64_t top_error_count;
};

struct io_uring_ring_row {
    uint64_t ring_ctx;
    struct io_uring_ring_stats value;
};

struct io_uring_failure_row {
    struct io_uring_failure_key key;
    struct io_uring_failure_stats value;
};

struct io_uring_link_row {
    struct io_uring_link_key key;
    struct io_uring_link_stats value;
};
static int compare_io_uring_aggregate_rows(const void *left,
                                           const void *right)
{
    const struct io_uring_aggregate_row *a = left;
    const struct io_uring_aggregate_row *b = right;
    uint64_t average_a;
    uint64_t average_b;

    if (a->value.maximum_ns < b->value.maximum_ns)
        return 1;
    if (a->value.maximum_ns > b->value.maximum_ns)
        return -1;
    average_a = a->value.count ?
        a->value.total_ns / a->value.count : 0;
    average_b = b->value.count ?
        b->value.total_ns / b->value.count : 0;
    if (average_a < average_b)
        return 1;
    if (average_a > average_b)
        return -1;
    return 0;
}

static size_t read_io_uring_aggregates(
    const struct output_options *output,
    struct io_uring_aggregate_row **rows)
{
    struct io_uring_aggregate_row *items = NULL;
    struct io_uring_aggregate_key current = {0};
    struct io_uring_aggregate_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_aggregate_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_aggregate_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_aggregate value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_aggregate_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 32;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].value = value;
        count++;
    }
    if (count > 1)
        qsort(items, count, sizeof(*items),
              compare_io_uring_aggregate_rows);
    *rows = items;
    return count;
}

static int compare_io_uring_result_rows(const void *left,
                                        const void *right)
{
    const struct io_uring_result_row *a = left;
    const struct io_uring_result_row *b = right;

    if (a->count < b->count)
        return 1;
    if (a->count > b->count)
        return -1;
    if (a->key.result > b->key.result)
        return 1;
    if (a->key.result < b->key.result)
        return -1;
    return 0;
}

static size_t read_io_uring_results(
    const struct output_options *output,
    struct io_uring_result_row **rows)
{
    struct io_uring_result_row *items = NULL;
    struct io_uring_result_key current = {0};
    struct io_uring_result_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_result_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_result_map_fd,
               have_current ? &current : NULL, &next)) {
        uint64_t value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_result_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 16;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].count = value;
        count++;
    }
    if (count > 1)
        qsort(items, count, sizeof(*items),
              compare_io_uring_result_rows);
    *rows = items;
    return count;
}

static bool io_uring_result_is_expected_timeout(
    const struct io_uring_result_key *key)
{
    return key->opcode == IORING_OP_TIMEOUT &&
           key->result == -ETIME;
}

static const char *errno_symbol(int error_number)
{
    if (error_number == EACCES)
        return "EACCES";
    if (error_number == EAGAIN)
        return "EAGAIN";
    if (error_number == EBADF)
        return "EBADF";
    if (error_number == ECANCELED)
        return "ECANCELED";
    if (error_number == ECONNREFUSED)
        return "ECONNREFUSED";
    if (error_number == EEXIST)
        return "EEXIST";
    if (error_number == EFAULT)
        return "EFAULT";
    if (error_number == EFBIG)
        return "EFBIG";
    if (error_number == EINTR)
        return "EINTR";
    if (error_number == EINVAL)
        return "EINVAL";
    if (error_number == EIO)
        return "EIO";
    if (error_number == EISDIR)
        return "EISDIR";
    if (error_number == EMFILE)
        return "EMFILE";
    if (error_number == ENFILE)
        return "ENFILE";
    if (error_number == ENOBUFS)
        return "ENOBUFS";
    if (error_number == ENODEV)
        return "ENODEV";
    if (error_number == ENOENT)
        return "ENOENT";
    if (error_number == ENOMEM)
        return "ENOMEM";
    if (error_number == ENOSPC)
        return "ENOSPC";
    if (error_number == ENOSYS)
        return "ENOSYS";
    if (error_number == ENXIO)
        return "ENXIO";
    if (error_number == EOPNOTSUPP)
        return "EOPNOTSUPP";
    if (error_number == EPERM)
        return "EPERM";
    if (error_number == EPIPE)
        return "EPIPE";
    if (error_number == ETIME)
        return "ETIME";
    if (error_number == ETIMEDOUT)
        return "ETIMEDOUT";
    return "ERRNO";
}

static void collect_io_uring_operation_summaries(
    const struct output_options *output,
    struct io_uring_operation_summary summaries[256])
{
    struct io_uring_aggregate_row *aggregates = NULL;
    struct io_uring_result_row *results = NULL;
    size_t aggregate_count;
    size_t result_count;
    size_t index;

    memset(summaries, 0, 256 * sizeof(*summaries));
    aggregate_count = read_io_uring_aggregates(output, &aggregates);
    for (index = 0; index < aggregate_count; index++) {
        const struct io_uring_aggregate_row *row = &aggregates[index];
        struct io_uring_operation_summary *summary;

        if (row->key.opcode >= 256)
            continue;
        summary = &summaries[row->key.opcode];
        summary->completions += row->value.count;
        summary->errors += row->value.errors;
        summary->total_ns += row->value.total_ns;
        summary->deferred += row->value.deferred_count;
        summary->io_wq += row->value.io_wq_count;
        summary->io_wq_queue_total_ns +=
            row->value.io_wq_queue_total_ns;
        if (row->value.maximum_ns > summary->maximum_ns)
            summary->maximum_ns = row->value.maximum_ns;
        if (row->value.io_wq_queue_maximum_ns >
            summary->io_wq_queue_maximum_ns)
            summary->io_wq_queue_maximum_ns =
                row->value.io_wq_queue_maximum_ns;
    }
    free(aggregates);

    result_count = read_io_uring_results(output, &results);
    for (index = 0; index < result_count; index++) {
        const struct io_uring_result_row *row = &results[index];
        struct io_uring_operation_summary *summary;

        if (row->key.opcode >= 256)
            continue;
        summary = &summaries[row->key.opcode];
        if (io_uring_result_is_expected_timeout(&row->key)) {
            summary->expected_timeouts += row->count;
        } else if (row->key.result < 0 &&
                   row->count > summary->top_error_count) {
            summary->top_error_result = row->key.result;
            summary->top_error_count = row->count;
        }
    }
    free(results);
}

static double io_uring_error_rate(uint64_t errors, uint64_t completions)
{
    if (!completions)
        return 0.0;
    return (double)errors * 100.0 / (double)completions;
}

static int compare_io_uring_error_code_summaries(
    const void *left, const void *right)
{
    const struct io_uring_error_code_summary *a = left;
    const struct io_uring_error_code_summary *b = right;

    if (a->count < b->count)
        return 1;
    if (a->count > b->count)
        return -1;
    if (a->result > b->result)
        return 1;
    if (a->result < b->result)
        return -1;
    return 0;
}

static size_t collect_io_uring_error_codes(
    const struct output_options *output,
    struct io_uring_error_code_summary **summaries)
{
    struct io_uring_result_row *rows = NULL;
    struct io_uring_error_code_summary *items = NULL;
    size_t row_count = read_io_uring_results(output, &rows);
    size_t capacity = 0;
    size_t count = 0;
    size_t row_index;

    *summaries = NULL;
    for (row_index = 0; row_index < row_count; row_index++) {
        const struct io_uring_result_row *row = &rows[row_index];
        size_t index;

        if (row->key.result >= 0 ||
            io_uring_result_is_expected_timeout(&row->key))
            continue;
        for (index = 0; index < count; index++) {
            if (items[index].result == row->key.result) {
                items[index].count += row->count;
                break;
            }
        }
        if (index < count)
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].result = row->key.result;
        items[count].count = row->count;
        count++;
    }
    free(rows);
    if (count > 1)
        qsort(items, count, sizeof(*items),
              compare_io_uring_error_code_summaries);
    *summaries = items;
    return count;
}

static size_t read_io_uring_ring_rows(
    const struct output_options *output,
    struct io_uring_ring_row **rows)
{
    struct io_uring_ring_row *items = NULL;
    uint64_t current = 0;
    uint64_t next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_ring_stats_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_ring_stats_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_ring_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(
                output->io_uring_ring_stats_map_fd,
                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].ring_ctx = next;
        items[count].value = value;
        count++;
    }
    *rows = items;
    return count;
}

static size_t read_io_uring_failure_rows(
    const struct output_options *output,
    struct io_uring_failure_row **rows)
{
    struct io_uring_failure_row *items = NULL;
    struct io_uring_failure_key current = {0};
    struct io_uring_failure_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_failure_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_failure_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_failure_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_failure_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].value = value;
        count++;
    }
    *rows = items;
    return count;
}

static size_t read_io_uring_link_rows(
    const struct output_options *output,
    struct io_uring_link_row **rows)
{
    struct io_uring_link_row *items = NULL;
    struct io_uring_link_key current = {0};
    struct io_uring_link_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_link_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_link_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_link_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_link_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].value = value;
        count++;
    }
    *rows = items;
    return count;
}

static void format_io_uring_setup_flags(
    uint32_t flags, char *buffer, size_t size)
{
    bool first = true;

    if (!size)
        return;
    buffer[0] = '\0';
#define APPEND_RING_FLAG(flag, name)                                      \
    do {                                                                 \
        if (flags & (flag)) {                                            \
            snprintf(buffer + strlen(buffer), size - strlen(buffer),     \
                     "%s%s", first ? "" : "|", (name));                  \
            first = false;                                               \
        }                                                                \
    } while (0)
    APPEND_RING_FLAG(IORING_SETUP_SQPOLL, "SQPOLL");
    APPEND_RING_FLAG(IORING_SETUP_IOPOLL, "IOPOLL");
    APPEND_RING_FLAG(IORING_SETUP_ATTACH_WQ, "ATTACH_WQ");
    APPEND_RING_FLAG(IORING_SETUP_DEFER_TASKRUN, "DEFER_TASKRUN");
    APPEND_RING_FLAG(IORING_SETUP_SINGLE_ISSUER, "SINGLE_ISSUER");
    APPEND_RING_FLAG(IORING_SETUP_COOP_TASKRUN, "COOP_TASKRUN");
#undef APPEND_RING_FLAG
    if (first)
        snprintf(buffer, size, "default");
}

static void print_io_uring_diagnostic_sections(
    const struct output_options *output, FILE *stream,
    const struct io_uring_counters *counters)
{
    struct io_uring_ring_row *rings = NULL;
    struct io_uring_failure_row *failures = NULL;
    struct io_uring_link_row *links = NULL;
    size_t ring_count = read_io_uring_ring_rows(output, &rings);
    size_t failure_count =
        read_io_uring_failure_rows(output, &failures);
    size_t link_count = read_io_uring_link_rows(output, &links);
    uint64_t rejected_sqe_count = 0;
    size_t failure_limit;
    size_t link_limit = 0;
    size_t index;

    for (index = 0; index < failure_count; index++)
        rejected_sqe_count += failures[index].value.count;

    fprintf(stream,
            "\n[3] Application errors\n"
            "  These are errors observed in the target application, "
            "not callweave collection failures.\n"
            "  CQE execution errors : %llu (%.2f%% of completions)\n"
            "  Kernel-rejected SQEs : %llu\n"
            "  Expected timeouts    : %llu (reported separately, not errors)\n",
            (unsigned long long)counters->errors,
            io_uring_error_rate(counters->errors,
                                counters->completions),
            (unsigned long long)rejected_sqe_count,
            (unsigned long long)counters->expected_timeouts);
    if (failure_count) {
        failure_limit = failure_count < 10 ? failure_count : 10;
        fprintf(stream,
                "\n  Rejected SQE details "
                "(application submitted invalid/unsupported input)\n"
                "  %-18s %-14s %8s %18s %18s\n"
                "  %-18s %-14s %8s %18s %18s\n",
                "OPERATION", "KERNEL ERROR", "COUNT",
                "RING", "SAMPLE USER_DATA",
                "------------------", "--------------", "--------",
                "------------------", "------------------");
        for (index = 0; index < failure_limit; index++) {
            const struct io_uring_failure_row *row = &failures[index];
            int error_number = row->key.error < 0 ?
                -row->key.error : row->key.error;
            char operation[32];
            char error_text[32];

            snprintf(operation, sizeof(operation), "%s(%u)",
                     cw_io_uring_opcode_name((uint8_t)row->key.opcode),
                     row->key.opcode);
            snprintf(error_text, sizeof(error_text), "%s(%d)",
                     errno_symbol(error_number), row->key.error);
            fprintf(stream,
                    "  %-18s %-14s %8llu 0x%016llx 0x%016llx\n"
                    "    sample SQE: len=%u off=%llu flags=0x%x "
                    "op_flags=0x%x buf=%u file_index=%u\n",
                    operation, error_text,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->key.ring_ctx,
                    (unsigned long long)row->value.user_data,
                    row->value.length,
                    (unsigned long long)row->value.offset,
                    row->value.sqe_flags,
                    row->value.operation_flags,
                    row->value.buffer_index,
                    row->value.file_index);
        }
        if (failure_count > failure_limit)
            fprintf(stream, "  ... %zu additional failure groups omitted\n",
                    failure_count - failure_limit);
    } else {
        fprintf(stream, "  Rejected SQE details: none observed\n");
    }

    fprintf(stream, "\n[4] Ring and queue health\n");
    if (!ring_count)
        fprintf(stream, "  No ring metadata was observed.\n");
    for (index = 0; index < ring_count; index++) {
        const struct io_uring_ring_stats *ring = &rings[index].value;
        char flags[128];
        char average[32];
        char maximum[32];
        char queue_average[32];
        char queue_maximum[32];
        const char *diagnosis = "healthy";

        format_io_uring_setup_flags(ring->flags, flags, sizeof(flags));
        format_interval(
            average, sizeof(average),
            ring->completions ?
                ring->total_ns / ring->completions : 0);
        format_interval(maximum, sizeof(maximum), ring->maximum_ns);
        format_interval(
            queue_average, sizeof(queue_average),
            ring->io_wq ?
                ring->io_wq_queue_total_ns / ring->io_wq : 0);
        format_interval(queue_maximum, sizeof(queue_maximum),
                        ring->io_wq_queue_maximum_ns);
        if (ring->cq_overflows)
            diagnosis = "CQ overflow / consumer too slow";
        else if (ring->io_wq_queue_maximum_ns >
                 ring->maximum_ns / 2 && ring->io_wq)
            diagnosis = "io-wq queue congestion";
        else if (ring->errors &&
                 io_uring_error_rate(ring->errors,
                                     ring->completions) >= 5.0)
            diagnosis = "high application CQE error rate";
        fprintf(stream, "  Ring %zu\n", index + 1);
        if (ring->ring_fd >= 0)
            fprintf(stream,
                    "    identity : ctx=0x%016llx fd=%d owner-pid=%u\n",
                    (unsigned long long)rings[index].ring_ctx,
                    ring->ring_fd, ring->owner_pid);
        else
            fprintf(stream,
                    "    identity : ctx=0x%016llx fd=unknown "
                    "owner-pid=%u\n",
                    (unsigned long long)rings[index].ring_ctx,
                    ring->owner_pid);
        fprintf(stream,
                "    setup    : sq=%u cq=%u flags=%s\n"
                "    load     : submitted=%llu completed=%llu "
                "pending=%llu peak-pending=%llu\n"
                "    latency  : average=%s maximum=%s\n",
                ring->sq_entries, ring->cq_entries, flags,
                (unsigned long long)ring->submitted,
                (unsigned long long)ring->completions,
                (unsigned long long)ring->pending,
                (unsigned long long)ring->peak_pending,
                average, maximum);
        fprintf(stream,
                "    path     : deferred=%llu io-wq=%llu hashed=%llu "
                "poll-armed=%llu\n"
                "    io-wq    : queue-average=%s queue-maximum=%s\n",
                (unsigned long long)ring->deferred,
                (unsigned long long)ring->io_wq,
                (unsigned long long)ring->io_wq_hashed,
                (unsigned long long)ring->poll_armed,
                queue_average, queue_maximum);
        fprintf(stream,
                "    cq       : waits=%llu overflows=%llu\n"
                "    app      : cqe-errors=%llu rejected-sqes=%llu "
                "links=%llu failed-links=%llu\n"
                "    diagnosis: %s\n",
                (unsigned long long)ring->cq_waits,
                (unsigned long long)ring->cq_overflows,
                (unsigned long long)ring->errors,
                (unsigned long long)ring->request_failures,
                (unsigned long long)ring->links,
                (unsigned long long)ring->failed_links,
                diagnosis);
    }

    fprintf(stream, "\n[5] Linked request chains\n");
    if (!link_count) {
        fprintf(stream, "  No linked requests were observed.\n");
    } else {
        link_limit = link_count < 10 ? link_count : 10;
        fprintf(stream,
                "  Showing %zu of %zu observed edge%s. "
                "These are application request dependencies.\n",
                link_limit, link_count, link_count == 1 ? "" : "s");
    }
    for (index = 0; index < link_count && index < link_limit; index++) {
        const struct io_uring_link_row *row = &links[index];

        fprintf(stream,
                "  [%2zu] %s user_data=0x%llx"
                " -> %s user_data=0x%llx%s\n"
                "       req=0x%llx -> req=0x%llx\n",
                index + 1,
                cw_io_uring_opcode_name(row->value.parent_opcode),
                (unsigned long long)row->key.parent_user_data,
                cw_io_uring_opcode_name(row->value.child_opcode),
                (unsigned long long)row->key.child_user_data,
                row->value.failures ? " [link failed/cancelled]" : "",
                (unsigned long long)row->value.parent_request,
                (unsigned long long)row->value.child_request);
    }
    if (link_count > link_limit)
        fprintf(stream, "  ... %zu additional edges omitted\n",
                link_count - link_limit);
    free(rings);
    free(failures);
    free(links);
}

static void print_io_uring_aggregates(struct output_options *output,
                                      FILE *stream)
{
    struct io_uring_aggregate_row *rows = NULL;
    size_t count = read_io_uring_aggregates(output, &rows);
    size_t limit = count;
    size_t index;

    fprintf(stream, "\n[6] Slowest submit groups\n");
    if (!output->io_uring_top) {
        fprintf(stream,
                "  Disabled. Use --io-top N to include Top-N groups.\n");
        free(rows);
        return;
    }
    if (!count) {
        fprintf(stream, "  No completed request groups were observed.\n");
        free(rows);
        return;
    }
    if (limit > output->io_uring_top)
        limit = output->io_uring_top;
    fprintf(stream,
            "  Top %zu by maximum SQE-to-CQE latency\n",
            limit);
    for (index = 0; index < limit; index++) {
        const struct io_uring_aggregate_row *row = &rows[index];
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        size_t duplicate_index;
        char operation[32];
        char average[32];
        char maximum[32];
        char resource[PATH_MAX];

        if (force_exit)
            break;
        snprintf(operation, sizeof(operation), "%s(%u)",
                 cw_io_uring_opcode_name((uint8_t)row->key.opcode),
                 row->key.opcode);
        format_interval(
            average, sizeof(average),
            row->value.count ?
                row->value.total_ns / row->value.count : 0);
        format_interval(maximum, sizeof(maximum),
                        row->value.maximum_ns);
        cw_io_uring_resolve_fd_resource(
            output, row->key.fd, resource, sizeof(resource));
        fprintf(stream,
                "  [%2zu] %-20s ring=0x%llx fd=%-4d count=%-8llu "
                "errors=%-6llu avg=%-12s max=%-12s",
                index + 1,
                operation,
                (unsigned long long)row->key.ring_ctx,
                row->key.fd,
                (unsigned long long)row->value.count,
                (unsigned long long)row->value.errors,
                average, maximum);
        if (output->io_uring_min_latency_ns)
            fprintf(stream, " slow=%-8llu",
                    (unsigned long long)row->value.slow_count);
        if (resource[0])
            fprintf(stream, "\n       resource: %s", resource);
        if (row->value.deferred_count || row->value.io_wq_count) {
            char queue_average[32];
            char queue_maximum[32];

            format_interval(
                queue_average, sizeof(queue_average),
                row->value.io_wq_count ?
                    row->value.io_wq_queue_total_ns /
                        row->value.io_wq_count : 0);
            format_interval(
                queue_maximum, sizeof(queue_maximum),
                row->value.io_wq_queue_maximum_ns);
            fprintf(stream,
                    "\n       phases: deferred=%llu io-wq=%llu "
                    "io-wq-queue-avg=%s max=%s",
                    (unsigned long long)row->value.deferred_count,
                    (unsigned long long)row->value.io_wq_count,
                    queue_average, queue_maximum);
        }
        fprintf(stream, "\n       submit stack:\n");
        duplicate_index = index;
        if (row->key.stack_id >= 0) {
            size_t previous;

            for (previous = 0; previous < index; previous++) {
                if (rows[previous].key.stack_id ==
                    row->key.stack_id) {
                    duplicate_index = previous;
                    break;
                }
            }
        }
        if (duplicate_index < index) {
            fprintf(stream,
                    "         same as group [%zu] (stack_id=%d)\n",
                    duplicate_index + 1, row->key.stack_id);
        } else if (row->key.stack_id < 0 ||
            output->io_uring_stack_map_fd < 0 ||
            bpf_map_lookup_elem(output->io_uring_stack_map_fd,
                                &row->key.stack_id, stack)) {
            if (row->key.stack_id < 0)
                fprintf(stream,
                        "         capture unavailable (stack_id=%d)\n",
                        row->key.stack_id);
            else
                fprintf(stream, "         unavailable\n");
        } else if (output->io_uring_maps) {
            print_stack_frames(stack, sizeof(stack),
                               output->io_uring_maps,
                               "       ", NULL, NULL, 0);
        } else {
            fprintf(stream, "         submitter maps unavailable\n");
        }
    }
    free(rows);
}

bool cw_io_uring_print_summary(struct output_options *output)
{
    struct io_uring_counters counters = {0};
    struct io_uring_operation_summary summaries[256];
    FILE *stream = output->json_output ? stderr : stdout;
    uint32_t zero = 0;
    size_t opcode;

    if (output->io_uring_counters_map_fd < 0 ||
        bpf_map_lookup_elem(output->io_uring_counters_map_fd,
                            &zero, &counters))
        return false;

    collect_io_uring_operation_summaries(output, summaries);
    if (output->json_output) {
        fprintf(stream,
                "\nio_uring capture stopped: accepted=%llu "
                "completed=%llu errors=%llu rejected/unmatched=%llu "
                "dropped=%llu; structured summary written to JSON output\n",
                (unsigned long long)counters.submitted,
                (unsigned long long)counters.completions,
                (unsigned long long)counters.errors,
                (unsigned long long)counters.unmatched,
                (unsigned long long)counters.dropped_events);
        return true;
    }
    fprintf(stream,
            "\nio_uring summary\n"
            "\n[1] Capture overview\n"
            "  Accepted requests  : %llu\n"
            "  Completion events  : %llu\n"
            "  Finished requests  : %llu\n"
            "  Detailed records   : %u"
            " (after detail filters)\n"
            "  In flight at stop  : %llu\n"
            "  Peak in flight     : %llu\n",
            (unsigned long long)counters.submitted,
            (unsigned long long)counters.completions,
            (unsigned long long)counters.finished,
            output->emitted_events,
            (unsigned long long)counters.pending,
            (unsigned long long)counters.peak_pending);
    fprintf(stream,
            "\n[2] Operation latency and CQE results\n"
            "  %-20s %8s %8s %9s %9s %12s %12s  %s\n",
            "OPERATION", "CQEs", "CQE ERR", "ERR RATE",
            "TIMEOUTS", "AVG", "MAX", "TOP CQE ERROR");
    fprintf(stream,
            "  %-20s %8s %8s %9s %9s %12s %12s  %s\n",
            "--------------------", "--------", "--------",
            "---------", "---------", "------------",
            "------------", "--------------------");
    for (opcode = 0; opcode < 256; opcode++) {
        const struct io_uring_operation_summary *summary =
            &summaries[opcode];
        char operation[32];
        char error_rate[32];
        char average[32];
        char maximum[32];
        char top_error[64] = "-";

        if (!summary->completions)
            continue;
        snprintf(operation, sizeof(operation), "%s(%zu)",
                 cw_io_uring_opcode_name((uint8_t)opcode), opcode);
        snprintf(error_rate, sizeof(error_rate), "%.2f%%",
                 io_uring_error_rate(summary->errors,
                                     summary->completions));
        format_interval(average, sizeof(average),
                        summary->total_ns / summary->completions);
        format_interval(maximum, sizeof(maximum),
                        summary->maximum_ns);
        if (summary->top_error_count) {
            int error_number = -summary->top_error_result;

            snprintf(top_error, sizeof(top_error), "%s(%d) x%llu",
                     errno_symbol(error_number),
                     summary->top_error_result,
                     (unsigned long long)summary->top_error_count);
        }
        fprintf(stream,
                "  %-20s %8llu %8llu %9s %9llu %12s %12s  %s\n",
                operation,
                (unsigned long long)summary->completions,
                (unsigned long long)summary->errors,
                error_rate,
                (unsigned long long)summary->expected_timeouts,
                average, maximum, top_error);
        if (summary->deferred || summary->io_wq) {
            char queue_average[32];
            char queue_maximum[32];

            format_interval(
                queue_average, sizeof(queue_average),
                summary->io_wq ?
                    summary->io_wq_queue_total_ns /
                        summary->io_wq : 0);
            format_interval(
                queue_maximum, sizeof(queue_maximum),
                summary->io_wq_queue_maximum_ns);
            fprintf(stream,
                    "    phases: deferred=%llu io-wq=%llu "
                    "io-wq-queue avg=%s max=%s\n",
                    (unsigned long long)summary->deferred,
                    (unsigned long long)summary->io_wq,
                    queue_average, queue_maximum);
        }
    }
    if (!output->json_output)
        print_io_uring_diagnostic_sections(output, stream, &counters);
    if (!output->json_output)
        print_io_uring_aggregates(output, stream);
    if (!output->json_output) {
        fprintf(stream,
                "\n[7] Correlation and collector health\n"
                "  Request correlation : unmatched completions=%llu\n"
                "  Event transport     : dropped detail events=%llu\n",
                (unsigned long long)counters.unmatched,
                (unsigned long long)counters.dropped_events);
        if (output->io_uring_callback_name)
            fprintf(stream,
                    "  Callback correlation: matched=%llu "
                    "unmatched=%llu dropped=%llu\n",
                    (unsigned long long)counters.callback_matched,
                    (unsigned long long)counters.callback_unmatched,
                    (unsigned long long)counters.callback_dropped);
        if (counters.unmatched ||
            counters.callback_unmatched)
            fprintf(stream,
                    "  Note: kernel-rejected SQEs can increase unmatched "
                    "counts because they never reach io_uring_submit_req; "
                    "see [3].\n");
        if (!counters.dropped_events &&
            !counters.callback_dropped)
            fprintf(stream,
                    "  Collector status    : no ring-buffer event loss "
                    "observed\n");
    }
    return true;
}

int cw_io_uring_write_summary_json(struct output_options *output)
{
    struct io_uring_counters counters = {0};
    struct io_uring_operation_summary summaries[256];
    struct io_uring_aggregate_row *rows = NULL;
    struct io_uring_error_code_summary *error_codes = NULL;
    size_t aggregate_count;
    size_t aggregate_limit;
    size_t aggregate_index;
    size_t error_code_count;
    size_t error_code_index;
    uint32_t zero = 0;
    size_t opcode;
    bool first = true;

    if (!output->json_stream ||
        output->io_uring_counters_map_fd < 0 ||
        bpf_map_lookup_elem(output->io_uring_counters_map_fd,
                            &zero, &counters))
        return 0;
    collect_io_uring_operation_summaries(output, summaries);
    if (fprintf(output->json_stream,
                "{\"type\":\"io_uring_summary\","
                "\"displayed\":%u,\"submitted\":%llu,"
                "\"completions\":%llu,"
                "\"finished\":%llu,\"pending\":%llu,"
                "\"peak_pending\":%llu,\"unmatched\":%llu,"
                "\"dropped_events\":%llu,\"errors\":%llu,"
                "\"error_rate_percent\":%.6f,"
                "\"expected_timeouts\":%llu,"
                "\"callback_matched\":%llu,"
                "\"callback_unmatched\":%llu,"
                "\"callback_dropped\":%llu,"
                "\"operations\":[",
                output->emitted_events,
                (unsigned long long)counters.submitted,
                (unsigned long long)counters.completions,
                (unsigned long long)counters.finished,
                (unsigned long long)counters.pending,
                (unsigned long long)counters.peak_pending,
                (unsigned long long)counters.unmatched,
                (unsigned long long)counters.dropped_events,
                (unsigned long long)counters.errors,
                io_uring_error_rate(counters.errors,
                                    counters.completions),
                (unsigned long long)counters.expected_timeouts,
                (unsigned long long)counters.callback_matched,
                (unsigned long long)counters.callback_unmatched,
                (unsigned long long)counters.callback_dropped) < 0)
        return -1;
    for (opcode = 0; opcode < 256; opcode++) {
        const struct io_uring_operation_summary *summary =
            &summaries[opcode];
        const char *name;

        if (!summary->completions)
            continue;
        name = cw_io_uring_opcode_name((uint8_t)opcode);
        if ((!first && fputc(',', output->json_stream) == EOF) ||
            fprintf(output->json_stream,
                    "{\"opcode\":%zu,\"operation\":", opcode) < 0 ||
            cw_io_uring_write_json_string(output->json_stream, name, strlen(name)) ||
            fprintf(output->json_stream,
                    ",\"completions\":%llu,\"errors\":%llu,"
                    "\"error_rate_percent\":%.6f,"
                    "\"expected_timeouts\":%llu,"
                    "\"average_ns\":%llu,\"maximum_ns\":%llu,"
                    "\"deferred\":%llu,\"io_wq\":%llu,"
                    "\"io_wq_queue_average_ns\":%llu,"
                    "\"io_wq_queue_maximum_ns\":%llu,"
                    "\"top_error_result\":%d,"
                    "\"top_error_count\":%llu}",
                    (unsigned long long)summary->completions,
                    (unsigned long long)summary->errors,
                    io_uring_error_rate(summary->errors,
                                        summary->completions),
                    (unsigned long long)summary->expected_timeouts,
                    (unsigned long long)
                        (summary->total_ns / summary->completions),
                    (unsigned long long)summary->maximum_ns,
                    (unsigned long long)summary->deferred,
                    (unsigned long long)summary->io_wq,
                    (unsigned long long)
                        (summary->io_wq ?
                             summary->io_wq_queue_total_ns /
                                 summary->io_wq : 0),
                    (unsigned long long)
                        summary->io_wq_queue_maximum_ns,
                    summary->top_error_result,
                    (unsigned long long)summary->top_error_count) < 0)
            return -1;
        first = false;
    }
    if (fputs("],\"error_codes\":[", output->json_stream) == EOF)
        return -1;
    error_code_count =
        collect_io_uring_error_codes(output, &error_codes);
    for (error_code_index = 0;
         error_code_index < error_code_count; error_code_index++) {
        const struct io_uring_error_code_summary *summary =
            &error_codes[error_code_index];
        int error_number;
        const char *symbol;

        error_number = -summary->result;
        symbol = errno_symbol(error_number);
        if ((error_code_index &&
             fputc(',', output->json_stream) == EOF) ||
            fprintf(output->json_stream,
                    "{\"result\":%d,\"errno\":%d,\"name\":",
                    summary->result, error_number) < 0 ||
            cw_io_uring_write_json_string(output->json_stream, symbol,
                              strlen(symbol)) ||
            fputs(",\"message\":", output->json_stream) == EOF ||
            cw_io_uring_write_json_string(output->json_stream,
                              strerror(error_number),
                              strlen(strerror(error_number))) ||
            fprintf(output->json_stream, ",\"count\":%llu}",
                    (unsigned long long)summary->count) < 0) {
            free(error_codes);
            return -1;
        }
    }
    free(error_codes);
    if (fputs("],\"aggregates\":[", output->json_stream) == EOF)
        return -1;
    aggregate_count = read_io_uring_aggregates(output, &rows);
    aggregate_limit = aggregate_count;
    if (aggregate_limit > output->io_uring_top)
        aggregate_limit = output->io_uring_top;
    for (aggregate_index = 0;
         aggregate_index < aggregate_limit; aggregate_index++) {
        const struct io_uring_aggregate_row *row =
            &rows[aggregate_index];
        const char *name =
            cw_io_uring_opcode_name((uint8_t)row->key.opcode);
        char resource[PATH_MAX];

        cw_io_uring_resolve_fd_resource(
            output, row->key.fd, resource, sizeof(resource));
        if ((aggregate_index &&
             fputc(',', output->json_stream) == EOF) ||
            fprintf(output->json_stream,
                    "{\"rank\":%zu,\"opcode\":%u,\"operation\":",
                    aggregate_index + 1, row->key.opcode) < 0 ||
            cw_io_uring_write_json_string(output->json_stream, name,
                              strlen(name)) ||
            fprintf(output->json_stream,
                    ",\"ring_ctx\":\"0x%016llx\","
                    "\"fd\":%d,\"stack_id\":%d,"
                    "\"count\":%llu,\"errors\":%llu,"
                    "\"slow_count\":%llu,\"average_ns\":%llu,"
                    "\"maximum_ns\":%llu,\"deferred\":%llu,"
                    "\"io_wq\":%llu,"
                    "\"io_wq_queue_average_ns\":%llu,"
                    "\"io_wq_queue_maximum_ns\":%llu,"
                    "\"resource\":",
                    (unsigned long long)row->key.ring_ctx,
                    row->key.fd, row->key.stack_id,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->value.errors,
                    (unsigned long long)row->value.slow_count,
                    (unsigned long long)
                        (row->value.count ?
                             row->value.total_ns / row->value.count : 0),
                    (unsigned long long)row->value.maximum_ns,
                    (unsigned long long)row->value.deferred_count,
                    (unsigned long long)row->value.io_wq_count,
                    (unsigned long long)
                        (row->value.io_wq_count ?
                             row->value.io_wq_queue_total_ns /
                                 row->value.io_wq_count : 0),
                    (unsigned long long)
                        row->value.io_wq_queue_maximum_ns) < 0 ||
            cw_io_uring_write_json_string(output->json_stream, resource,
                              strlen(resource)) ||
            fputc('}', output->json_stream) == EOF) {
            free(rows);
            return -1;
        }
    }
    free(rows);
    {
        struct io_uring_ring_row *rings = NULL;
        size_t count = read_io_uring_ring_rows(output, &rings);
        size_t index;

        if (fputs("],\"rings\":[", output->json_stream) == EOF) {
            free(rings);
            return -1;
        }
        for (index = 0; index < count; index++) {
            const struct io_uring_ring_stats *ring =
                &rings[index].value;

            if ((index &&
                 fputc(',', output->json_stream) == EOF) ||
                fprintf(
                    output->json_stream,
                    "{\"ring_ctx\":\"0x%016llx\",\"owner_pid\":%u,"
                    "\"fd\":%d,\"flags\":%u,\"sq_entries\":%u,"
                    "\"cq_entries\":%u,\"submitted\":%llu,"
                    "\"completions\":%llu,\"pending\":%llu,"
                    "\"peak_pending\":%llu,\"errors\":%llu,"
                    "\"expected_timeouts\":%llu,\"average_ns\":%llu,"
                    "\"maximum_ns\":%llu,\"deferred\":%llu,"
                    "\"io_wq\":%llu,\"io_wq_hashed\":%llu,"
                    "\"io_wq_queue_average_ns\":%llu,"
                    "\"io_wq_queue_maximum_ns\":%llu,"
                    "\"poll_armed\":%llu,\"cq_waits\":%llu,"
                    "\"cq_overflows\":%llu,\"request_failures\":%llu,"
                    "\"links\":%llu,\"failed_links\":%llu,"
                    "\"registrations\":%llu,"
                    "\"registered_files\":%u,"
                    "\"registered_buffers\":%u}",
                    (unsigned long long)rings[index].ring_ctx,
                    ring->owner_pid, ring->ring_fd, ring->flags,
                    ring->sq_entries, ring->cq_entries,
                    (unsigned long long)ring->submitted,
                    (unsigned long long)ring->completions,
                    (unsigned long long)ring->pending,
                    (unsigned long long)ring->peak_pending,
                    (unsigned long long)ring->errors,
                    (unsigned long long)ring->expected_timeouts,
                    (unsigned long long)
                        (ring->completions ?
                             ring->total_ns / ring->completions : 0),
                    (unsigned long long)ring->maximum_ns,
                    (unsigned long long)ring->deferred,
                    (unsigned long long)ring->io_wq,
                    (unsigned long long)ring->io_wq_hashed,
                    (unsigned long long)
                        (ring->io_wq ?
                             ring->io_wq_queue_total_ns /
                                 ring->io_wq : 0),
                    (unsigned long long)
                        ring->io_wq_queue_maximum_ns,
                    (unsigned long long)ring->poll_armed,
                    (unsigned long long)ring->cq_waits,
                    (unsigned long long)ring->cq_overflows,
                    (unsigned long long)ring->request_failures,
                    (unsigned long long)ring->links,
                    (unsigned long long)ring->failed_links,
                    (unsigned long long)ring->registrations,
                    ring->registered_files,
                    ring->registered_buffers) < 0) {
                free(rings);
                return -1;
            }
        }
        free(rings);
    }
    {
        struct io_uring_failure_row *failures = NULL;
        size_t count =
            read_io_uring_failure_rows(output, &failures);
        size_t index;

        if (fputs("],\"submission_failures\":[",
                  output->json_stream) == EOF) {
            free(failures);
            return -1;
        }
        for (index = 0; index < count; index++) {
            const struct io_uring_failure_row *row =
                &failures[index];

            if ((index &&
                 fputc(',', output->json_stream) == EOF) ||
                fprintf(
                    output->json_stream,
                    "{\"ring_ctx\":\"0x%016llx\",\"opcode\":%u,"
                    "\"operation\":",
                    (unsigned long long)row->key.ring_ctx,
                    row->key.opcode) < 0 ||
                cw_io_uring_write_json_string(
                    output->json_stream,
                    cw_io_uring_opcode_name(
                        (uint8_t)row->key.opcode),
                    strlen(cw_io_uring_opcode_name(
                        (uint8_t)row->key.opcode))) ||
                fprintf(
                    output->json_stream,
                    ",\"error\":%d,\"count\":%llu,"
                    "\"user_data\":\"0x%016llx\",\"offset\":%llu,"
                    "\"address\":\"0x%016llx\","
                    "\"address3\":\"0x%016llx\",\"length\":%u,"
                    "\"operation_flags\":%u,\"file_index\":%u,"
                    "\"buffer_index\":%u,\"sqe_flags\":%u,"
                    "\"ioprio\":%u}",
                    row->key.error,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->value.user_data,
                    (unsigned long long)row->value.offset,
                    (unsigned long long)row->value.address,
                    (unsigned long long)row->value.address3,
                    row->value.length,
                    row->value.operation_flags,
                    row->value.file_index,
                    row->value.buffer_index,
                    row->value.sqe_flags,
                    row->value.ioprio) < 0) {
                free(failures);
                return -1;
            }
        }
        free(failures);
    }
    {
        struct io_uring_link_row *links = NULL;
        size_t count = read_io_uring_link_rows(output, &links);
        size_t index;

        if (fputs("],\"links\":[", output->json_stream) == EOF) {
            free(links);
            return -1;
        }
        for (index = 0; index < count; index++) {
            const struct io_uring_link_row *row = &links[index];

            if ((index &&
                 fputc(',', output->json_stream) == EOF) ||
                fprintf(
                    output->json_stream,
                    "{\"ring_ctx\":\"0x%016llx\","
                    "\"parent_request\":\"0x%016llx\","
                    "\"parent_user_data\":\"0x%016llx\","
                    "\"parent_opcode\":%u,"
                    "\"child_request\":\"0x%016llx\","
                    "\"child_user_data\":\"0x%016llx\","
                    "\"child_opcode\":%u,\"count\":%llu,"
                    "\"failures\":%llu}",
                    (unsigned long long)row->key.ring_ctx,
                    (unsigned long long)row->value.parent_request,
                    (unsigned long long)row->key.parent_user_data,
                    row->value.parent_opcode,
                    (unsigned long long)row->value.child_request,
                    (unsigned long long)row->key.child_user_data,
                    row->value.child_opcode,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->value.failures) < 0) {
                free(links);
                return -1;
            }
        }
        free(links);
    }
    return fputs("]}\n", output->json_stream) == EOF ? -1 : 0;
}
