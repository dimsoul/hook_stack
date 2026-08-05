// SPDX-License-Identifier: MIT

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>

#include "callweave_internal.h"
#include "core/fd_resources.h"
#include "epoll/epoll.h"
#include "epoll/epoll_internal.h"

struct cw_epoll_loop_row {
    struct cw_epoll_loop_key key;
    struct cw_epoll_loop_stats value;
};

struct cw_epoll_resource_row {
    struct cw_epoll_resource_key key;
    struct cw_epoll_resource_stats value;
};

struct cw_epoll_instance_row {
    struct cw_epoll_instance_key key;
    struct cw_epoll_instance_stats value;
};

static int compare_loop_rows(const void *left, const void *right)
{
    const struct cw_epoll_loop_row *a = left;
    const struct cw_epoll_loop_row *b = right;

    if (a->value.ready_events < b->value.ready_events)
        return 1;
    if (a->value.ready_events > b->value.ready_events)
        return -1;
    if (a->value.calls < b->value.calls)
        return 1;
    if (a->value.calls > b->value.calls)
        return -1;
    return 0;
}

static int compare_resource_rows(const void *left, const void *right)
{
    const struct cw_epoll_resource_row *a = left;
    const struct cw_epoll_resource_row *b = right;

    if (a->value.ready_count < b->value.ready_count)
        return 1;
    if (a->value.ready_count > b->value.ready_count)
        return -1;
    return 0;
}

static int compare_callback_rows(const void *left, const void *right)
{
    const struct cw_epoll_resource_row *a = left;
    const struct cw_epoll_resource_row *b = right;

    if (a->value.callback_maximum_duration_ns <
        b->value.callback_maximum_duration_ns)
        return 1;
    if (a->value.callback_maximum_duration_ns >
        b->value.callback_maximum_duration_ns)
        return -1;
    if (a->value.callback_completed <
        b->value.callback_completed)
        return 1;
    if (a->value.callback_completed >
        b->value.callback_completed)
        return -1;
    return 0;
}

static size_t read_loop_rows(
    const struct output_options *output,
    struct cw_epoll_loop_row **rows)
{
    struct cw_epoll_loop_row *items = NULL;
    struct cw_epoll_loop_key current = {0};
    struct cw_epoll_loop_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->epoll_loop_stats_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->epoll_loop_stats_map_fd,
               have_current ? &current : NULL, &next)) {
        struct cw_epoll_loop_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->epoll_loop_stats_map_fd,
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
        items[count].value = value;
        count++;
    }
    if (count > 1)
        qsort(items, count, sizeof(*items), compare_loop_rows);
    *rows = items;
    return count;
}

static size_t read_resource_rows(
    const struct output_options *output,
    struct cw_epoll_resource_row **rows)
{
    struct cw_epoll_resource_row *items = NULL;
    struct cw_epoll_resource_key current = {0};
    struct cw_epoll_resource_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->epoll_resource_stats_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->epoll_resource_stats_map_fd,
               have_current ? &current : NULL, &next)) {
        struct cw_epoll_resource_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->epoll_resource_stats_map_fd,
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
        qsort(items, count, sizeof(*items), compare_resource_rows);
    *rows = items;
    return count;
}

static size_t read_instance_rows(
    const struct output_options *output,
    struct cw_epoll_instance_row **rows)
{
    struct cw_epoll_instance_row *items = NULL;
    struct cw_epoll_instance_key current = {0};
    struct cw_epoll_instance_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->epoll_instance_stats_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->epoll_instance_stats_map_fd,
               have_current ? &current : NULL, &next)) {
        struct cw_epoll_instance_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(
                output->epoll_instance_stats_map_fd,
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

static uint32_t current_fd_generation(
    const struct output_options *output, uint32_t pid, int fd)
{
    struct cw_epoll_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    uint32_t generation = 1;

    if (output->epoll_fd_generation_map_fd >= 0)
        bpf_map_lookup_elem(
            output->epoll_fd_generation_map_fd,
            &key, &generation);
    return generation;
}

static const char *diagnose_loop(
    const struct cw_epoll_loop_stats *stats)
{
    uint64_t average_wait = stats->calls ?
        stats->total_wait_ns / stats->calls : 0;

    if (stats->potential_oneshot_missing_rearm)
        return "possible missing ONESHOT rearm";
    if (stats->potential_et_undrained)
        return "possible incomplete EPOLLET drain";
    if (stats->io_errors)
        return "I/O errors after readiness";
    if (stats->unconsumed)
        return "ready work handed off/unhandled";
    if (stats->errors)
        return "syscall errors";
    if (stats->calls >= 10 &&
        stats->saturated_batches * 5 >= stats->calls)
        return "batch capacity pressure";
    if (stats->calls >= 10 && average_wait < 100000 &&
        stats->timeouts * 2 >= stats->calls)
        return "empty/busy polling";
    if (stats->calls &&
        stats->timeouts * 4 >= stats->calls * 3)
        return "mostly idle/timeouts";
    if (stats->unresolved_events)
        return "opaque event.data";
    return "active";
}

static void print_loop_table(
    const struct cw_epoll_loop_row *rows, size_t count,
    FILE *stream)
{
    size_t index;

    fprintf(stream,
            "\n[2] Event loops\n"
            "  %-8s %-6s %8s %8s %8s %8s %12s %12s  %s\n",
            "TID", "EPFD", "WAITS", "READY", "TIMEOUT",
            "FULL", "AVG WAIT", "MAX WAIT", "DIAGNOSIS");
    fprintf(stream,
            "  %-8s %-6s %8s %8s %8s %8s %12s %12s  %s\n",
            "--------", "------", "--------", "--------",
            "--------", "--------", "------------",
            "------------", "----------------------");
    for (index = 0; index < count; index++) {
        const struct cw_epoll_loop_stats *stats = &rows[index].value;
        char average[32];
        char maximum[32];

        format_interval(
            average, sizeof(average),
            stats->calls ? stats->total_wait_ns / stats->calls : 0);
        format_interval(maximum, sizeof(maximum), stats->maximum_wait_ns);
        fprintf(stream,
                "  %-8u %-6d %8llu %8llu %8llu %8llu %12s %12s  %s\n",
                stats->tid, rows[index].key.epoll_fd,
                (unsigned long long)stats->calls,
                (unsigned long long)stats->ready_events,
                (unsigned long long)stats->timeouts,
                (unsigned long long)stats->saturated_batches,
                average, maximum, diagnose_loop(stats));
    }

    fprintf(stream,
            "\n[3] Event-loop cycle attribution\n"
            "  %-8s %-6s %8s %12s %12s %12s %12s %12s\n",
            "TID", "EPFD", "CYCLES", "AVG CYCLE",
            "AVG ONCPU", "BLOCKED", "RUN QUEUE", "PREEMPT/UNK");
    fprintf(stream,
            "  %-8s %-6s %8s %12s %12s %12s %12s %12s\n",
            "--------", "------", "--------", "------------",
            "------------", "------------", "------------",
            "------------");
    for (index = 0; index < count; index++) {
        const struct cw_epoll_loop_stats *stats = &rows[index].value;
        uint64_t average_cycle = stats->cycles ?
            stats->total_cycle_ns / stats->cycles : 0;
        uint64_t average_offcpu = stats->cycles ?
            stats->cycle_offcpu_ns / stats->cycles : 0;
        char cycle[32];
        char oncpu[32];
        char blocked[32];
        char runqueue[32];
        char unknown[32];
        uint64_t attributed_offcpu;

        format_interval(cycle, sizeof(cycle), average_cycle);
        format_interval(
            oncpu, sizeof(oncpu),
            average_cycle > average_offcpu ?
                average_cycle - average_offcpu : 0);
        format_interval(
            blocked, sizeof(blocked),
            stats->cycles ?
                stats->cycle_blocked_ns / stats->cycles : 0);
        format_interval(
            runqueue, sizeof(runqueue),
            stats->cycles ?
                stats->cycle_runqueue_ns / stats->cycles : 0);
        attributed_offcpu =
            stats->cycle_blocked_ns + stats->cycle_runqueue_ns;
        format_interval(
            unknown, sizeof(unknown),
            stats->cycles &&
            stats->cycle_offcpu_ns > attributed_offcpu ?
                (stats->cycle_offcpu_ns - attributed_offcpu) /
                    stats->cycles : 0);
        fprintf(stream,
                "  %-8u %-6d %8llu %12s %12s %12s %12s %12s\n",
                stats->tid, rows[index].key.epoll_fd,
                (unsigned long long)stats->cycles,
                cycle, oncpu, blocked, runqueue, unknown);
    }

    fprintf(stream,
            "\n[4] Ready-to-I/O dispatch health\n"
            "  %-8s %-6s %9s %10s %12s %12s %8s %8s %8s\n",
            "TID", "EPFD", "HANDLED", "UNHANDLED",
            "AVG DISPATCH", "MAX DISPATCH", "ET WARN",
            "1SHOT", "IO ERR");
    fprintf(stream,
            "  %-8s %-6s %9s %10s %12s %12s %8s %8s %8s\n",
            "--------", "------", "---------", "----------",
            "------------", "------------", "--------", "--------",
            "--------");
    for (index = 0; index < count; index++) {
        const struct cw_epoll_loop_stats *stats = &rows[index].value;
        char average[32];
        char maximum[32];

        format_interval(
            average, sizeof(average),
            stats->dispatches ?
                stats->total_dispatch_ns / stats->dispatches : 0);
        format_interval(
            maximum, sizeof(maximum), stats->maximum_dispatch_ns);
        fprintf(
            stream,
            "  %-8u %-6d %9llu %10llu %12s %12s %8llu %8llu %8llu\n",
            stats->tid, rows[index].key.epoll_fd,
            (unsigned long long)stats->dispatches,
            (unsigned long long)stats->unconsumed,
            average, maximum,
            (unsigned long long)stats->potential_et_undrained,
            (unsigned long long)
                stats->potential_oneshot_missing_rearm,
            (unsigned long long)stats->io_errors);
    }

}

static void print_instance_table(
    const struct cw_epoll_instance_row *instances,
    size_t instance_count,
    const struct cw_epoll_loop_row *loops, size_t loop_count,
    FILE *stream)
{
    size_t index;

    fprintf(stream,
            "\n[5] Shared epoll instances and waiter fairness\n"
            "  %-6s %-4s %7s %7s %8s %9s %9s  %s\n",
            "EPFD", "GEN", "WAITERS", "PEAK", "READY",
            "MAX SHARE", "EXCLUSIVE", "DIAGNOSIS");
    fprintf(stream,
            "  %-6s %-4s %7s %7s %8s %9s %9s  %s\n",
            "------", "----", "-------", "-------", "--------",
            "---------", "---------", "--------------------------");
    for (index = 0; index < instance_count; index++) {
        const struct cw_epoll_instance_row *instance =
            &instances[index];
        uint64_t maximum_ready = 0;
        uint64_t total_ready = 0;
        size_t waiters = 0;
        size_t loop_index;
        unsigned share = 0;
        const char *diagnosis = "single waiter";

        for (loop_index = 0; loop_index < loop_count; loop_index++) {
            const struct cw_epoll_loop_row *loop = &loops[loop_index];

            if (loop->value.pid != instance->key.pid ||
                loop->key.epoll_fd != instance->key.epoll_fd ||
                loop->key.epoll_generation !=
                    instance->key.epoll_generation)
                continue;
            waiters++;
            total_ready += loop->value.ready_events;
            if (loop->value.ready_events > maximum_ready)
                maximum_ready = loop->value.ready_events;
        }
        if (total_ready)
            share = (unsigned)(maximum_ready * 100 / total_ready);
        if (waiters > 1 && total_ready >= 10 && share >= 80)
            diagnosis = "uneven ready distribution";
        else if (instance->value.exclusive_resources)
            diagnosis = "EPOLLEXCLUSIVE enabled";
        else if (instance->value.peak_waiters > 1)
            diagnosis = "concurrent waiters observed";
        else if (waiters > 1)
            diagnosis = "multiple waiters observed";
        fprintf(stream,
                "  %-6d %-4u %7zu %7llu %8llu %8u%% %9llu  %s\n",
                instance->key.epoll_fd,
                instance->key.epoll_generation,
                waiters,
                (unsigned long long)instance->value.peak_waiters,
                (unsigned long long)total_ready,
                share,
                (unsigned long long)
                    instance->value.exclusive_resources,
                diagnosis);
    }
}

static void print_loop_callsites(
    struct output_options *output,
    const struct cw_epoll_loop_row *rows, size_t count,
    FILE *stream)
{
    size_t index;

    if (!output->epoll_top || !count)
        return;
    fprintf(stream, "\n[6] Event-loop call sites\n");
    for (index = 0;
         index < count && index < output->epoll_top; index++) {
        const struct cw_epoll_loop_stats *stats = &rows[index].value;
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};

        if (cw_capture_cancelled(output->control))
            break;
        fprintf(stream,
                "  [%zu] PID %u/TID %u (%.*s) epfd=%d "
                "waits=%llu ready=%llu\n",
                index + 1, stats->pid, stats->tid,
                (int)sizeof(stats->comm), stats->comm,
                rows[index].key.epoll_fd,
                (unsigned long long)stats->calls,
                (unsigned long long)stats->ready_events);
        fprintf(stream, "      wait stack:\n");
        if (stats->stack_id < 0 ||
            output->epoll_stack_map_fd < 0 ||
            bpf_map_lookup_elem(output->epoll_stack_map_fd,
                                &stats->stack_id, stack)) {
            fprintf(stream, "        unavailable (stack_id=%d)\n",
                    stats->stack_id);
        } else if (output->target_maps) {
            print_stack_frames(
                stack, sizeof(stack), output->target_maps,
                "      ", NULL, NULL, 0, output->control);
        } else {
            fprintf(stream, "        process maps unavailable\n");
        }
    }
}

static void print_resource_table(
    struct output_options *output,
    const struct cw_epoll_resource_row *rows, size_t count,
    FILE *stream)
{
    size_t index;
    size_t rank = 0;

    fprintf(stream, "\n[7] Monitored resources\n");
    if (!count) {
        fprintf(stream,
                "  No successful epoll_ctl registrations were observed "
                "during capture.\n");
        return;
    }
    fprintf(stream,
            "  %-6s %-5s %-7s %8s %8s %9s %12s %8s %8s %8s %s\n",
            "EPFD", "FD", "GEN", "READY", "HANDLED", "UNHANDLED",
            "AVG DISP", "IO ERR", "ET WARN", "1SHOT", "RESOURCE");
    fprintf(stream,
            "  %-6s %-5s %-7s %8s %8s %9s %12s %8s %8s %8s %s\n",
            "------", "-----", "-------", "--------", "--------",
            "---------", "------------", "--------", "--------", "--------",
            "----------------------------");
    for (index = 0; index < count; index++) {
        const struct cw_epoll_resource_stats *stats = &rows[index].value;
        char average[32];
        char interest[128];
        char observed[128];
        char resource[PATH_MAX];
        uint64_t et_warnings;
        uint32_t current_generation;
        bool reused;

        cw_epoll_format_events(
            stats->interest_events, interest, sizeof(interest));
        cw_epoll_format_events(
            stats->observed_events, observed, sizeof(observed));
        cw_fd_resolve(
            &output->fd_resources, output->target_pid,
            rows[index].key.fd, resource, sizeof(resource));
        format_interval(
            average, sizeof(average),
            stats->dispatches ?
                stats->total_dispatch_ns / stats->dispatches : 0);
        et_warnings = cw_epoll_resource_single_read(resource) ?
            0 : stats->potential_et_undrained;
        current_generation = current_fd_generation(
            output, rows[index].key.pid, rows[index].key.fd);
        reused =
            current_generation != rows[index].key.fd_generation;
        if (reused)
            snprintf(
                resource, sizeof(resource),
                "(stale FD lifetime; current generation=%u)",
                current_generation);
        fprintf(stream,
                "  %-6d %-5d %-7u %8llu %8llu %9llu %12s "
                "%8llu %8llu %8llu %s%s%s\n",
                rows[index].key.epoll_fd, rows[index].key.fd,
                rows[index].key.fd_generation,
                (unsigned long long)stats->ready_count,
                (unsigned long long)stats->dispatches,
                (unsigned long long)stats->unconsumed,
                average,
                (unsigned long long)stats->io_errors,
                (unsigned long long)et_warnings,
                (unsigned long long)
                    stats->potential_oneshot_missing_rearm,
                resource[0] ? resource : "(unavailable)",
                stats->active ? "" : " [removed]",
                reused ? " [closed/reused]" : "");
        fprintf(stream,
                "         events: interest=%s observed=%s; "
                "ONESHOT ready/rearm=%llu/%llu\n",
                interest, observed,
                (unsigned long long)stats->oneshot_events,
                (unsigned long long)stats->oneshot_rearms);
    }

    if (!output->epoll_top)
        return;
    fprintf(stream, "\n[8] Ready-handler call sites\n");
    for (index = 0;
         index < count && index < output->epoll_top; index++) {
        const struct cw_epoll_resource_stats *stats =
            &rows[index].value;
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        char resource[PATH_MAX];
        uint32_t current_generation;
        bool reused;

        if (cw_capture_cancelled(output->control))
            break;
        if (!stats->dispatches)
            continue;
        rank++;
        cw_fd_resolve(
            &output->fd_resources, output->target_pid,
            rows[index].key.fd, resource, sizeof(resource));
        current_generation = current_fd_generation(
            output, rows[index].key.pid, rows[index].key.fd);
        reused =
            current_generation != rows[index].key.fd_generation;
        if (reused)
            snprintf(
                resource, sizeof(resource),
                "(stale FD lifetime; current generation=%u)",
                current_generation);
        fprintf(
            stream,
            "  [%zu] epfd=%d gen=%u fd=%d gen=%u%s handled=%llu I/O=%llu "
            "read=%llu B write=%llu B\n"
            "      resource: %s%s\n"
            "      first I/O stack:\n",
            rank, rows[index].key.epoll_fd,
            rows[index].key.epoll_generation,
            rows[index].key.fd,
            rows[index].key.fd_generation,
            reused ? " (stale)" : "",
            (unsigned long long)stats->dispatches,
            (unsigned long long)stats->io_calls,
            (unsigned long long)stats->bytes_read,
            (unsigned long long)stats->bytes_written,
            resource[0] ? resource : "(unavailable)",
            stats->active ? "" : " [removed]");
        if (stats->dispatch_stack_id < 0 ||
            output->epoll_stack_map_fd < 0 ||
            bpf_map_lookup_elem(
                output->epoll_stack_map_fd,
                &stats->dispatch_stack_id, stack)) {
            fprintf(stream, "        unavailable (stack_id=%d)\n",
                    stats->dispatch_stack_id);
        } else if (output->target_maps) {
            print_stack_frames(
                stack, sizeof(stack), output->target_maps,
                "      ", NULL, NULL, 0, output->control);
        } else {
            fprintf(stream, "        process maps unavailable\n");
        }
    }
}

static void print_wake_source_table(
    struct output_options *output,
    const struct cw_epoll_resource_row *rows, size_t count,
    FILE *stream)
{
    size_t index;
    size_t rank = 0;

    fprintf(stream, "\n[9] Wake-source attribution\n");
    fprintf(stream,
            "  %-6s %-5s %-5s %-9s %8s %8s %8s %12s %12s  %s\n",
            "EPFD", "FD", "GEN", "KIND", "READY", "MATCHED",
            "SRC OPS", "AVG LAT", "MAX LAT", "LATEST SOURCE");
    fprintf(stream,
            "  %-6s %-5s %-5s %-9s %8s %8s %8s %12s %12s  %s\n",
            "------", "-----", "-----", "---------", "--------",
            "--------", "--------", "------------", "------------",
            "------------------------------");
    for (index = 0; index < count; index++) {
        const struct cw_epoll_resource_stats *stats =
            &rows[index].value;
        const struct cw_epoll_wake_source *wake =
            &stats->last_wake;
        char average[32] = "-";
        char maximum[32] = "-";
        char source[128] = "unavailable";

        if (!stats->wake_ready || !wake->kind)
            continue;
        if (stats->wake_latency_samples) {
            format_interval(
                average, sizeof(average),
                stats->wake_total_latency_ns /
                    stats->wake_latency_samples);
            format_interval(
                maximum, sizeof(maximum),
                stats->wake_maximum_latency_ns);
        }
        if (wake->action) {
            if (wake->action ==
                CW_EPOLL_WAKE_ACTION_SIGNAL_SEND)
                snprintf(
                    source, sizeof(source),
                    "PID %u/TID %u %.*s signal=%u",
                    wake->source_pid, wake->source_tid,
                    (int)sizeof(wake->comm), wake->comm,
                    wake->signal_number);
            else
                snprintf(
                    source, sizeof(source),
                    "PID %u/TID %u %.*s %s",
                    wake->source_pid, wake->source_tid,
                    (int)sizeof(wake->comm), wake->comm,
                    cw_epoll_wake_action_name(wake->action));
        }
        fprintf(
            stream,
            "  %-6d %-5d %-5u %-9s %8llu %8llu %8llu "
            "%12s %12s  %s\n",
            rows[index].key.epoll_fd,
            rows[index].key.fd,
            rows[index].key.fd_generation,
            cw_epoll_wake_kind_name(wake->kind),
            (unsigned long long)stats->wake_ready,
            (unsigned long long)stats->wake_attributed,
            (unsigned long long)stats->wake_operations,
            average, maximum, source);
    }
    if (!output->epoll_top)
        return;
    for (index = 0;
         index < count && rank < output->epoll_top; index++) {
        const struct cw_epoll_resource_stats *stats =
            &rows[index].value;
        const struct cw_epoll_wake_source *wake =
            &stats->last_wake;
        struct map_list source_maps = {0};
        struct map_list *maps = output->target_maps;
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        bool temporary_maps = false;

        if (!stats->wake_ready || !wake->kind)
            continue;
        rank++;
        fprintf(
            stream,
            "  [%zu] epfd=%d gen=%u fd=%d gen=%u %s "
            "attributed=%llu/%llu\n",
            rank,
            rows[index].key.epoll_fd,
            rows[index].key.epoll_generation,
            rows[index].key.fd,
            rows[index].key.fd_generation,
            cw_epoll_wake_kind_name(wake->kind),
            (unsigned long long)stats->wake_attributed,
            (unsigned long long)stats->wake_ready);
        if (!wake->action) {
            fprintf(
                stream,
                "      source stack: unavailable "
                "(pre-attach, external producer, or unmatched signal)\n");
            continue;
        }
        fprintf(stream, "      latest source stack:\n");
        if (wake->stack_id < 0 ||
            output->epoll_stack_map_fd < 0 ||
            bpf_map_lookup_elem(
                output->epoll_stack_map_fd,
                &wake->stack_id, stack)) {
            fprintf(
                stream,
                "        unavailable (stack_id=%d)\n",
                wake->stack_id);
            continue;
        }
        if (wake->source_pid != (uint32_t)output->target_pid &&
            wake->source_global_pid &&
            wake->source_global_pid != output->target_maps_pid) {
            if (!read_process_maps(
                    wake->source_global_pid, &source_maps)) {
                maps = &source_maps;
                temporary_maps = true;
            } else {
                maps = NULL;
            }
        }
        if (maps)
            print_stack_frames(
                stack, sizeof(stack), maps,
                "      ", NULL, NULL, 0, output->control);
        else
            fprintf(stream, "        process maps unavailable\n");
        if (temporary_maps)
            map_list_free(&source_maps);
        if (cw_capture_cancelled(output->control))
            break;
    }
}

static void print_callback_table(
    struct output_options *output,
    const struct cw_epoll_resource_row *rows, size_t count,
    FILE *stream)
{
    struct cw_epoll_resource_row *callbacks;
    size_t callback_count = 0;
    size_t index;
    size_t rank = 0;

    if (!output->epoll_callback_name)
        return;
    if (output->libuv_mode)
        fprintf(
            stream,
            "\n[10] libuv callback execution "
            "(automatic uv_poll_t handle matching)\n");
    else if (output->libevent_mode)
        fprintf(
            stream,
            "\n[10] libevent I/O callback execution "
            "(automatic event-to-FD matching)\n");
    else
        fprintf(
            stream,
            "\n[10] Callback execution: %s "
            "(match=%s key-arg%u)\n",
            output->epoll_callback_name,
            cw_epoll_callback_match_name(
                output->epoll_callback_match),
            output->epoll_callback_key_arg);
    callbacks = calloc(count ? count : 1, sizeof(*callbacks));
    if (!callbacks) {
        fprintf(stream, "  Cannot allocate callback summary rows.\n");
        return;
    }
    for (index = 0; index < count; index++) {
        if (!rows[index].value.callback_matched)
            continue;
        callbacks[callback_count++] = rows[index];
    }
    if (!callback_count) {
        if (output->libuv_mode)
            fprintf(
                stream,
                "  No discovered libuv callback invocation matched "
                "an epoll-ready FD.\n");
        else if (output->libevent_mode)
            fprintf(
                stream,
                "  No discovered libevent I/O callback invocation "
                "matched an epoll-ready FD. Timer and signal events "
                "are reported by adapter health but do not identify "
                "an application I/O FD.\n");
        else
            fprintf(
                stream,
                "  No callback invocation matched a ready event. "
                "Verify --epoll-callback-key-arg and "
                "--epoll-callback-match.\n");
        free(callbacks);
        return;
    }
    qsort(
        callbacks, callback_count, sizeof(*callbacks),
        compare_callback_rows);
    fprintf(
        stream,
        "  %-6s %-26s %-5s %8s %12s %12s %12s %12s "
        "%12s %12s %12s\n",
        "EPFD", "CALLBACK KEY -> FD", "GEN", "CALLS", "AVG R->CB",
        "MAX R->CB", "AVG WORK", "MAX WORK",
        "AVG ONCPU", "AVG BLOCK", "AVG RUNQ");
    fprintf(
        stream,
        "  %-6s %-26s %-5s %8s %12s %12s %12s %12s "
        "%12s %12s %12s\n",
        "------", "--------------------------", "-----", "--------",
        "------------", "------------", "------------",
        "------------", "------------", "------------",
        "------------");
    for (index = 0; index < callback_count; index++) {
        const struct cw_epoll_resource_stats *stats =
            &callbacks[index].value;
        uint64_t completed = stats->callback_completed;
        uint64_t oncpu =
            stats->callback_total_duration_ns >
                stats->callback_offcpu_ns ?
                stats->callback_total_duration_ns -
                    stats->callback_offcpu_ns : 0;
        char average_delay[32];
        char maximum_delay[32];
        char average_duration[32];
        char maximum_duration[32];
        char average_oncpu[32];
        char average_blocked[32];
        char average_runqueue[32];
        char callback_key[32];

        format_interval(
            average_delay, sizeof(average_delay),
            stats->callback_matched ?
                stats->callback_total_delay_ns /
                    stats->callback_matched : 0);
        format_interval(
            maximum_delay, sizeof(maximum_delay),
            stats->callback_maximum_delay_ns);
        format_interval(
            average_duration, sizeof(average_duration),
            completed ?
                stats->callback_total_duration_ns /
                    completed : 0);
        format_interval(
            maximum_duration, sizeof(maximum_duration),
            stats->callback_maximum_duration_ns);
        format_interval(
            average_oncpu, sizeof(average_oncpu),
            completed ? oncpu / completed : 0);
        format_interval(
            average_blocked, sizeof(average_blocked),
            completed ?
                stats->callback_blocked_ns / completed : 0);
        format_interval(
            average_runqueue, sizeof(average_runqueue),
            completed ?
                stats->callback_runqueue_ns / completed : 0);
        if (output->epoll_callback_match ==
                CW_EPOLL_CALLBACK_MATCH_FD)
            snprintf(
                callback_key, sizeof(callback_key),
                "%d -> %d",
                callbacks[index].key.fd,
                callbacks[index].key.fd);
        else if (output->epoll_callback_match ==
                 CW_EPOLL_CALLBACK_MATCH_LIBUV)
            snprintf(
                callback_key, sizeof(callback_key),
                "0x%016llx -> %d",
                (unsigned long long)stats->callback_key,
                callbacks[index].key.fd);
        else if (output->epoll_callback_match ==
                 CW_EPOLL_CALLBACK_MATCH_LIBEVENT)
            snprintf(
                callback_key, sizeof(callback_key),
                "0x%llx -> %d",
                (unsigned long long)stats->callback_key,
                callbacks[index].key.fd);
        else
            snprintf(
                callback_key, sizeof(callback_key),
                "0x%016llx -> %d",
                (unsigned long long)stats->data,
                callbacks[index].key.fd);
        fprintf(
            stream,
            "  %-6d %-26s %-5u %8llu %12s %12s %12s %12s "
            "%12s %12s %12s\n",
            callbacks[index].key.epoll_fd,
            callback_key,
            callbacks[index].key.fd_generation,
            (unsigned long long)completed,
            average_delay, maximum_delay,
            average_duration, maximum_duration,
            average_oncpu, average_blocked,
            average_runqueue);
    }
    if (!output->epoll_top)
        goto done;
    fprintf(
        stream,
        "\n  Slowest callback call sites "
        "(by maximum execution time)\n");
    for (index = 0;
         index < callback_count && rank < output->epoll_top;
         index++) {
        const struct cw_epoll_resource_stats *stats =
            &callbacks[index].value;
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        char maximum[32];
        char resource[PATH_MAX];

        if (!stats->callback_completed)
            continue;
        rank++;
        format_interval(
            maximum, sizeof(maximum),
            stats->callback_maximum_duration_ns);
        cw_fd_resolve(
            &output->fd_resources, output->target_pid,
            callbacks[index].key.fd,
            resource, sizeof(resource));
        fprintf(
            stream,
            "  [%zu] epfd=%d gen=%u fd=%d gen=%u "
            "callbacks=%llu max=%s\n"
            "      resource: %s\n"
            "      slowest callback stack:\n",
            rank,
            callbacks[index].key.epoll_fd,
            callbacks[index].key.epoll_generation,
            callbacks[index].key.fd,
            callbacks[index].key.fd_generation,
            (unsigned long long)stats->callback_completed,
            maximum,
            resource[0] ? resource : "(unavailable)");
        if (stats->callback_stack_id < 0 ||
            output->epoll_stack_map_fd < 0 ||
            bpf_map_lookup_elem(
                output->epoll_stack_map_fd,
                &stats->callback_stack_id, stack)) {
            fprintf(
                stream,
                "        unavailable (stack_id=%d)\n",
                stats->callback_stack_id);
        } else if (output->target_maps) {
            print_stack_frames(
                stack, sizeof(stack), output->target_maps,
                "      ", NULL, NULL, 0, output->control);
        } else {
            fprintf(stream, "        process maps unavailable\n");
        }
        fprintf(stream, "      blocking in slowest callback:\n");
        if (stats->callback_slowest_futex_waits) {
            cw_epoll_print_callback_futex(
                &stats->callback_slowest_futex_wait,
                stats->callback_slowest_futex_waits,
                stats->callback_slowest_futex_wait_ns,
                output, "        ");
        } else if (stats->callback_slowest_blocked_ns) {
            char blocked[32];

            format_interval(
                blocked, sizeof(blocked),
                stats->callback_slowest_blocked_ns);
            fprintf(
                stream,
                "        blocked=%s; no futex wait observed "
                "(possible sleep, timer, I/O, or other wait)\n",
                blocked);
        } else {
            fprintf(stream, "        no blocking wait observed\n");
        }
        if (cw_capture_cancelled(output->control))
            break;
    }

done:
    free(callbacks);
}

bool cw_epoll_print_summary(struct output_options *output)
{
    struct cw_epoll_counters counters = {0};
    struct cw_epoll_loop_row *loops = NULL;
    struct cw_epoll_resource_row *resources = NULL;
    struct cw_epoll_instance_row *instances = NULL;
    FILE *stream = output->json_output ? stderr : stdout;
    size_t loop_count;
    size_t resource_count;
    size_t instance_count;
    uint64_t correlatable;
    uint64_t pending_at_stop;
    char callback_futex_total[32];
    uint32_t zero = 0;

    if (output->epoll_counters_map_fd < 0 ||
        bpf_map_lookup_elem(output->epoll_counters_map_fd,
                            &zero, &counters))
        return false;
    loop_count = read_loop_rows(output, &loops);
    resource_count = read_resource_rows(output, &resources);
    instance_count = read_instance_rows(output, &instances);
    correlatable = counters.ready_events > counters.unresolved_events ?
        counters.ready_events - counters.unresolved_events : 0;
    pending_at_stop =
        correlatable > counters.dispatches + counters.unconsumed ?
        correlatable - counters.dispatches - counters.unconsumed : 0;
    format_interval(
        callback_futex_total, sizeof(callback_futex_total),
        counters.callback_futex_wait_ns);
    if (output->json_output) {
        fprintf(stream,
                "\n%s capture stopped: waits=%llu ready=%llu "
                "timeouts=%llu errors=%llu; structured summary "
                "written to JSON output\n",
                output->libuv_mode ? "libuv" :
                    (output->libevent_mode ? "libevent" : "epoll"),
                (unsigned long long)counters.calls,
                (unsigned long long)counters.ready_events,
                (unsigned long long)counters.timeouts,
                (unsigned long long)counters.errors);
        free(loops);
        free(resources);
        free(instances);
        return true;
    }

    fprintf(
        stream, "\n%s summary\n",
        output->libuv_mode ? "libuv" :
            (output->libevent_mode ? "libevent" : "epoll"));
    if (output->libuv_mode)
        fprintf(
            stream,
            "  Runtime             : native uv_poll_t adapter\n"
            "  Linux I/O backend   : epoll\n");
    else if (output->libevent_mode)
        fprintf(
            stream,
            "  Runtime             : native libevent adapter\n"
            "  Linux I/O backend   : epoll\n");
    fprintf(stream,
            "\n[1] Capture overview\n"
            "  Detail output       : %s\n"
            "  Observation scope   : %s\n"
            "  Bootstrap state     : %u registration%s from %u epoll "
            "FD%s (%u scans, %u conflicts, %u failures)\n"
            "  Wait calls          : %llu\n"
            "  Ready returns       : %llu\n"
            "  Ready events        : %llu\n"
            "  Timeout returns     : %llu\n"
            "  Interrupted waits   : %llu\n"
            "  Other errors        : %llu\n"
            "  Full batches        : %llu\n"
            "  Unresolved data     : %llu\n"
            "  Truncated details   : %llu\n"
            "  Detailed records    : %u\n"
            "  Dropped records     : %llu\n"
            "  Handled ready FDs   : %llu\n"
            "  Unhandled/handoff   : %llu\n"
            "  Pending at stop     : %llu\n"
            "  I/O errors          : %llu\n"
            "  EPOLLET drain warns : %llu\n"
            "  ONESHOT rearm warns : %llu\n"
            "  FD close / dup      : %llu / %llu\n"
            "  Reused registrations: %llu\n"
            "  Wake-source ready   : %llu\n"
            "  Wake attributed     : %llu\n"
            "    eventfd/timerfd/signalfd/socketpair: "
            "%llu / %llu / %llu / %llu\n"
            "  Callback match/done : %llu / %llu\n"
            "    matched fd/data/libuv/libevent: "
            "%llu / %llu / %llu / %llu\n"
            "    unmatched/overflow: %llu / %llu\n"
            "  Callback records    : %llu\n"
            "  Callback dropped    : %llu\n"
            "  Callback futex waits: %llu (total %s)\n"
            "  Evidence exact      : %llu\n"
            "  Evidence ready-to-I/O: %llu\n"
            "  Evidence ready-only : %llu\n"
            "  Dispatch records    : %llu\n"
            "  Dispatch dropped    : %llu\n",
            cw_epoll_output_mode_name(
                output->epoll_output_mode),
            output->epoll_started_target ?
                "complete from target start" :
                "post-attach only; earlier activity is unavailable",
            output->epoll_bootstrap_registrations,
            output->epoll_bootstrap_registrations == 1 ? "" : "s",
            output->epoll_bootstrap_fds,
            output->epoll_bootstrap_fds == 1 ? "" : "s",
            output->epoll_bootstrap_scans,
            output->epoll_bootstrap_conflicts,
            output->epoll_bootstrap_failures,
            (unsigned long long)counters.calls,
            (unsigned long long)counters.ready_returns,
            (unsigned long long)counters.ready_events,
            (unsigned long long)counters.timeouts,
            (unsigned long long)counters.interrupted,
            (unsigned long long)counters.errors,
            (unsigned long long)counters.saturated_batches,
            (unsigned long long)counters.unresolved_events,
            (unsigned long long)counters.truncated_events,
            output->emitted_events,
            (unsigned long long)counters.dropped,
            (unsigned long long)counters.dispatches,
            (unsigned long long)counters.unconsumed,
            (unsigned long long)pending_at_stop,
            (unsigned long long)counters.io_errors,
            (unsigned long long)counters.potential_et_undrained,
            (unsigned long long)
                counters.potential_oneshot_missing_rearm,
            (unsigned long long)counters.fd_closes,
            (unsigned long long)counters.fd_duplications,
            (unsigned long long)counters.fd_reuses,
            (unsigned long long)counters.wake_ready,
            (unsigned long long)counters.wake_attributed,
            (unsigned long long)counters.eventfd_ready,
            (unsigned long long)counters.timerfd_ready,
            (unsigned long long)counters.signalfd_ready,
            (unsigned long long)counters.socketpair_ready,
            (unsigned long long)counters.callback_matched,
            (unsigned long long)counters.callback_completed,
            (unsigned long long)counters.callback_fd_matched,
            (unsigned long long)counters.callback_data_matched,
            (unsigned long long)counters.callback_libuv_matched,
            (unsigned long long)counters.callback_libevent_matched,
            (unsigned long long)counters.callback_unmatched,
            (unsigned long long)counters.callback_overflow,
            (unsigned long long)counters.callback_emitted,
            (unsigned long long)counters.callback_dropped,
            (unsigned long long)counters.callback_futex_waits,
            callback_futex_total,
            (unsigned long long)counters.evidence_exact,
            (unsigned long long)counters.evidence_ready_to_io,
            (unsigned long long)counters.evidence_ready_only,
            (unsigned long long)counters.dispatch_emitted,
            (unsigned long long)counters.dispatch_dropped);
    if (counters.potential_et_undrained)
        fprintf(
            stream,
            "  Note: EPOLLET drain warnings are heuristic. Counter-style "
            "eventfd/timerfd/signalfd reads are suppressed as warnings "
            "in the resource table.\n");
    if (counters.potential_oneshot_missing_rearm)
        fprintf(
            stream,
            "  Note: ONESHOT warnings mean no rearm or close was "
            "observed before the waiter entered epoll again.\n");
    if (output->libevent_mode && counters.callback_unmatched)
        fprintf(
            stream,
            "  Note: libevent unmatched callbacks can be non-I/O "
            "timer/signal callbacks; unmatched does not mean the "
            "record was dropped.\n");
    if (output->libevent_mode && pending_at_stop)
        fprintf(
            stream,
            "  Note: pending final cycles were still open at capture "
            "stop; pending does not mean the record was dropped.\n");
    print_loop_table(loops, loop_count, stream);
    print_instance_table(
        instances, instance_count, loops, loop_count, stream);
    print_loop_callsites(output, loops, loop_count, stream);
    print_resource_table(
        output, resources, resource_count, stream);
    print_wake_source_table(
        output, resources, resource_count, stream);
    print_callback_table(
        output, resources, resource_count, stream);
    free(loops);
    free(resources);
    free(instances);
    return true;
}

static int write_summary_wake_json(
    FILE *stream, const struct cw_epoll_resource_stats *stats)
{
    const struct cw_epoll_wake_source *wake = &stats->last_wake;

    if (!wake->kind)
        return fputs("null", stream) == EOF ? -1 : 0;
    if (fprintf(
            stream,
            "{\"kind\":\"%s\",\"action\":\"%s\","
            "\"ready\":%llu,\"attributed\":%llu,"
            "\"operations\":%llu,\"latency_samples\":%llu,"
            "\"total_latency_ns\":%llu,"
            "\"maximum_latency_ns\":%llu,"
            "\"last_latency_ns\":%llu,"
            "\"last_latency_valid\":%s,"
            "\"value\":%llu,\"timer_initial_ns\":%llu,"
            "\"timer_interval_ns\":%llu,\"timer_abstime\":%s,"
            "\"signal_number\":%u,\"source_pid\":%u,"
            "\"source_tid\":%u,\"source_global_pid\":%u,"
            "\"source_global_tid\":%u,\"stack_id\":%d,\"comm\":",
            cw_epoll_wake_kind_name(wake->kind),
            cw_epoll_wake_action_name(wake->action),
            (unsigned long long)stats->wake_ready,
            (unsigned long long)stats->wake_attributed,
            (unsigned long long)stats->wake_operations,
            (unsigned long long)stats->wake_latency_samples,
            (unsigned long long)stats->wake_total_latency_ns,
            (unsigned long long)stats->wake_maximum_latency_ns,
            (unsigned long long)wake->latency_ns,
            wake->flags & CW_EPOLL_WAKE_LATENCY_VALID ?
                "true" : "false",
            (unsigned long long)wake->value,
            (unsigned long long)wake->timer_initial_ns,
            (unsigned long long)wake->timer_interval_ns,
            wake->flags & CW_EPOLL_WAKE_TIMER_ABSTIME ?
                "true" : "false",
            wake->signal_number,
            wake->source_pid, wake->source_tid,
            wake->source_global_pid, wake->source_global_tid,
            wake->stack_id) < 0 ||
        cw_epoll_write_json_string(
            stream, wake->comm, sizeof(wake->comm)) ||
        fputc('}', stream) == EOF)
        return -1;
    return 0;
}

static int write_summary_futex_json(
    FILE *stream, const struct cw_epoll_futex_wait *wait)
{
    if (!wait->duration_ns)
        return fputs("null", stream) == EOF ? -1 : 0;
    if (fprintf(
            stream,
            "{\"operation\":\"%s\","
            "\"address\":\"0x%016llx\","
            "\"duration_ns\":%llu,\"wake_ns\":%llu,"
            "\"waker_pid\":%u,\"waker_tid\":%u,"
            "\"waker_global_pid\":%u,"
            "\"waker_global_tid\":%u,"
            "\"waker_stack_id\":%d,\"waker_comm\":",
            cw_epoll_futex_operation_name(wait->operation),
            (unsigned long long)wait->address,
            (unsigned long long)wait->duration_ns,
            (unsigned long long)wait->wake_ns,
            wait->waker_pid, wait->waker_tid,
            wait->waker_global_pid, wait->waker_global_tid,
            wait->waker_stack_id) < 0 ||
        cw_epoll_write_json_string(
            stream, wait->waker_comm, sizeof(wait->waker_comm)) ||
        fputc('}', stream) == EOF)
        return -1;
    return 0;
}

static int write_summary_callback_json(
    FILE *stream, const struct cw_epoll_resource_stats *stats)
{
    if (!stats->callback_matched)
        return fputs("null", stream) == EOF ? -1 : 0;
    if (fprintf(
            stream,
            "{\"matched\":%llu,\"completed\":%llu,"
            "\"total_ready_to_callback_ns\":%llu,"
            "\"maximum_ready_to_callback_ns\":%llu,"
            "\"total_duration_ns\":%llu,"
            "\"maximum_duration_ns\":%llu,"
            "\"offcpu_ns\":%llu,\"blocked_ns\":%llu,"
            "\"runqueue_ns\":%llu,\"stack_id\":%d,"
            "\"futex_waits\":%llu,\"futex_wait_ns\":%llu,"
            "\"slowest_blocked_ns\":%llu,"
            "\"slowest_futex_waits\":%llu,"
            "\"slowest_futex_wait_ns\":%llu,"
            "\"slowest_futex\":",
            (unsigned long long)stats->callback_matched,
            (unsigned long long)stats->callback_completed,
            (unsigned long long)
                stats->callback_total_delay_ns,
            (unsigned long long)
                stats->callback_maximum_delay_ns,
            (unsigned long long)
                stats->callback_total_duration_ns,
            (unsigned long long)
                stats->callback_maximum_duration_ns,
            (unsigned long long)stats->callback_offcpu_ns,
            (unsigned long long)stats->callback_blocked_ns,
            (unsigned long long)stats->callback_runqueue_ns,
            stats->callback_stack_id,
            (unsigned long long)stats->callback_futex_waits,
            (unsigned long long)stats->callback_futex_wait_ns,
            (unsigned long long)stats->callback_slowest_blocked_ns,
            (unsigned long long)
                stats->callback_slowest_futex_waits,
            (unsigned long long)
                stats->callback_slowest_futex_wait_ns) < 0 ||
        write_summary_futex_json(
            stream, &stats->callback_slowest_futex_wait) ||
        fputc('}', stream) == EOF)
        return -1;
    return 0;
}

int cw_epoll_write_summary_json(struct output_options *output)
{
    struct cw_epoll_counters counters = {0};
    struct cw_epoll_loop_row *loops = NULL;
    struct cw_epoll_resource_row *resources = NULL;
    struct cw_epoll_instance_row *instances = NULL;
    FILE *stream = output->json_stream;
    size_t loop_count;
    size_t resource_count;
    size_t instance_count;
    size_t index;
    uint64_t correlatable;
    uint64_t pending_at_stop;
    uint32_t zero = 0;
    int error = 0;

    if (!stream || output->epoll_counters_map_fd < 0)
        return 0;
    if (bpf_map_lookup_elem(output->epoll_counters_map_fd,
                            &zero, &counters))
        return -1;
    loop_count = read_loop_rows(output, &loops);
    resource_count = read_resource_rows(output, &resources);
    instance_count = read_instance_rows(output, &instances);
    correlatable = counters.ready_events > counters.unresolved_events ?
        counters.ready_events - counters.unresolved_events : 0;
    pending_at_stop =
        correlatable > counters.dispatches + counters.unconsumed ?
        correlatable - counters.dispatches - counters.unconsumed : 0;
    if (fprintf(
            stream,
            "{\"type\":\"epoll_summary\",\"detail_mode\":\"%s\","
            "\"calls\":%llu,"
            "\"ready_returns\":%llu,\"ready_events\":%llu,"
            "\"timeouts\":%llu,\"interrupted\":%llu,"
            "\"errors\":%llu,\"saturated_batches\":%llu,"
            "\"unresolved_events\":%llu,"
            "\"truncated_events\":%llu,\"emitted\":%llu,"
            "\"dropped\":%llu,\"dispatches\":%llu,"
            "\"unconsumed\":%llu,\"dispatch_emitted\":%llu,"
            "\"dispatch_dropped\":%llu,\"io_errors\":%llu,"
            "\"potential_et_undrained\":%llu,"
            "\"potential_oneshot_missing_rearm\":%llu,"
            "\"fd_closes\":%llu,\"fd_duplications\":%llu,"
            "\"fd_reuses\":%llu,"
            "\"wake_ready\":%llu,\"wake_attributed\":%llu,"
            "\"eventfd_ready\":%llu,\"timerfd_ready\":%llu,"
            "\"signalfd_ready\":%llu,"
            "\"socketpair_ready\":%llu,"
            "\"callback_matched\":%llu,"
            "\"callback_fd_matched\":%llu,"
            "\"callback_data_matched\":%llu,"
            "\"callback_libuv_matched\":%llu,"
            "\"callback_libevent_matched\":%llu,"
            "\"callback_unmatched\":%llu,"
            "\"callback_completed\":%llu,"
            "\"callback_overflow\":%llu,"
            "\"callback_emitted\":%llu,"
            "\"callback_dropped\":%llu,"
            "\"callback_futex_waits\":%llu,"
            "\"callback_futex_wait_ns\":%llu,"
            "\"evidence_exact\":%llu,"
            "\"evidence_ready_to_io\":%llu,"
            "\"evidence_ready_only\":%llu,"
            "\"pending_at_stop\":%llu,"
            "\"observation_from_target_start\":%s,"
            "\"bootstrap_scans\":%u,\"bootstrap_epoll_fds\":%u,"
            "\"bootstrap_registrations\":%u,"
            "\"bootstrap_conflicts\":%u,\"bootstrap_failures\":%u,"
            "\"loops\":[",
            cw_epoll_output_mode_name(
                output->epoll_output_mode),
            (unsigned long long)counters.calls,
            (unsigned long long)counters.ready_returns,
            (unsigned long long)counters.ready_events,
            (unsigned long long)counters.timeouts,
            (unsigned long long)counters.interrupted,
            (unsigned long long)counters.errors,
            (unsigned long long)counters.saturated_batches,
            (unsigned long long)counters.unresolved_events,
            (unsigned long long)counters.truncated_events,
            (unsigned long long)counters.emitted,
            (unsigned long long)counters.dropped,
            (unsigned long long)counters.dispatches,
            (unsigned long long)counters.unconsumed,
            (unsigned long long)counters.dispatch_emitted,
            (unsigned long long)counters.dispatch_dropped,
            (unsigned long long)counters.io_errors,
            (unsigned long long)counters.potential_et_undrained,
            (unsigned long long)
                counters.potential_oneshot_missing_rearm,
            (unsigned long long)counters.fd_closes,
            (unsigned long long)counters.fd_duplications,
            (unsigned long long)counters.fd_reuses,
            (unsigned long long)counters.wake_ready,
            (unsigned long long)counters.wake_attributed,
            (unsigned long long)counters.eventfd_ready,
            (unsigned long long)counters.timerfd_ready,
            (unsigned long long)counters.signalfd_ready,
            (unsigned long long)counters.socketpair_ready,
            (unsigned long long)counters.callback_matched,
            (unsigned long long)counters.callback_fd_matched,
            (unsigned long long)counters.callback_data_matched,
            (unsigned long long)counters.callback_libuv_matched,
            (unsigned long long)counters.callback_libevent_matched,
            (unsigned long long)counters.callback_unmatched,
            (unsigned long long)counters.callback_completed,
            (unsigned long long)counters.callback_overflow,
            (unsigned long long)counters.callback_emitted,
            (unsigned long long)counters.callback_dropped,
            (unsigned long long)counters.callback_futex_waits,
            (unsigned long long)counters.callback_futex_wait_ns,
            (unsigned long long)counters.evidence_exact,
            (unsigned long long)counters.evidence_ready_to_io,
            (unsigned long long)counters.evidence_ready_only,
            (unsigned long long)pending_at_stop,
            output->epoll_started_target ? "true" : "false",
            output->epoll_bootstrap_scans,
            output->epoll_bootstrap_fds,
            output->epoll_bootstrap_registrations,
            output->epoll_bootstrap_conflicts,
            output->epoll_bootstrap_failures) < 0) {
        error = -1;
        goto done;
    }
    for (index = 0; index < loop_count; index++) {
        const struct cw_epoll_loop_stats *stats = &loops[index].value;

        if ((index && fputc(',', stream) == EOF) ||
            fprintf(
                stream,
                "{\"pid\":%u,\"tid\":%u,\"global_pid\":%u,"
                "\"global_tid\":%u,\"epoll_fd\":%d,"
                "\"epoll_generation\":%u,"
                "\"calls\":%llu,\"ready_events\":%llu,"
                "\"timeouts\":%llu,\"errors\":%llu,"
                "\"saturated_batches\":%llu,"
                "\"total_wait_ns\":%llu,\"maximum_wait_ns\":%llu,"
                "\"dispatches\":%llu,\"unconsumed\":%llu,"
                "\"total_dispatch_ns\":%llu,"
                "\"maximum_dispatch_ns\":%llu,"
                "\"cycles\":%llu,\"total_cycle_ns\":%llu,"
                "\"maximum_cycle_ns\":%llu,"
                "\"cycle_offcpu_ns\":%llu,"
                "\"cycle_blocked_ns\":%llu,"
                "\"cycle_runqueue_ns\":%llu,"
                "\"io_errors\":%llu,"
                "\"potential_et_undrained\":%llu,"
                "\"potential_oneshot_missing_rearm\":%llu,"
                "\"diagnosis\":",
                stats->pid, stats->tid,
                loops[index].key.global_pid,
                loops[index].key.global_tid,
                loops[index].key.epoll_fd,
                loops[index].key.epoll_generation,
                (unsigned long long)stats->calls,
                (unsigned long long)stats->ready_events,
                (unsigned long long)stats->timeouts,
                (unsigned long long)stats->errors,
                (unsigned long long)stats->saturated_batches,
                (unsigned long long)stats->total_wait_ns,
                (unsigned long long)stats->maximum_wait_ns,
                (unsigned long long)stats->dispatches,
                (unsigned long long)stats->unconsumed,
                (unsigned long long)stats->total_dispatch_ns,
                (unsigned long long)stats->maximum_dispatch_ns,
                (unsigned long long)stats->cycles,
                (unsigned long long)stats->total_cycle_ns,
                (unsigned long long)stats->maximum_cycle_ns,
                (unsigned long long)stats->cycle_offcpu_ns,
                (unsigned long long)stats->cycle_blocked_ns,
                (unsigned long long)stats->cycle_runqueue_ns,
                (unsigned long long)stats->io_errors,
                (unsigned long long)stats->potential_et_undrained,
                (unsigned long long)
                    stats->potential_oneshot_missing_rearm) < 0 ||
            cw_epoll_write_json_string(
                stream, diagnose_loop(stats),
                strlen(diagnose_loop(stats))) ||
            fputc('}', stream) == EOF) {
            error = -1;
            goto done;
        }
    }
    if (fputs("],\"resources\":[", stream) == EOF) {
        error = -1;
        goto done;
    }
    for (index = 0; index < resource_count; index++) {
        const struct cw_epoll_resource_stats *stats =
            &resources[index].value;
        char resource[PATH_MAX];
        uint64_t et_warnings;
        uint32_t current_generation;
        bool reused;

        cw_fd_resolve(
            &output->fd_resources, output->target_pid,
            resources[index].key.fd, resource, sizeof(resource));
        et_warnings = cw_epoll_resource_single_read(resource) ?
            0 : stats->potential_et_undrained;
        current_generation = current_fd_generation(
            output, resources[index].key.pid,
            resources[index].key.fd);
        reused = current_generation !=
            resources[index].key.fd_generation;
        if (reused)
            snprintf(
                resource, sizeof(resource),
                "(stale FD lifetime; current generation=%u)",
                current_generation);
        if ((index && fputc(',', stream) == EOF) ||
            fprintf(
                stream,
                "{\"epoll_fd\":%d,\"epoll_generation\":%u,"
                "\"fd\":%d,\"fd_generation\":%u,"
                "\"current_fd_generation\":%u,\"fd_reused\":%s,"
                "\"data\":\"0x%016llx\",\"ready_count\":%llu,"
                "\"interest_events\":%u,\"observed_events\":%u,"
                "\"dispatches\":%llu,\"unconsumed\":%llu,"
                "\"total_dispatch_ns\":%llu,"
                "\"maximum_dispatch_ns\":%llu,"
                "\"io_calls\":%llu,\"bytes_read\":%llu,"
                "\"bytes_written\":%llu,\"io_errors\":%llu,"
                "\"eagain\":%llu,"
                "\"potential_et_undrained\":%llu,"
                "\"et_warnings\":%llu,"
                "\"oneshot_events\":%llu,"
                "\"oneshot_rearms\":%llu,"
                "\"potential_oneshot_missing_rearm\":%llu,"
                "\"active\":%s,\"resource\":",
                resources[index].key.epoll_fd,
                resources[index].key.epoll_generation,
                resources[index].key.fd,
                resources[index].key.fd_generation,
                current_generation,
                reused ? "true" : "false",
                (unsigned long long)stats->data,
                (unsigned long long)stats->ready_count,
                stats->interest_events, stats->observed_events,
                (unsigned long long)stats->dispatches,
                (unsigned long long)stats->unconsumed,
                (unsigned long long)stats->total_dispatch_ns,
                (unsigned long long)stats->maximum_dispatch_ns,
                (unsigned long long)stats->io_calls,
                (unsigned long long)stats->bytes_read,
                (unsigned long long)stats->bytes_written,
                (unsigned long long)stats->io_errors,
                (unsigned long long)stats->eagain,
                (unsigned long long)stats->potential_et_undrained,
                (unsigned long long)et_warnings,
                (unsigned long long)stats->oneshot_events,
                (unsigned long long)stats->oneshot_rearms,
                (unsigned long long)
                    stats->potential_oneshot_missing_rearm,
                stats->active && !reused ? "true" : "false") < 0 ||
            cw_epoll_write_json_string(
                stream, resource, strlen(resource)) ||
            fputs(",\"wake\":", stream) == EOF ||
            write_summary_wake_json(stream, stats) ||
            fputs(",\"callback\":", stream) == EOF ||
            write_summary_callback_json(stream, stats) ||
            fputc('}', stream) == EOF) {
            error = -1;
            goto done;
        }
    }
    if (fputs("],\"instances\":[", stream) == EOF) {
        error = -1;
        goto done;
    }
    for (index = 0; index < instance_count; index++) {
        if ((index && fputc(',', stream) == EOF) ||
            fprintf(
                stream,
                "{\"pid\":%u,\"epoll_fd\":%d,"
                "\"epoll_generation\":%u,\"calls\":%llu,"
                "\"ready_returns\":%llu,\"ready_events\":%llu,"
                "\"active_waiters\":%llu,\"peak_waiters\":%llu,"
                "\"exclusive_resources\":%llu}",
                instances[index].key.pid,
                instances[index].key.epoll_fd,
                instances[index].key.epoll_generation,
                (unsigned long long)instances[index].value.calls,
                (unsigned long long)
                    instances[index].value.ready_returns,
                (unsigned long long)
                    instances[index].value.ready_events,
                (unsigned long long)
                    instances[index].value.active_waiters,
                (unsigned long long)
                    instances[index].value.peak_waiters,
                (unsigned long long)
                    instances[index].value.exclusive_resources) < 0) {
            error = -1;
            goto done;
        }
    }
    if (fputs("]}\n", stream) == EOF)
        error = -1;

done:
    free(loops);
    free(resources);
    free(instances);
    return error;
}
