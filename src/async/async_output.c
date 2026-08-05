// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>

#include "async_events.h"
#include "async_output.h"
#include "callweave_internal.h"
#include "report.h"

static const char *futex_operation_name(uint32_t operation)
{
    switch (operation) {
    case 0:
        return "wait";
    case 9:
        return "wait-bitset";
    default:
        return "wait";
    }
}

static void copy_queue_diagnostic(
    struct cw_queue_diagnostic *destination,
    const struct async_hop_stats *source, uint32_t index,
    const struct output_options *output)
{
    memset(destination, 0, sizeof(*destination));
    destination->index = index;
    if (index < output->async_hop_count) {
        destination->source = output->async_hops[index].source;
        destination->source_exit = output->async_hops[index].source_exit;
        destination->target = output->async_hops[index].target;
    } else {
        destination->source = output->async_source_name ?
            output->async_source_name : "source";
        destination->target = output->final_target_name ?
            output->final_target_name : "target";
    }
    destination->submitted = source->submitted;
    destination->started = source->started;
    destination->completed = source->completed;
    destination->pending = source->pending;
    destination->peak_pending = source->peak_pending;
    destination->active = source->active;
    destination->peak_active = source->peak_active;
    destination->queue_total_ns = source->queue_total_ns;
    destination->work_total_ns = source->work_total_ns;
    destination->futex_waits = source->futex_waits;
    destination->futex_wait_ns = source->futex_wait_ns;
    destination->duplicate_keys = source->duplicate_keys;
    destination->expired = source->expired;
    destination->unmatched_targets = source->unmatched_targets;
    destination->dropped = source->dropped;
}

size_t read_queue_diagnostics(
    const struct output_options *output,
    struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS],
    struct async_hop_stats raw[MAX_ASYNC_HOPS])
{
    struct async_worker_key key;
    struct async_worker_key next;
    size_t count = output->async_hop_count ?
        output->async_hop_count : (output->show_async ? 1 : 0);
    uint32_t index;

    if (count > MAX_ASYNC_HOPS)
        count = MAX_ASYNC_HOPS;
    memset(raw, 0, sizeof(*raw) * MAX_ASYNC_HOPS);
    memset(diagnostics, 0, sizeof(*diagnostics) * MAX_ASYNC_HOPS);
    if (output->async_hop_stats_map_fd < 0)
        return 0;
    for (index = 0; index < count; index++) {
        if (bpf_map_lookup_elem(output->async_hop_stats_map_fd,
                                &index, &raw[index]))
            continue;
        copy_queue_diagnostic(&diagnostics[index], &raw[index],
                              index, output);
    }

    if (output->async_worker_stats_map_fd < 0 ||
        bpf_map_get_next_key(output->async_worker_stats_map_fd,
                             NULL, &next))
        return count;
    do {
        struct async_worker_stats worker;
        struct cw_queue_diagnostic *diagnostic;

        key = next;
        if (!bpf_map_lookup_elem(output->async_worker_stats_map_fd,
                                 &key, &worker) &&
            key.hop_index < count) {
            diagnostic = &diagnostics[key.hop_index];
            diagnostic->worker_count++;
            if (worker.started >
                diagnostic->busiest_worker_started) {
                diagnostic->busiest_worker_tid = worker.tid;
                diagnostic->busiest_worker_started = worker.started;
                diagnostic->busiest_worker_average_work_ns =
                    worker.completed ?
                        worker.work_total_ns / worker.completed : 0;
            }
        }
    } while (!bpf_map_get_next_key(output->async_worker_stats_map_fd,
                                    &key, &next));
    return count;
}

static const char *queue_diagnosis(
    const struct cw_queue_diagnostic *diagnostic,
    uint64_t submitted_delta, uint64_t started_delta)
{
    uint64_t anomalies = diagnostic->duplicate_keys +
        diagnostic->expired + diagnostic->dropped;

    if (!diagnostic->submitted)
        return "waiting for samples";
    if (diagnostic->pending && submitted_delta > started_delta)
        return "backlog growing";
    if (diagnostic->pending && diagnostic->active &&
        diagnostic->active >= diagnostic->peak_active)
        return "workers saturated";
    if (diagnostic->completed &&
        diagnostic->futex_waits * 4 >= diagnostic->completed)
        return "lock contention";
    if (anomalies)
        return "correlation loss observed";
    return "no clear bottleneck";
}

bool print_queue_diagnostics(struct output_options *output,
                                    bool final)
{
    struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS];
    struct async_hop_stats raw[MAX_ASYNC_HOPS];
    uint64_t now = monotonic_time_ns();
    uint64_t elapsed_ns = output->diagnostic_last_ns ?
        now - output->diagnostic_last_ns : 0;
    FILE *stream = output->json_output ? stderr : stdout;
    size_t count;
    size_t index;
    bool changed = false;

    count = read_queue_diagnostics(output, diagnostics, raw);
    for (index = 0; index < count; index++) {
        if (memcmp(&raw[index], &output->diagnostic_previous[index],
                   sizeof(raw[index]))) {
            changed = true;
            break;
        }
    }
    if (!changed && !final)
        return false;

    fprintf(stream, "\n[queue diagnostics%s]\n",
            final ? " final" : "");
    for (index = 0; index < count; index++) {
        const struct cw_queue_diagnostic *diagnostic =
            &diagnostics[index];
        uint64_t submitted_delta = raw[index].submitted -
            output->diagnostic_previous[index].submitted;
        uint64_t started_delta = raw[index].started -
            output->diagnostic_previous[index].started;
        uint64_t completed_delta = raw[index].completed -
            output->diagnostic_previous[index].completed;
        double seconds = elapsed_ns ?
            (double)elapsed_ns / 1000000000.0 : 0.0;
        char average_queue[32];
        char average_work[32];

        format_interval(
            average_queue, sizeof(average_queue),
            diagnostic->started ?
                diagnostic->queue_total_ns / diagnostic->started : 0);
        format_interval(
            average_work, sizeof(average_work),
            diagnostic->completed ?
                diagnostic->work_total_ns / diagnostic->completed : 0);
        fprintf(stream,
                "  hop %zu %s%s -> %s: "
                "rate %.1f/%.1f/%.1f per s, "
                "pending %llu (peak %llu), active %llu (peak %llu), "
                "average queue %s, average work %s, workers %u, %s\n",
                index, diagnostic->source,
                diagnostic->source_exit ? " completed" : " started",
                diagnostic->target,
                seconds ? submitted_delta / seconds : 0.0,
                seconds ? started_delta / seconds : 0.0,
                seconds ? completed_delta / seconds : 0.0,
                (unsigned long long)diagnostic->pending,
                (unsigned long long)diagnostic->peak_pending,
                (unsigned long long)diagnostic->active,
                (unsigned long long)diagnostic->peak_active,
                average_queue, average_work, diagnostic->worker_count,
                queue_diagnosis(diagnostic, submitted_delta,
                                started_delta));
        if (diagnostic->duplicate_keys || diagnostic->expired ||
            diagnostic->unmatched_targets || diagnostic->dropped) {
            fprintf(stream,
                    "    anomalies: duplicate=%llu expired=%llu "
                    "unmatched=%llu no-handoff=%llu\n",
                    (unsigned long long)diagnostic->duplicate_keys,
                    (unsigned long long)diagnostic->expired,
                    (unsigned long long)diagnostic->unmatched_targets,
                    (unsigned long long)diagnostic->dropped);
        }
    }
    fflush(stream);
    memcpy(output->diagnostic_previous, raw, sizeof(raw));
    output->diagnostic_last_ns = now;
    return true;
}

static void calculate_attribution(uint64_t duration_ns, uint64_t offcpu_ns,
                                  uint64_t blocked_ns, uint64_t runqueue_ns,
                                  uint64_t *oncpu_ns, uint64_t *unknown_ns)
{
    uint64_t classified_ns;

    if (offcpu_ns > duration_ns)
        offcpu_ns = duration_ns;
    classified_ns = blocked_ns + runqueue_ns;
    *unknown_ns = offcpu_ns > classified_ns ?
                  offcpu_ns - classified_ns : 0;
    *oncpu_ns = duration_ns - offcpu_ns;
}

static const char *dominant_attribution(uint64_t oncpu_ns,
                                        uint64_t blocked_ns,
                                        uint64_t runqueue_ns,
                                        uint64_t unknown_ns)
{
    const char *dominant = "on-CPU";
    uint64_t maximum = oncpu_ns;

    if (blocked_ns > maximum) {
        dominant = "blocked";
        maximum = blocked_ns;
    }
    if (runqueue_ns > maximum) {
        dominant = "run-queue";
        maximum = runqueue_ns;
    }
    if (unknown_ns > maximum)
        dominant = "preempt/unknown";
    return dominant;
}

static void print_attribution(uint64_t duration_ns, uint64_t offcpu_ns,
                              uint64_t blocked_ns, uint64_t runqueue_ns,
                              bool include_dominant)
{
    uint64_t oncpu_ns;
    uint64_t unknown_ns;

    calculate_attribution(duration_ns, offcpu_ns, blocked_ns, runqueue_ns,
                          &oncpu_ns, &unknown_ns);
    print_interval("oncpu", oncpu_ns);
    print_interval("offcpu", offcpu_ns > duration_ns ?
                   duration_ns : offcpu_ns);
    print_interval("blocked", blocked_ns);
    print_interval("runq", runqueue_ns);
    print_interval("preempt/unknown", unknown_ns);
    if (include_dominant)
        printf(" dominant=%s",
               dominant_attribution(oncpu_ns, blocked_ns, runqueue_ns,
                                    unknown_ns));
}

static void print_wait_resource(const struct wait_resource *wait,
                                const struct output_options *output,
                                const char *indent)
{
    struct map_list waker_maps = {0};
    uint64_t waker_stack[MAX_ASYNC_STACK_DEPTH] = {0};
    uint32_t maps_pid;

    if (wait->kind != WAIT_KIND_FUTEX || !wait->duration_ns)
        return;
    printf("%swait=futex operation=%s address=0x%016llx",
           indent, futex_operation_name(wait->operation),
           (unsigned long long)wait->address);
    print_interval("duration", wait->duration_ns);
    putchar('\n');
    if (!wait->waker_tid) {
        printf("%s  waker=unobserved (timeout, signal, or unmatched wake)\n",
               indent);
        return;
    }

    printf("%s  waker PID %u/TID %u (%.*s)",
           indent, wait->waker_pid, wait->waker_tid,
           (int)sizeof(wait->waker_comm), wait->waker_comm);
    if (wait->wake_ns)
        print_interval("wake-after-wait-start", wait->wake_ns);
    putchar('\n');
    if (wait->waker_pid != wait->waker_global_pid ||
        wait->waker_tid != wait->waker_global_tid)
        printf("%s  waker global PID %u/TID %u\n", indent,
               wait->waker_global_pid, wait->waker_global_tid);
    if (wait->waker_pidns_error)
        printf("%s  waker PID namespace translation failed: %s (%d)\n",
               indent, strerror(-wait->waker_pidns_error),
               wait->waker_pidns_error);
    if (wait->waker_stack_id < 0) {
        printf("%s  unable to collect waker user stack: %s (%d)\n",
               indent, strerror(-wait->waker_stack_id),
               wait->waker_stack_id);
        return;
    }
    if (output->wait_stack_map_fd < 0) {
        printf("%s  waker stack map is unavailable\n", indent);
        return;
    }
    if (bpf_map_lookup_elem(output->wait_stack_map_fd,
                            &wait->waker_stack_id, waker_stack)) {
        printf("%s  waker stack id %d is unavailable: %s\n",
               indent, wait->waker_stack_id, strerror(errno));
        return;
    }

    maps_pid = wait->waker_pid;
    if (read_process_maps(maps_pid, &waker_maps) &&
        wait->waker_global_pid != maps_pid) {
        map_list_free(&waker_maps);
        maps_pid = wait->waker_global_pid;
        read_process_maps(maps_pid, &waker_maps);
    }
    print_stack_frames(waker_stack, sizeof(waker_stack), &waker_maps,
                       "waker ", NULL, NULL, 0, output->control);
    map_list_free(&waker_maps);
}

static bool has_async_chain_filters(const struct output_options *output)
{
    return output->min_total_ns || output->min_queue_ns ||
           output->min_work_ns || output->max_events;
}

static bool async_chain_matches(const struct stack_trace_event *event,
                                const struct output_options *output)
{
    uint64_t total_ns = 0;
    uint64_t maximum_queue_ns = 0;
    uint64_t maximum_work_ns = 0;
    uint32_t count = event->async_hop_count;
    uint32_t index;

    if (!count)
        return false;
    if (count > MAX_ASYNC_HOPS)
        count = MAX_ASYNC_HOPS;
    for (index = 0; index < count; index++) {
        const struct async_hop_event *hop = &event->async_hops[index];

        if (UINT64_MAX - total_ns < hop->queue_ns)
            total_ns = UINT64_MAX;
        else
            total_ns += hop->queue_ns;
        if (UINT64_MAX - total_ns < hop->target_ns)
            total_ns = UINT64_MAX;
        else
            total_ns += hop->target_ns;
        if (hop->queue_ns > maximum_queue_ns)
            maximum_queue_ns = hop->queue_ns;
        if (hop->target_ns > maximum_work_ns)
            maximum_work_ns = hop->target_ns;
    }

    return total_ns >= output->min_total_ns &&
           maximum_queue_ns >= output->min_queue_ns &&
           maximum_work_ns >= output->min_work_ns;
}

static uint64_t event_realtime_milliseconds(uint64_t timestamp_ns)
{
    return event_realtime_nanoseconds(timestamp_ns) / 1000000ULL;
}

static bool calculate_libuv_handoff(
    const struct async_hop_event *hop,
    uint64_t *publish_ns, uint64_t *notify_ns,
    uint64_t *loop_ns, uint64_t *poll_ns,
    uint64_t *dispatch_ns)
{
    uint64_t notify_boundary_ns;
    uint64_t target_entry_ns;

    *publish_ns = 0;
    *notify_ns = 0;
    *loop_ns = 0;
    *poll_ns = 0;
    *dispatch_ns = 0;
    if (hop->lifecycle_kind != CW_ASYNC_HANDOFF_LIBUV ||
        !(hop->lifecycle_flags & CW_ASYNC_LIFECYCLE_NOTIFY_ENTRY) ||
        hop->notify_entry_ns < hop->source_ns ||
        UINT64_MAX - hop->source_ns < hop->queue_ns)
        return false;
    target_entry_ns = hop->source_ns + hop->queue_ns;
    if (hop->notify_entry_ns > target_entry_ns)
        return false;

    *publish_ns = hop->notify_entry_ns - hop->source_ns;
    notify_boundary_ns = hop->notify_entry_ns;
    if ((hop->lifecycle_flags & CW_ASYNC_LIFECYCLE_NOTIFY_EXIT) &&
        hop->notify_exit_ns >= hop->notify_entry_ns &&
        hop->notify_exit_ns <= target_entry_ns) {
        *notify_ns = hop->notify_exit_ns - hop->notify_entry_ns;
        notify_boundary_ns = hop->notify_exit_ns;
    }
    if ((hop->lifecycle_flags & CW_ASYNC_LIFECYCLE_EPOLL_EXIT) &&
        hop->epoll_exit_ns >= notify_boundary_ns &&
        hop->epoll_exit_ns <= target_entry_ns) {
        if (hop->epoll_enter_ns > notify_boundary_ns &&
            hop->epoll_enter_ns <= hop->epoll_exit_ns) {
            *loop_ns = hop->epoll_enter_ns - notify_boundary_ns;
            *poll_ns = hop->epoll_exit_ns - hop->epoll_enter_ns;
        } else {
            *poll_ns = hop->epoll_exit_ns - notify_boundary_ns;
        }
        *dispatch_ns = target_entry_ns - hop->epoll_exit_ns;
    } else {
        *loop_ns = target_entry_ns - notify_boundary_ns;
    }
    return true;
}

static void copy_report_comm(char destination[17],
                             const char source[16])
{
    memcpy(destination, source, 16);
    destination[16] = '\0';
}

static void build_report_chain(const struct stack_trace_event *event,
                               const struct output_options *output,
                               struct cw_report_chain *chain)
{
    uint32_t hop_count = event->async_hop_count;
    uint32_t hop_index;

    memset(chain, 0, sizeof(*chain));
    chain->timestamp_ms =
        event_realtime_milliseconds(event->timestamp_ns);
    chain->pid = event->pid;
    chain->tid = event->tid;
    copy_report_comm(chain->comm, event->comm);
    chain->duration_ns = event->duration_ns;
    chain->offcpu_ns = event->offcpu_ns;
    chain->blocked_ns = event->blocked_ns;
    chain->runqueue_ns = event->runqueue_ns;
    chain->truncated = event->async_truncated;
    if (hop_count > CW_REPORT_MAX_HOPS)
        hop_count = CW_REPORT_MAX_HOPS;
    chain->hop_count = hop_count;

    for (hop_index = 0; hop_index < hop_count; hop_index++) {
        const struct async_hop_event *source =
            &event->async_hops[hop_index];
        struct cw_report_hop *destination =
            &chain->hops[hop_index];
        uint32_t hop_id = source->reserved & ASYNC_HOP_ID_MASK;
        uint32_t configured_hop =
            hop_id ? hop_id - 1 : hop_index;

        destination->index = configured_hop;
        destination->pid = source->pid;
        destination->tid = source->tid;
        destination->target_tid =
            hop_index + 1 < hop_count ?
                event->async_hops[hop_index + 1].tid : event->tid;
        destination->target_arg =
            source->reserved >> ASYNC_TARGET_ARG_SHIFT;
        copy_report_comm(destination->comm, source->comm);
        if (configured_hop < output->async_hop_count) {
            destination->source =
                output->async_hops[configured_hop].source;
            destination->target =
                output->async_hops[configured_hop].target;
            destination->source_exit =
                output->async_hops[configured_hop].source_exit;
        } else {
            destination->source =
                output->async_source_name ?
                    output->async_source_name : "source";
            destination->target =
                output->final_target_name ?
                    output->final_target_name : "target";
        }
        destination->key = source->key;
        destination->queue_ns = source->queue_ns;
        destination->handoff_kind = source->lifecycle_kind;
        destination->handoff_flags = source->lifecycle_flags;
        (void)calculate_libuv_handoff(
            source, &destination->publish_ns,
            &destination->notify_ns, &destination->loop_ns,
            &destination->poll_ns,
            &destination->dispatch_ns);
        destination->work_ns = source->target_ns;
        destination->offcpu_ns = source->offcpu_ns;
        destination->blocked_ns = source->blocked_ns;
        destination->runqueue_ns = source->runqueue_ns;
        destination->wait_kind = source->wait.kind;
        destination->wait_operation = source->wait.operation;
        destination->wait_address = source->wait.address;
        destination->wait_duration_ns = source->wait.duration_ns;
        destination->wait_wake_ns = source->wait.wake_ns;
        destination->waker_pid = source->wait.waker_pid;
        destination->waker_tid = source->wait.waker_tid;
        copy_report_comm(destination->waker_comm,
                         source->wait.waker_comm);
    }
}

static void export_completed_chain(const struct stack_trace_event *event,
                                   struct output_options *output)
{
    struct cw_report_chain chain;
    bool failed = false;

    if ((!output->json_stream && !output->report_stream) ||
        output->export_failed)
        return;
    build_report_chain(event, output, &chain);
    if (output->json_stream) {
        failed = cw_write_chain_json(output->json_stream, &chain) ||
                 fputc('\n', output->json_stream) == EOF ||
                 fflush(output->json_stream);
    }
    if (!failed && output->report_stream) {
        failed = cw_html_report_write(output->report_stream, &chain,
                                      &output->report_first) ||
                 fflush(output->report_stream);
    }
    if (failed) {
        fprintf(stderr, "failed to write trace export: %s\n",
                strerror(errno ? errno : EIO));
        output->export_failed = true;
        cw_capture_request_stop(output->control, CW_STOP_OUTPUT_ERROR);
    }
}

static void count_completed_chain(struct output_options *output)
{
    output->emitted_events++;
    if (output->max_events &&
        output->emitted_events >= output->max_events)
        cw_capture_request_stop(output->control, CW_STOP_MAX_EVENTS);
}

int handle_event(void *context, void *data, size_t data_size)
{
    const struct stack_trace_event *event = data;
    struct output_options *output = context;
    struct map_list maps = {0};
    size_t header_size = offsetof(struct stack_trace_event, stack);
    size_t entry_size = sizeof(*event);
    uint32_t maps_pid;

    if (!cw_capture_running(output->control))
        return 0;
    if (data_size < header_size) {
        fprintf(stderr,
                "short event header received: %zu bytes (expected %zu)\n",
                data_size, header_size);
        return 0;
    }
    if (output->show_async && has_async_chain_filters(output)) {
        if (event->event_type == EVENT_ENTRY)
            return 0;
        if (event->event_type == EVENT_RETURN &&
            !async_chain_matches(event, output))
            return 0;
    }
    if (event->event_type == EVENT_RETURN && event->async_hop_count) {
        export_completed_chain(event, output);
        if (output->json_output) {
            count_completed_chain(output);
            return 0;
        }
    } else if (output->json_output) {
        return 0;
    }
    maps_pid = event->pid;

    print_event_time(event->timestamp_ns);
    printf("PID %u/TID %u (%.*s)", event->pid, event->tid,
           (int)sizeof(event->comm), event->comm);
    if (event->event_type == EVENT_RETURN) {
        printf(" RETURN");
        if (output->show_return_value)
            printf(" ret=0x%016llx (%lld)",
                   (unsigned long long)(uint64_t)event->return_value,
                   (long long)event->return_value);
        if (output->show_duration)
            print_interval("duration", event->duration_ns);
        if (output->show_attribution)
            print_attribution(event->duration_ns, event->offcpu_ns,
                              event->blocked_ns, event->runqueue_ns, false);
        putchar('\n');
        if (output->show_attribution &&
            !(output->show_async && event->async_hop_count))
            print_wait_resource(&event->wait, output, "  ");
    } else {
        if (output->show_return_value || output->show_duration)
            printf(" ENTRY");
        putchar('\n');
    }
    if (event->pidns_error) {
        fprintf(stderr,
                "warning: PID namespace translation failed: %s (%d); "
                "using global PID %u\n",
                strerror(-event->pidns_error), event->pidns_error,
                event->global_pid);
    } else if (event->pid != event->global_pid ||
               event->tid != event->global_tid) {
        printf("  global PID %u/TID %u\n",
               event->global_pid, event->global_tid);
    }
    fflush(stdout);

    if (event->event_type != EVENT_ENTRY) {
        if (event->event_type != EVENT_RETURN) {
            fprintf(stderr, "unknown event type: %u\n", event->event_type);
            return 0;
        }
    }
    if (event->event_type == EVENT_ENTRY && data_size < entry_size) {
        fprintf(stderr, "short entry event received: %zu bytes (expected %zu)\n",
                data_size, entry_size);
        return 0;
    }
    if ((event->event_type == EVENT_ENTRY ||
         (output->show_async && event->async_hop_count)) &&
        read_process_maps(maps_pid, &maps)) {
        int maps_error = errno;

        if (event->global_pid != maps_pid) {
            map_list_free(&maps);
            if (!read_process_maps(event->global_pid, &maps)) {
                maps_pid = event->global_pid;
                printf("  using global /proc/%u/maps\n", maps_pid);
                maps_error = 0;
            }
        }
        if (maps_error) {
            fflush(stdout);
            fprintf(stderr, "warning: cannot read /proc/%u/maps: %s\n",
                    maps_pid, strerror(maps_error));
        }
    }

    if (output->show_async && event->async_hop_count) {
        uint32_t hop_count = event->async_hop_count;
        uint32_t hop_index;

        if (hop_count > MAX_ASYNC_HOPS)
            hop_count = MAX_ASYNC_HOPS;
        if (event->async_truncated)
            printf("  ... %u earlier async hop(s) truncated ...\n",
                   event->async_truncated);
        for (hop_index = 0; hop_index < hop_count; hop_index++) {
            const struct async_hop_event *hop =
                &event->async_hops[hop_index];
            uint64_t async_stack[MAX_ASYNC_STACK_DEPTH] = {0};
            uint32_t hop_id = hop->reserved & ASYNC_HOP_ID_MASK;
            uint32_t configured_hop =
                hop_id ? hop_id - 1 : hop_index;
            uint32_t matched_target_arg =
                hop->reserved >> ASYNC_TARGET_ARG_SHIFT;

            const char *source_name = output->async_source_name;
            const char *target_name = output->final_target_name;

            if (configured_hop < output->async_hop_count) {
                source_name = output->async_hops[configured_hop].source;
                target_name = output->async_hops[configured_hop].target;
            }
            printf("  async hop %u %s%s -> %s PID %u/TID %u (%.*s) "
                   "key=0x%016llx target-arg=%u\n",
                   configured_hop,
                   source_name ? source_name : "source",
                   configured_hop < output->async_hop_count &&
                           output->async_hops[configured_hop].source_exit ?
                       " completed" : " started",
                   target_name ? target_name : "target",
                   hop->pid, hop->tid,
                   (int)sizeof(hop->comm), hop->comm,
                   (unsigned long long)hop->key,
                   matched_target_arg);
            printf("    ");
            print_interval("queue", hop->queue_ns);
            if (hop->target_ns) {
                print_interval("work", hop->target_ns);
                print_attribution(hop->target_ns, hop->offcpu_ns,
                                  hop->blocked_ns, hop->runqueue_ns, true);
            } else {
                printf(" work=unavailable");
            }
            putchar('\n');
            if (hop->lifecycle_kind == CW_ASYNC_HANDOFF_LIBUV) {
                uint64_t publish_ns;
                uint64_t notify_ns;
                uint64_t loop_ns;
                uint64_t poll_ns;
                uint64_t dispatch_ns;

                printf("    libuv handoff:");
                if (calculate_libuv_handoff(
                        hop, &publish_ns, &notify_ns,
                        &loop_ns, &poll_ns, &dispatch_ns)) {
                    print_interval("completion-publish", publish_ns);
                    if (hop->lifecycle_flags &
                        CW_ASYNC_LIFECYCLE_NOTIFY_EXIT)
                        print_interval("uv_async_send", notify_ns);
                    else
                        printf(" uv_async_send=exit-unobserved");
                    if (hop->lifecycle_flags &
                        CW_ASYNC_LIFECYCLE_EPOLL_EXIT) {
                        if (loop_ns)
                            print_interval("loop-active/backlog", loop_ns);
                        print_interval("epoll-wait/wakeup", poll_ns);
                        print_interval("ready-to-callback", dispatch_ns);
                    } else {
                        print_interval("loop-active/backlog", loop_ns);
                        printf(" (no epoll return observed)");
                    }
                } else {
                    printf(" notification boundary unavailable");
                }
                putchar('\n');
            }
            print_wait_resource(&hop->wait, output, "    ");
            if (hop->pid != hop->global_pid ||
                hop->tid != hop->global_tid)
                printf("  async global PID %u/TID %u\n",
                       hop->global_pid, hop->global_tid);
            if (hop->stack_id < 0) {
                printf("  async unable to collect user stack: %s (%d)\n",
                       strerror(-hop->stack_id), hop->stack_id);
            } else if (output->async_stack_map_fd < 0) {
                printf("  async stack map is unavailable\n");
            } else if (bpf_map_lookup_elem(output->async_stack_map_fd,
                                           &hop->stack_id,
                                           async_stack)) {
                printf("  async stack id %d is unavailable: %s\n",
                       hop->stack_id, strerror(errno));
            } else {
                print_stack_frames(async_stack, sizeof(async_stack),
                                   &maps, "async ", NULL, NULL, 0,
                                   output->control);
            }
        }
    }
    if (output->show_discovery && event->discovery_valid) {
        const struct discovery_wakeup *waker = &event->discovery_waker;
        struct map_list waker_maps = {0};
        uint64_t waker_stack[MAX_ASYNC_STACK_DEPTH] = {0};
        char candidate[256] = {0};
        uint32_t waker_maps_pid = waker->pid;

        printf("  async discovery: latest waker PID %u/TID %u (%.*s)",
               waker->pid, waker->tid, (int)sizeof(waker->comm),
               waker->comm);
        print_interval("wake-to-target", event->discovery_wakeup_ns);
        putchar('\n');
        if (waker->pid != waker->global_pid ||
            waker->tid != waker->global_tid)
            printf("  waker global PID %u/TID %u\n",
                   waker->global_pid, waker->global_tid);
        if (waker->pidns_error)
            printf("  waker PID namespace translation failed: %s (%d)\n",
                   strerror(-waker->pidns_error), waker->pidns_error);

        if (read_process_maps(waker_maps_pid, &waker_maps) &&
            waker->global_pid != waker_maps_pid) {
            map_list_free(&waker_maps);
            waker_maps_pid = waker->global_pid;
            read_process_maps(waker_maps_pid, &waker_maps);
        }

        if (waker->stack_id < 0) {
            printf("  unable to collect waker user stack: %s (%d)\n",
                   strerror(-waker->stack_id), waker->stack_id);
        } else if (output->discovery_stack_map_fd < 0) {
            printf("  discovery stack map is unavailable\n");
        } else if (bpf_map_lookup_elem(output->discovery_stack_map_fd,
                                       &waker->stack_id, waker_stack)) {
            printf("  discovery stack id %d is unavailable: %s\n",
                   waker->stack_id, strerror(errno));
        } else {
            print_stack_frames(waker_stack, sizeof(waker_stack),
                               &waker_maps, "waker ",
                               output->target_path, candidate,
                               sizeof(candidate), output->control);
        }

        if (candidate[0]) {
            printf("  candidate source function: %s\n", candidate);
            if (output->discovery_target_arg) {
                printf("  suggested template:\n"
                       "    --async-hop %s,?,%s,%u %s\n",
                       candidate,
                       output->final_target_name ?
                           output->final_target_name : "TARGET",
                       output->discovery_target_arg,
                       output->final_target_name ?
                           output->final_target_name : "TARGET");
            } else {
                printf("  suggested template:\n"
                       "    --async-hop %s,?,%s %s\n",
                       candidate,
                       output->final_target_name ?
                           output->final_target_name : "TARGET",
                       output->final_target_name ?
                           output->final_target_name : "TARGET");
            }
        } else {
            printf("  no source symbol was inferred; inspect the waker "
                   "stack and choose the enqueue/submit frame\n");
        }
        map_list_free(&waker_maps);
    }
    if (event->event_type == EVENT_RETURN) {
        if (output->show_async && event->async_hop_count)
            count_completed_chain(output);
        putchar('\n');
        map_list_free(&maps);
        return 0;
    }
    print_stack_frames(event->stack, event->stack_size, &maps, "",
                       NULL, NULL, 0, output->control);
    putchar('\n');

    map_list_free(&maps);
    return 0;
}
