// SPDX-License-Identifier: MIT

#include "runtime_report.h"

#include "callweave_internal.h"
#include "report.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define CW_RUNTIME_REPORT_MAX_RECORDS 2048
#define CW_RUNTIME_LABEL_SIZE 96

struct cw_runtime_record {
    struct cw_report_chain chain;
    char name[160];
    char source[CW_REPORT_MAX_HOPS][CW_RUNTIME_LABEL_SIZE];
    char target[CW_REPORT_MAX_HOPS][CW_RUNTIME_LABEL_SIZE];
    uint64_t match_ns;
    uint64_t match_id;
    uint64_t match_data;
    int fd;
    char match_comm[17];
    bool completion_added;
    bool callback_added;
};

struct cw_runtime_report {
    char mode[16];
    struct cw_runtime_record **records;
    size_t count;
    size_t capacity;
    size_t dropped;
};

static const char *callback_role(const struct cw_runtime_report *report)
{
    if (!report)
        return "callback";
    if (!strcmp(report->mode, "io_uring"))
        return "io_uring_callback";
    if (!strcmp(report->mode, "libuv"))
        return "libuv_callback";
    if (!strcmp(report->mode, "libevent"))
        return "libevent_callback";
    if (!strcmp(report->mode, "epoll"))
        return "epoll_callback";
    return "callback";
}

static void format_callback_label(
    const struct cw_runtime_report *report, const char *callback_name,
    char *label, size_t label_size)
{
    snprintf(label, label_size, "%s (%s)", callback_role(report),
             callback_name && callback_name[0] ?
                 callback_name : "application_callback");
}

static void copy_comm(char destination[17], const char source[16])
{
    memcpy(destination, source, 16);
    destination[16] = '\0';
}

static uint64_t realtime_milliseconds(uint64_t timestamp_ns)
{
    return event_realtime_nanoseconds(timestamp_ns) / 1000000ULL;
}

static struct cw_runtime_record *new_record(
    struct cw_runtime_report *report)
{
    struct cw_runtime_record *record;

    if (!report)
        return NULL;
    if (report->count >= CW_RUNTIME_REPORT_MAX_RECORDS) {
        report->dropped++;
        return NULL;
    }
    if (report->count == report->capacity) {
        size_t capacity = report->capacity ? report->capacity * 2 : 64;
        struct cw_runtime_record **records;

        if (capacity > CW_RUNTIME_REPORT_MAX_RECORDS)
            capacity = CW_RUNTIME_REPORT_MAX_RECORDS;
        records = realloc(report->records, capacity * sizeof(*records));
        if (!records)
            return NULL;
        report->records = records;
        report->capacity = capacity;
    }
    record = calloc(1, sizeof(*record));
    if (!record)
        return NULL;
    record->fd = -1;
    record->chain.kind = report->mode;
    record->chain.name = record->name;
    report->records[report->count++] = record;
    return record;
}

static struct cw_report_hop *add_hop(
    struct cw_runtime_record *record, const char *source,
    const char *target)
{
    uint32_t index = record->chain.hop_count;
    struct cw_report_hop *hop;

    if (index >= CW_REPORT_MAX_HOPS)
        return NULL;
    snprintf(record->source[index], sizeof(record->source[index]),
             "%s", source ? source : "source");
    snprintf(record->target[index], sizeof(record->target[index]),
             "%s", target ? target : "target");
    hop = &record->chain.hops[index];
    hop->index = index;
    hop->source = record->source[index];
    hop->target = record->target[index];
    record->chain.hop_count++;
    return hop;
}

static struct cw_report_hop *prepend_hop(
    struct cw_runtime_record *record, const char *source,
    const char *target)
{
    uint32_t count = record->chain.hop_count;
    uint32_t index;

    if (count >= CW_REPORT_MAX_HOPS)
        return NULL;
    for (index = count; index > 0; index--) {
        record->chain.hops[index] = record->chain.hops[index - 1];
        memcpy(record->source[index], record->source[index - 1],
               sizeof(record->source[index]));
        memcpy(record->target[index], record->target[index - 1],
               sizeof(record->target[index]));
    }
    memset(&record->chain.hops[0], 0, sizeof(record->chain.hops[0]));
    snprintf(record->source[0], sizeof(record->source[0]), "%s",
             source ? source : "source");
    snprintf(record->target[0], sizeof(record->target[0]), "%s",
             target ? target : "target");
    record->chain.hop_count++;
    for (index = 0; index < record->chain.hop_count; index++) {
        record->chain.hops[index].index = index;
        record->chain.hops[index].source = record->source[index];
        record->chain.hops[index].target = record->target[index];
    }
    return &record->chain.hops[0];
}

static void update_duration(struct cw_runtime_record *record)
{
    uint64_t duration = 0;
    uint32_t index;

    for (index = 0; index < record->chain.hop_count; index++)
        duration += record->chain.hops[index].queue_ns +
                    record->chain.hops[index].work_ns;
    record->chain.duration_ns = duration;
}

static const char *epoll_wait_name(uint32_t kind)
{
    switch (kind) {
    case CW_EPOLL_PWAIT:
        return "epoll_pwait";
    case CW_EPOLL_PWAIT2:
        return "epoll_pwait2";
    case CW_EPOLL_WAIT:
    default:
        return "epoll_wait";
    }
}

static const char *io_dispatch_name(int operation)
{
    switch (operation) {
    case CW_EPOLL_IO_READ:
        return "read";
    case CW_EPOLL_IO_READV:
        return "readv";
    case CW_EPOLL_IO_RECVFROM:
        return "recvfrom";
    case CW_EPOLL_IO_RECVMSG:
        return "recvmsg";
    case CW_EPOLL_IO_RECVMMSG:
        return "recvmmsg";
    case CW_EPOLL_IO_WRITE:
        return "write";
    case CW_EPOLL_IO_WRITEV:
        return "writev";
    case CW_EPOLL_IO_SENDTO:
        return "sendto";
    case CW_EPOLL_IO_SENDMSG:
        return "sendmsg";
    case CW_EPOLL_IO_SENDMMSG:
        return "sendmmsg";
    case CW_EPOLL_IO_ACCEPT:
        return "accept";
    case CW_EPOLL_IO_ACCEPT4:
        return "accept4";
    case CW_EPOLL_IO_CONNECT:
        return "connect";
    case CW_EPOLL_IO_CLOSE:
        return "close";
    default:
        return "I/O dispatch";
    }
}

static const char *wake_action_name(uint32_t action)
{
    switch (action) {
    case CW_EPOLL_WAKE_ACTION_EVENTFD_WRITE:
        return "eventfd_write";
    case CW_EPOLL_WAKE_ACTION_TIMERFD_ARM:
        return "timerfd_arm";
    case CW_EPOLL_WAKE_ACTION_SIGNAL_SEND:
        return "signal_send";
    default:
        return "wake source";
    }
}

struct cw_runtime_report *cw_runtime_report_create(const char *mode)
{
    struct cw_runtime_report *report = calloc(1, sizeof(*report));

    if (!report)
        return NULL;
    snprintf(report->mode, sizeof(report->mode), "%s",
             mode ? mode : "runtime");
    return report;
}

void cw_runtime_report_destroy(struct cw_runtime_report *report)
{
    size_t index;

    if (!report)
        return;
    for (index = 0; index < report->count; index++)
        free(report->records[index]);
    free(report->records);
    free(report);
}

int cw_runtime_report_capture_io_uring(
    struct cw_runtime_report *report,
    const struct io_uring_event *event,
    const char *operation)
{
    struct cw_runtime_record *record = NULL;
    struct cw_report_hop *hop;
    char source[CW_RUNTIME_LABEL_SIZE];
    char target[CW_RUNTIME_LABEL_SIZE];
    uint64_t queued;
    size_t index;

    if (!operation)
        operation = "IO";
    if (!report)
        return 0;
    for (index = report->count; index > 0; index--) {
        struct cw_runtime_record *candidate = report->records[index - 1];

        if (candidate->match_id == event->request &&
            candidate->match_data == event->user_data &&
            candidate->callback_added &&
            !candidate->completion_added) {
            record = candidate;
            break;
        }
    }
    if (!record)
        record = new_record(report);
    if (!record)
        return report && report->count >= CW_RUNTIME_REPORT_MAX_RECORDS ? 0 : -1;
    record->match_id = event->request;
    record->match_data = event->user_data;
    record->fd = event->fd;
    snprintf(record->name, sizeof(record->name),
             record->callback_added ?
                 "%s user_data=0x%llx result=%d -> callback" :
                 "%s user_data=0x%llx result=%d",
             operation, (unsigned long long)event->user_data,
             event->result);
    record->chain.timestamp_ms = realtime_milliseconds(event->timestamp_ns);
    if (!record->callback_added) {
        record->chain.pid = event->submit_global_pid;
        record->chain.tid = event->submit_global_tid;
        copy_comm(record->chain.comm, event->submit_comm);
    }
    copy_comm(record->match_comm, event->complete_comm);
    snprintf(source, sizeof(source), "SQE %s", operation);
    snprintf(target, sizeof(target), "CQE result=%d", event->result);
    hop = record->callback_added ?
        prepend_hop(record, source, target) :
        add_hop(record, source, target);
    if (!hop)
        return -1;
    queued = event->defer_delay_ns + event->io_wq_queue_ns;
    if (queued < event->defer_delay_ns || queued > event->duration_ns)
        queued = event->duration_ns;
    hop->pid = event->submit_global_pid;
    hop->tid = event->submit_global_tid;
    hop->target_tid = event->complete_global_tid;
    copy_comm(hop->comm, event->submit_comm);
    hop->key = event->user_data;
    hop->queue_ns = queued;
    hop->work_ns = event->duration_ns - queued;
    hop->work_kind = CW_REPORT_WORK_IN_FLIGHT;
    record->completion_added = true;
    update_duration(record);
    return 0;
}

int cw_runtime_report_capture_io_uring_callback(
    struct cw_runtime_report *report,
    const struct io_uring_callback_event *event,
    const char *operation,
    const char *callback_name,
    bool allow_pending)
{
    struct cw_runtime_record *record = NULL;
    struct cw_report_hop *hop;
    char callback_label[CW_RUNTIME_LABEL_SIZE];
    size_t index;

    if (!report)
        return 0;
    if (!operation)
        operation = "IO";
    for (index = report->count; index > 0; index--) {
        struct cw_runtime_record *candidate = report->records[index - 1];

        if (candidate->match_id == event->request &&
            candidate->match_data == event->user_data &&
            !candidate->callback_added) {
            record = candidate;
            break;
        }
    }
    if (!record) {
        if (!allow_pending)
            return 0;
        record = new_record(report);
        if (!record)
            return report->count >= CW_RUNTIME_REPORT_MAX_RECORDS ? 0 : -1;
        record->match_id = event->request;
        record->match_data = event->user_data;
        record->chain.timestamp_ms =
            realtime_milliseconds(event->timestamp_ns);
        record->chain.pid = event->pid;
        record->chain.tid = event->tid;
        copy_comm(record->chain.comm, event->comm);
        snprintf(record->name, sizeof(record->name),
                 "%s CQE to callback", operation);
    } else {
        snprintf(record->name, sizeof(record->name),
                 "%s user_data=0x%llx → callback",
                 operation,
                 (unsigned long long)event->user_data);
    }
    format_callback_label(
        report, callback_name, callback_label, sizeof(callback_label));
    hop = add_hop(record, "CQE complete", callback_label);
    if (!hop)
        return -1;
    hop->pid = event->global_pid;
    hop->tid = record->chain.hop_count > 1 ?
        record->chain.hops[record->chain.hop_count - 2].target_tid :
        event->global_tid;
    hop->target_tid = event->global_tid;
    if (record->match_comm[0])
        snprintf(hop->comm, sizeof(hop->comm), "%s", record->match_comm);
    else
        copy_comm(hop->comm, event->comm);
    hop->key = event->user_data;
    hop->queue_ns = event->callback_delay_ns;
    record->chain.pid = event->global_pid;
    record->chain.tid = event->global_tid;
    copy_comm(record->chain.comm, event->comm);
    record->callback_added = true;
    update_duration(record);
    return 0;
}

static struct cw_runtime_record *find_epoll_record(
    struct cw_runtime_report *report, uint64_t ready_ns,
    int fd, uint64_t data)
{
    size_t index;

    for (index = report->count; index > 0; index--) {
        struct cw_runtime_record *record = report->records[index - 1];

        if (record->match_ns == ready_ns &&
            (record->fd == fd || (data && record->match_data == data)) &&
            !record->callback_added)
            return record;
    }
    return NULL;
}

static struct cw_runtime_record *new_epoll_record(
    struct cw_runtime_report *report, uint64_t timestamp_ns,
    uint32_t pid, uint32_t tid, const char comm[16],
    int fd, uint64_t data)
{
    struct cw_runtime_record *record = new_record(report);

    if (!record)
        return NULL;
    record->match_ns = timestamp_ns;
    record->match_data = data;
    record->fd = fd;
    record->chain.timestamp_ms = realtime_milliseconds(timestamp_ns);
    record->chain.pid = pid;
    record->chain.tid = tid;
    copy_comm(record->chain.comm, comm);
    return record;
}

int cw_runtime_report_capture_epoll_wait(
    struct cw_runtime_report *report,
    const struct cw_epoll_event *event)
{
    uint32_t count = event->captured_events;
    uint32_t index;

    if (!report)
        return 0;
    if (!count && event->result == 0)
        count = 1;
    for (index = 0; index < count; index++) {
        const struct cw_epoll_ready *ready =
            event->captured_events ? &event->ready[index] : NULL;
        int fd = ready ? ready->fd : -1;
        uint64_t data = ready ? ready->data : 0;
        struct cw_runtime_record *record = new_epoll_record(
            report, event->timestamp_ns, event->pid, event->tid,
            event->comm, fd, data);
        struct cw_report_hop *hop;
        char target[CW_RUNTIME_LABEL_SIZE];

        if (!record)
            return report->count >= CW_RUNTIME_REPORT_MAX_RECORDS ? 0 : -1;
        if (ready) {
            snprintf(record->name, sizeof(record->name),
                     "ready fd=%d events=0x%x", fd, ready->events);
            snprintf(target, sizeof(target), "ready fd=%d", fd);
        } else {
            snprintf(record->name, sizeof(record->name), "wait timeout");
            snprintf(target, sizeof(target), "timeout");
        }
        hop = add_hop(record, epoll_wait_name(event->wait_kind), target);
        if (!hop)
            return -1;
        hop->pid = event->pid;
        hop->tid = event->tid;
        hop->target_tid = event->tid;
        copy_comm(hop->comm, event->comm);
        hop->key = data;
        hop->queue_ns = event->wait_ns;
        update_duration(record);
    }
    return 0;
}

int cw_runtime_report_capture_epoll_dispatch(
    struct cw_runtime_report *report,
    const struct cw_epoll_dispatch_event *event)
{
    const struct cw_epoll_dispatch_item *item = &event->item;
    struct cw_runtime_record *record;
    struct cw_report_hop *hop;
    uint64_t delay;
    const char *operation;

    if (!report)
        return 0;
    record = find_epoll_record(
        report, item->ready_ns, item->fd, item->data);
    if (!record)
        record = new_epoll_record(
            report, item->ready_ns, event->pid, event->tid,
            event->comm, item->fd, item->data);
    if (!record)
        return report->count >= CW_RUNTIME_REPORT_MAX_RECORDS ? 0 : -1;
    operation = item->flags & CW_EPOLL_DISPATCH_CONSUMED ?
        io_dispatch_name(item->first_operation) : "no matching I/O";
    snprintf(record->name, sizeof(record->name),
             "fd=%d → %s", item->fd, operation);
    hop = add_hop(record, "ready event", operation);
    if (!hop)
        return -1;
    delay = item->first_io_ns > item->ready_ns ?
        item->first_io_ns - item->ready_ns : event->return_to_wait_ns;
    hop->pid = event->pid;
    hop->tid = event->tid;
    hop->target_tid = event->tid;
    copy_comm(hop->comm, event->comm);
    hop->key = item->data;
    hop->queue_ns = delay;
    hop->work_ns = item->total_io_ns;
    hop->work_kind = CW_REPORT_WORK_IO;
    record->callback_added = true;
    update_duration(record);
    return 0;
}

int cw_runtime_report_capture_epoll_callback(
    struct cw_runtime_report *report,
    const struct cw_epoll_callback_event *event,
    const char *callback_name)
{
    struct cw_runtime_record *record;
    struct cw_report_hop *hop;
    char callback_label[CW_RUNTIME_LABEL_SIZE];
    const char *name = callback_label;

    if (!report)
        return 0;
    record = find_epoll_record(
        report, event->ready_ns, event->fd, event->data);
    if (!record)
        record = new_epoll_record(
            report, event->ready_ns, event->pid, event->tid,
            event->comm, event->fd, event->data);
    if (!record)
        return report->count >= CW_RUNTIME_REPORT_MAX_RECORDS ? 0 : -1;
    format_callback_label(
        report, callback_name, callback_label, sizeof(callback_label));
    if (event->wake.action &&
        (event->wake.flags & CW_EPOLL_WAKE_LATENCY_VALID) &&
        record->chain.hop_count) {
        struct cw_report_hop *wake = &record->chain.hops[0];

        snprintf(record->source[0], sizeof(record->source[0]), "%s",
                 wake_action_name(event->wake.action));
        snprintf(record->target[0], sizeof(record->target[0]),
                 "ready fd=%d", event->fd);
        wake->pid = event->wake.source_pid;
        wake->tid = event->wake.source_tid;
        wake->target_tid = event->tid;
        copy_comm(wake->comm, event->wake.comm);
        wake->queue_ns = event->wake.latency_ns;
        wake->work_ns = 0;
    }
    snprintf(record->name, sizeof(record->name),
             "%s fd=%d", name, event->fd);
    hop = add_hop(record, "ready event", name);
    if (!hop)
        return -1;
    hop->pid = event->pid;
    hop->tid = event->tid;
    hop->target_tid = event->tid;
    copy_comm(hop->comm, event->comm);
    hop->key = event->callback_key ? event->callback_key : event->data;
    hop->queue_ns = event->delay_ns;
    hop->work_ns = event->duration_ns;
    hop->offcpu_ns = event->offcpu_ns;
    hop->blocked_ns = event->blocked_ns;
    hop->runqueue_ns = event->runqueue_ns;
    if (event->futex_waits && event->longest_futex_wait.duration_ns) {
        hop->wait_kind = 1;
        hop->wait_operation = event->longest_futex_wait.operation;
        hop->wait_address = event->longest_futex_wait.address;
        hop->wait_duration_ns = event->longest_futex_wait.duration_ns;
        hop->wait_wake_ns = event->longest_futex_wait.wake_ns;
        hop->waker_pid = event->longest_futex_wait.waker_pid;
        hop->waker_tid = event->longest_futex_wait.waker_tid;
        copy_comm(hop->waker_comm,
                  event->longest_futex_wait.waker_comm);
    }
    record->callback_added = true;
    update_duration(record);
    return 0;
}

int cw_runtime_report_write(
    struct cw_runtime_report *report, FILE *stream)
{
    bool first = true;
    size_t index;

    if (!report || !stream)
        return -1;
    if (report->dropped)
        fprintf(stderr,
                "HTML report retained %zu operations and omitted %zu "
                "additional operation%s\n",
                report->count, report->dropped,
                report->dropped == 1 ? "" : "s");
    if (cw_html_report_begin_mode(stream, report->mode))
        return -1;
    for (index = 0; index < report->count; index++) {
        if (!strcmp(report->mode, "io_uring") &&
            !report->records[index]->completion_added)
            continue;
        if (cw_html_report_write(stream, &report->records[index]->chain,
                                 &first))
            return -1;
    }
    return cw_html_report_end(stream, NULL, 0);
}
