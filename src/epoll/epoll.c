// SPDX-License-Identifier: MIT

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/epoll.h>

#include <bpf/bpf.h>

#include "callweave_internal.h"
#include "core/fd_resources.h"
#include "epoll/epoll.h"
#include "epoll/epoll_internal.h"

const char *cw_epoll_output_mode_name(uint32_t mode)
{
    switch (mode) {
    case CW_EPOLL_OUTPUT_LIVE:
        return "live";
    case CW_EPOLL_OUTPUT_VERBOSE:
        return "verbose";
    case CW_EPOLL_OUTPUT_CUSTOM:
        return "custom";
    case CW_EPOLL_OUTPUT_SUMMARY:
    default:
        return "summary";
    }
}

const char *cw_epoll_wait_kind_name(uint32_t kind)
{
    switch (kind) {
    case CW_EPOLL_WAIT:
        return "epoll_wait";
    case CW_EPOLL_PWAIT:
        return "epoll_pwait";
    case CW_EPOLL_PWAIT2:
        return "epoll_pwait2";
    default:
        return "epoll_wait";
    }
}

const char *cw_epoll_callback_match_name(uint32_t match)
{
    switch (match) {
    case CW_EPOLL_CALLBACK_MATCH_FD:
        return "fd";
    case CW_EPOLL_CALLBACK_MATCH_DATA:
        return "data";
    case CW_EPOLL_CALLBACK_MATCH_LIBUV:
        return "libuv-handle";
    case CW_EPOLL_CALLBACK_MATCH_LIBEVENT:
        return "libevent-object-or-fd";
    default:
        return "unknown";
    }
}

static const char *dispatch_evidence_name(
    const struct cw_epoll_dispatch_item *item)
{
    if (item->flags & CW_EPOLL_DISPATCH_CALLBACK_COMPLETED)
        return "exact";
    if (item->flags & CW_EPOLL_DISPATCH_CONSUMED)
        return "ready-to-I/O";
    return "ready-only";
}

const char *cw_epoll_io_operation_name(uint32_t operation)
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
    case CW_EPOLL_IO_DUP:
        return "dup";
    case CW_EPOLL_IO_DUP2:
        return "dup2";
    case CW_EPOLL_IO_DUP3:
        return "dup3";
    case CW_EPOLL_IO_FCNTL_DUP:
        return "fcntl-dup";
    case CW_EPOLL_IO_SPLICE:
        return "splice";
    default:
        return "none";
    }
}

const char *cw_epoll_wake_kind_name(uint32_t kind)
{
    switch (kind) {
    case CW_EPOLL_WAKE_EVENTFD:
        return "eventfd";
    case CW_EPOLL_WAKE_TIMERFD:
        return "timerfd";
    case CW_EPOLL_WAKE_SIGNALFD:
        return "signalfd";
    default:
        return "none";
    }
}

const char *cw_epoll_wake_action_name(uint32_t action)
{
    switch (action) {
    case CW_EPOLL_WAKE_ACTION_EVENTFD_WRITE:
        return "write";
    case CW_EPOLL_WAKE_ACTION_TIMERFD_ARM:
        return "arm";
    case CW_EPOLL_WAKE_ACTION_SIGNAL_SEND:
        return "signal";
    default:
        return "none";
    }
}

bool cw_epoll_resource_single_read(const char *resource)
{
    return resource &&
        (strstr(resource, "anon_inode:[eventfd]") ||
         strstr(resource, "anon_inode:[timerfd]") ||
         strstr(resource, "anon_inode:[signalfd]"));
}

static void append_event_name(
    char *buffer, size_t size, const char *name)
{
    size_t length = strlen(buffer);

    if (length && length + 1 < size) {
        buffer[length++] = '|';
        buffer[length] = '\0';
    }
    if (length < size)
        snprintf(buffer + length, size - length, "%s", name);
}

void cw_epoll_format_events(uint32_t events, char *buffer, size_t size)
{
    struct event_name {
        uint32_t flag;
        const char *name;
    };
    static const struct event_name names[] = {
        {EPOLLIN, "IN"},
        {EPOLLPRI, "PRI"},
        {EPOLLOUT, "OUT"},
        {EPOLLERR, "ERR"},
        {EPOLLHUP, "HUP"},
#ifdef EPOLLRDHUP
        {EPOLLRDHUP, "RDHUP"},
#endif
        {EPOLLET, "ET"},
        {EPOLLONESHOT, "ONESHOT"},
#ifdef EPOLLWAKEUP
        {EPOLLWAKEUP, "WAKEUP"},
#endif
#ifdef EPOLLEXCLUSIVE
        {EPOLLEXCLUSIVE, "EXCLUSIVE"},
#endif
    };
    uint32_t known = 0;
    size_t index;

    if (!buffer || !size)
        return;
    buffer[0] = '\0';
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (events & names[index].flag) {
            append_event_name(buffer, size, names[index].name);
            known |= names[index].flag;
        }
    }
    if (events & ~known) {
        char unknown[24];

        snprintf(unknown, sizeof(unknown), "0x%x", events & ~known);
        append_event_name(buffer, size, unknown);
    }
    if (!buffer[0])
        snprintf(buffer, size, "0");
}

int cw_epoll_write_json_string(
    FILE *stream, const char *text, size_t size)
{
    size_t index;

    if (fputc('"', stream) == EOF)
        return -1;
    for (index = 0; index < size && text[index]; index++) {
        unsigned char character = (unsigned char)text[index];

        if (character == '"' || character == '\\') {
            if (fputc('\\', stream) == EOF ||
                fputc(character, stream) == EOF)
                return -1;
        } else if (character == '\n') {
            if (fputs("\\n", stream) == EOF)
                return -1;
        } else if (character == '\r') {
            if (fputs("\\r", stream) == EOF)
                return -1;
        } else if (character == '\t') {
            if (fputs("\\t", stream) == EOF)
                return -1;
        } else if (character < 0x20) {
            if (fprintf(stream, "\\u%04x", character) < 0)
                return -1;
        } else if (fputc(character, stream) == EOF) {
            return -1;
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

static int write_ready_json(
    FILE *stream, struct output_options *output,
    const struct cw_epoll_event *event)
{
    uint32_t index;

    if (fputs(",\"ready\":[", stream) == EOF)
        return -1;
    for (index = 0; index < event->captured_events; index++) {
        const struct cw_epoll_ready *ready = &event->ready[index];
        char flags[128];
        char resource[PATH_MAX];

        cw_epoll_format_events(
            ready->events, flags, sizeof(flags));
        cw_fd_resolve(&output->fd_resources, output->target_pid,
                      ready->fd, resource, sizeof(resource));
        if (index && fputc(',', stream) == EOF)
            return -1;
        if (fprintf(stream,
                    "{\"fd\":%d,\"data\":\"0x%016llx\","
                    "\"events\":%u,\"flags\":",
                    ready->fd, (unsigned long long)ready->data,
                    ready->events) < 0 ||
            cw_epoll_write_json_string(
                stream, flags, strlen(flags)) ||
            fputs(",\"resource\":", stream) == EOF ||
            cw_epoll_write_json_string(
                stream, resource, strlen(resource)) ||
            fputc('}', stream) == EOF)
            return -1;
    }
    return fputc(']', stream) == EOF ? -1 : 0;
}

static int write_epoll_json(
    struct output_options *output,
    const struct cw_epoll_event *event)
{
    FILE *stream = output->json_stream;
    uint64_t realtime_ns =
        event_realtime_nanoseconds(event->timestamp_ns);

    if (!stream)
        return 0;
    if (fprintf(
            stream,
            "{\"type\":\"epoll_wait\",\"timestamp_ns\":%llu,"
            "\"pid\":%u,\"tid\":%u,\"global_pid\":%u,"
            "\"global_tid\":%u,\"comm\":",
            (unsigned long long)realtime_ns,
            event->pid, event->tid, event->global_pid,
            event->global_tid) < 0 ||
        cw_epoll_write_json_string(
            stream, event->comm, sizeof(event->comm)) ||
        fputs(",\"syscall\":", stream) == EOF ||
        cw_epoll_write_json_string(
            stream, cw_epoll_wait_kind_name(event->wait_kind),
            strlen(cw_epoll_wait_kind_name(event->wait_kind))) ||
        fprintf(
            stream,
            ",\"epoll_fd\":%d,\"result\":%d,\"timeout_ms\":%d,"
            "\"max_events\":%u,\"wait_ns\":%llu,"
            "\"captured_events\":%u,\"unresolved_events\":%u",
            event->epoll_fd, event->result, event->timeout_ms,
            event->max_events,
            (unsigned long long)event->wait_ns,
            event->captured_events, event->unresolved_events) < 0 ||
        write_ready_json(stream, output, event) ||
        fputs("}\n", stream) == EOF ||
        fflush(stream))
        return -1;
    return 0;
}

static void print_epoll_event(
    struct output_options *output,
    const struct cw_epoll_event *event)
{
    uint32_t index;

    print_event_time(event->timestamp_ns);
    printf("EPOLL %s PID %u/TID %u (%.*s) epfd=%d result=%d",
           cw_epoll_wait_kind_name(event->wait_kind),
           event->pid, event->tid,
           (int)sizeof(event->comm), event->comm,
           event->epoll_fd, event->result);
    print_interval("wait", event->wait_ns);
    if (event->timeout_ms == -2)
        printf(" timeout=timespec");
    else
        printf(" timeout=%d ms", event->timeout_ms);
    if (event->result < 0 && event->result >= -4095)
        printf(" error=%s", strerror(-event->result));
    putchar('\n');

    for (index = 0; index < event->captured_events; index++) {
        const struct cw_epoll_ready *ready = &event->ready[index];
        char flags[128];
        char resource[PATH_MAX];

        cw_epoll_format_events(
            ready->events, flags, sizeof(flags));
        cw_fd_resolve(&output->fd_resources, output->target_pid,
                      ready->fd, resource, sizeof(resource));
        printf("  ready[%u]: fd=", index);
        if (ready->fd >= 0)
            printf("%d", ready->fd);
        else
            printf("unresolved");
        printf(" events=%s data=0x%016llx",
               flags, (unsigned long long)ready->data);
        if (resource[0])
            printf("\n             resource: %s", resource);
        putchar('\n');
    }
    if (event->result > (int32_t)event->captured_events)
        printf("  ... %u additional ready events not copied\n",
               (uint32_t)event->result - event->captured_events);
    if (event->unresolved_events)
        printf("  note: %u event.data value%s could not be mapped "
               "back to an FD\n",
               event->unresolved_events,
               event->unresolved_events == 1 ? "" : "s");
    putchar('\n');
}

static bool seed_libuv_ready_token(
    struct output_options *output,
    const struct cw_epoll_event *event,
    const struct cw_epoll_ready *ready)
{
    struct cw_epoll_fd_key epoll_key = {
        .pid = event->pid,
        .fd = event->epoll_fd,
    };
    struct cw_epoll_fd_key fd_key = {
        .pid = event->pid,
    };
    struct cw_epoll_token_key token_key = {
        .data = ready->data,
        .pid = event->pid,
        .epoll_fd = event->epoll_fd,
    };
    struct cw_epoll_token_value token = {0};
    uint32_t epoll_generation = 1;
    uint32_t fd_generation = 1;

    if (!output->libuv_mode || ready->fd >= 0 ||
        ready->data > INT32_MAX ||
        output->epoll_token_map_fd < 0 ||
        output->epoll_fd_generation_map_fd < 0)
        return false;
    fd_key.fd = (int32_t)ready->data;
    (void)bpf_map_lookup_elem(
        output->epoll_fd_generation_map_fd,
        &epoll_key, &epoll_generation);
    (void)bpf_map_lookup_elem(
        output->epoll_fd_generation_map_fd,
        &fd_key, &fd_generation);
    token_key.epoll_generation = epoll_generation;
    token.fd = fd_key.fd;
    token.fd_generation = fd_generation;
    if (bpf_map_update_elem(
            output->epoll_token_map_fd,
            &token_key, &token, BPF_NOEXIST))
        return false;
    output->libuv_fallback_tokens++;
    return true;
}

int cw_epoll_handle_event(void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct cw_epoll_event *event = data;
    uint32_t index;

    if (data_size < sizeof(*event) ||
        !cw_capture_running(output->control))
        return 0;
    for (index = 0; index < event->captured_events; index++) {
        (void)seed_libuv_ready_token(
            output, event, &event->ready[index]);
        cw_fd_cache_one(
            &output->fd_resources, output->target_pid,
            event->ready[index].fd);
    }

    if (output->epoll_output_mode == CW_EPOLL_OUTPUT_SUMMARY)
        return 0;
    if (output->json_output) {
        if (write_epoll_json(output, event)) {
            fprintf(stderr, "failed to write epoll JSON output: %s\n",
                    strerror(errno ? errno : EIO));
            output->export_failed = true;
            cw_capture_request_stop(
                output->control, CW_STOP_OUTPUT_ERROR);
            return 0;
        }
    } else {
        print_epoll_event(output, event);
    }

    output->emitted_events++;
    if (output->max_events &&
        output->emitted_events >= output->max_events)
        cw_capture_request_stop(
            output->control, CW_STOP_MAX_EVENTS);
    return 0;
}

static const char *dispatch_status(
    const struct cw_epoll_dispatch_item *item,
    bool single_read_resource)
{
    if (!(item->flags & CW_EPOLL_DISPATCH_CONSUMED))
        return "not handled on the event-loop thread";
    if (item->flags & CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM)
        return "possible missing EPOLLONESHOT rearm";
    if (item->flags & CW_EPOLL_DISPATCH_MSG_PEEK)
        return "MSG_PEEK observed; data may remain queued";
    if (item->flags & CW_EPOLL_DISPATCH_EAGAIN)
        return "drained to EAGAIN";
    if (item->flags & CW_EPOLL_DISPATCH_EOF)
        return "EOF observed";
    if (item->flags & CW_EPOLL_DISPATCH_CLOSED)
        return "FD closed";
    if (item->flags & CW_EPOLL_DISPATCH_REARMED)
        return "registration rearmed";
    if (item->flags & CW_EPOLL_DISPATCH_SHORT_READ)
        return "short read";
    if ((item->flags & CW_EPOLL_DISPATCH_ET_UNDRAINED) &&
        single_read_resource)
        return "single-read counter FD handled";
    if (item->flags & CW_EPOLL_DISPATCH_ET_UNDRAINED)
        return "possible incomplete EPOLLET drain";
    return "handled";
}

static uint64_t dispatch_latency(
    const struct cw_epoll_dispatch_event *event,
    const struct cw_epoll_dispatch_item *item)
{
    if (item->first_io_ns > item->ready_ns)
        return item->first_io_ns - item->ready_ns;
    return event->return_to_wait_ns;
}

static int write_wake_json(
    FILE *stream, const struct cw_epoll_wake_source *wake)
{
    if (!wake->kind)
        return fputs("null", stream) == EOF ? -1 : 0;
    if (fprintf(
            stream,
            "{\"kind\":\"%s\",\"action\":\"%s\","
            "\"attributed\":%s,\"first_timestamp_ns\":%llu,"
            "\"timestamp_ns\":%llu,\"latency_valid\":%s,"
            "\"latency_ns\":%llu,\"operations\":%llu,"
            "\"value\":%llu,\"timer_initial_ns\":%llu,"
            "\"timer_interval_ns\":%llu,\"timer_abstime\":%s,"
            "\"timer_disarmed\":%s,\"signal_number\":%u,"
            "\"source_pid\":%u,\"source_tid\":%u,"
            "\"source_global_pid\":%u,"
            "\"source_global_tid\":%u,\"stack_id\":%d,\"comm\":",
            cw_epoll_wake_kind_name(wake->kind),
            cw_epoll_wake_action_name(wake->action),
            wake->action ? "true" : "false",
            (unsigned long long)wake->first_timestamp_ns,
            (unsigned long long)wake->timestamp_ns,
            wake->flags & CW_EPOLL_WAKE_LATENCY_VALID ?
                "true" : "false",
            (unsigned long long)wake->latency_ns,
            (unsigned long long)wake->operations,
            (unsigned long long)wake->value,
            (unsigned long long)wake->timer_initial_ns,
            (unsigned long long)wake->timer_interval_ns,
            wake->flags & CW_EPOLL_WAKE_TIMER_ABSTIME ?
                "true" : "false",
            wake->flags & CW_EPOLL_WAKE_TIMER_DISARMED ?
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

static int write_callback_futex_json(
    FILE *stream, const struct cw_epoll_callback_event *event)
{
    const struct cw_epoll_futex_wait *wait =
        &event->longest_futex_wait;

    if (!event->futex_waits || !wait->duration_ns)
        return fputs("null", stream) == EOF ? -1 : 0;
    if (fprintf(
            stream,
            "{\"waits\":%llu,\"total_wait_ns\":%llu,"
            "\"longest\":{\"operation\":\"%s\","
            "\"address\":\"0x%016llx\","
            "\"duration_ns\":%llu,\"wake_ns\":%llu,"
            "\"waker_pid\":%u,\"waker_tid\":%u,"
            "\"waker_global_pid\":%u,"
            "\"waker_global_tid\":%u,"
            "\"waker_stack_id\":%d,\"waker_comm\":",
            (unsigned long long)event->futex_waits,
            (unsigned long long)event->futex_wait_ns,
            cw_epoll_futex_operation_name(wait->operation),
            (unsigned long long)wait->address,
            (unsigned long long)wait->duration_ns,
            (unsigned long long)wait->wake_ns,
            wait->waker_pid, wait->waker_tid,
            wait->waker_global_pid, wait->waker_global_tid,
            wait->waker_stack_id) < 0 ||
        cw_epoll_write_json_string(
            stream, wait->waker_comm, sizeof(wait->waker_comm)) ||
        fputs("}}", stream) == EOF)
        return -1;
    return 0;
}

static int write_dispatch_json_item(
    struct output_options *output,
    const struct cw_epoll_dispatch_event *event,
    const struct cw_epoll_dispatch_item *item)
{
    FILE *stream = output->json_stream;
    uint64_t realtime_ns =
        event_realtime_nanoseconds(item->ready_ns);
    char ready_flags[128];
    char interest_flags[128];
    char resource[PATH_MAX];
    bool single_read_resource;
    bool et_warning;

    if (!stream)
        return 0;
    cw_epoll_format_events(
        item->ready_events, ready_flags, sizeof(ready_flags));
    cw_epoll_format_events(
        item->interest_events, interest_flags,
        sizeof(interest_flags));
    cw_fd_resolve(
        &output->fd_resources, output->target_pid,
        item->fd, resource, sizeof(resource));
    single_read_resource = cw_epoll_resource_single_read(resource);
    et_warning =
        (item->flags & CW_EPOLL_DISPATCH_ET_UNDRAINED) &&
        !single_read_resource;
    if (fprintf(
            stream,
            "{\"type\":\"epoll_dispatch\","
            "\"timestamp_ns\":%llu,\"pid\":%u,\"tid\":%u,"
            "\"global_pid\":%u,\"global_tid\":%u,"
            "\"epoll_fd\":%d,\"fd\":%d,"
            "\"epoll_generation\":%u,\"fd_generation\":%u,"
            "\"data\":\"0x%016llx\",\"ready_events\":%u,"
            "\"ready_flags\":",
            (unsigned long long)realtime_ns,
            event->pid, event->tid,
            event->global_pid, event->global_tid,
            event->epoll_fd, item->fd,
            item->epoll_generation, item->fd_generation,
            (unsigned long long)item->data,
            item->ready_events) < 0 ||
        cw_epoll_write_json_string(
            stream, ready_flags, strlen(ready_flags)) ||
        fputs(",\"interest_flags\":", stream) == EOF ||
        cw_epoll_write_json_string(
            stream, interest_flags, strlen(interest_flags)) ||
        fprintf(
            stream,
            ",\"consumed\":%s,\"dispatch_ns\":%llu,"
            "\"evidence\":\"%s\","
            "\"return_to_wait_ns\":%llu,"
            "\"cycle_offcpu_ns\":%llu,"
            "\"cycle_blocked_ns\":%llu,"
            "\"cycle_runqueue_ns\":%llu,"
            "\"io_calls\":%u,"
            "\"read_calls\":%u,\"write_calls\":%u,"
            "\"bytes_read\":%llu,\"bytes_written\":%llu,"
            "\"requested_bytes\":%llu,"
            "\"io_errors\":%u,\"first_operation\":",
            item->flags & CW_EPOLL_DISPATCH_CONSUMED ?
                "true" : "false",
            (unsigned long long)dispatch_latency(event, item),
            dispatch_evidence_name(item),
            (unsigned long long)event->return_to_wait_ns,
            (unsigned long long)event->cycle_offcpu_ns,
            (unsigned long long)event->cycle_blocked_ns,
            (unsigned long long)event->cycle_runqueue_ns,
            item->io_calls, item->read_calls, item->write_calls,
            (unsigned long long)item->bytes_read,
            (unsigned long long)item->bytes_written,
            (unsigned long long)item->requested_bytes,
            item->io_errors) < 0 ||
        cw_epoll_write_json_string(
            stream,
            cw_epoll_io_operation_name(item->first_operation),
            strlen(cw_epoll_io_operation_name(
                item->first_operation))) ||
        fputs(",\"last_operation\":", stream) == EOF ||
        cw_epoll_write_json_string(
            stream,
            cw_epoll_io_operation_name(item->last_operation),
            strlen(cw_epoll_io_operation_name(
                item->last_operation))) ||
        fprintf(
            stream,
            ",\"last_result\":%d,\"eagain\":%s,"
            "\"short_read\":%s,\"eof\":%s,\"closed\":%s,"
            "\"rearmed\":%s,\"potential_et_undrained\":%s,"
            "\"potential_oneshot_missing_rearm\":%s,"
            "\"msg_peek\":%s,"
            "\"et_warning\":%s,\"resource\":",
            item->last_result,
            item->flags & CW_EPOLL_DISPATCH_EAGAIN ?
                "true" : "false",
            item->flags & CW_EPOLL_DISPATCH_SHORT_READ ?
                "true" : "false",
            item->flags & CW_EPOLL_DISPATCH_EOF ?
                "true" : "false",
            item->flags & CW_EPOLL_DISPATCH_CLOSED ?
                "true" : "false",
            item->flags & CW_EPOLL_DISPATCH_REARMED ?
                "true" : "false",
            item->flags & CW_EPOLL_DISPATCH_ET_UNDRAINED ?
                "true" : "false",
            item->flags &
                CW_EPOLL_DISPATCH_ONESHOT_MISSING_REARM ?
                "true" : "false",
            item->flags & CW_EPOLL_DISPATCH_MSG_PEEK ?
                "true" : "false",
            et_warning ? "true" : "false") < 0 ||
        cw_epoll_write_json_string(
            stream, resource, strlen(resource)) ||
        fputs(",\"wake\":", stream) == EOF ||
        write_wake_json(stream, &item->wake) ||
        fputs(",\"status\":", stream) == EOF ||
        cw_epoll_write_json_string(
            stream,
            dispatch_status(item, single_read_resource),
            strlen(dispatch_status(
                item, single_read_resource))) ||
        fputs("}\n", stream) == EOF ||
        fflush(stream))
        return -1;
    return 0;
}

static void print_wake_source(
    const struct cw_epoll_wake_source *wake)
{
    if (!wake->kind)
        return;
    printf("  wake    : %s", cw_epoll_wake_kind_name(wake->kind));
    if (!wake->action) {
        printf(" source unavailable "
               "(pre-attach, external producer, or unmatched signal)\n");
        return;
    }
    printf(" %s by PID %u/TID %u (%.*s)",
           cw_epoll_wake_action_name(wake->action),
           wake->source_pid, wake->source_tid,
           (int)sizeof(wake->comm), wake->comm);
    if (wake->action == CW_EPOLL_WAKE_ACTION_EVENTFD_WRITE)
        printf(" writes=%llu value=%llu",
               (unsigned long long)wake->operations,
               (unsigned long long)wake->value);
    else if (wake->action == CW_EPOLL_WAKE_ACTION_TIMERFD_ARM) {
        print_interval("initial", wake->timer_initial_ns);
        print_interval("interval", wake->timer_interval_ns);
        if (wake->flags & CW_EPOLL_WAKE_TIMER_ABSTIME)
            printf(" absolute");
    } else if (wake->action == CW_EPOLL_WAKE_ACTION_SIGNAL_SEND)
        printf(" signo=%u count=%llu",
               wake->signal_number,
               (unsigned long long)wake->operations);
    if (wake->flags & CW_EPOLL_WAKE_LATENCY_VALID)
        print_interval(
            wake->action == CW_EPOLL_WAKE_ACTION_TIMERFD_ARM ?
                "schedule->ready" : "source->ready",
            wake->latency_ns);
    putchar('\n');
}

const char *cw_epoll_futex_operation_name(uint32_t operation)
{
    switch (operation) {
    case 9:
        return "wait-bitset";
    case 0:
    default:
        return "wait";
    }
}

void cw_epoll_print_callback_futex(
    const struct cw_epoll_futex_wait *wait,
    uint64_t waits, uint64_t total_wait_ns,
    const struct output_options *output, const char *indent)
{
    uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};

    if (!wait || !waits || !wait->duration_ns || !output)
        return;
    printf("%sfutex waits: count=%llu", indent,
           (unsigned long long)waits);
    print_interval("total", total_wait_ns);
    putchar('\n');
    printf("%slongest futex: operation=%s address=0x%016llx",
           indent, cw_epoll_futex_operation_name(wait->operation),
           (unsigned long long)wait->address);
    print_interval("duration", wait->duration_ns);
    putchar('\n');
    if (!wait->waker_tid) {
        printf("%s  waker=unobserved "
               "(timeout, signal, or unmatched wake)\n", indent);
        return;
    }
    printf("%s  waker PID %u/TID %u (%.*s)", indent,
           wait->waker_pid, wait->waker_tid,
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
        printf("%s  unable to collect waker stack: %s (%d)\n",
               indent, strerror(-wait->waker_stack_id),
               wait->waker_stack_id);
        return;
    }
    if (output->wait_stack_map_fd < 0 ||
        bpf_map_lookup_elem(
            output->wait_stack_map_fd,
            &wait->waker_stack_id, stack)) {
        printf("%s  waker stack unavailable (stack_id=%d)\n",
               indent, wait->waker_stack_id);
        return;
    }
    if (!output->target_maps) {
        printf("%s  waker process maps unavailable\n", indent);
        return;
    }
    print_stack_frames(
        stack, sizeof(stack), output->target_maps,
        "        waker ", NULL, NULL, 0, output->control);
}

static void print_dispatch_item(
    struct output_options *output,
    const struct cw_epoll_dispatch_event *event,
    const struct cw_epoll_dispatch_item *item)
{
    char ready_flags[128];
    char interest_flags[128];
    char resource[PATH_MAX];
    bool single_read_resource;

    cw_epoll_format_events(
        item->ready_events, ready_flags, sizeof(ready_flags));
    cw_epoll_format_events(
        item->interest_events, interest_flags,
        sizeof(interest_flags));
    cw_fd_resolve(
        &output->fd_resources, output->target_pid,
        item->fd, resource, sizeof(resource));
    single_read_resource = cw_epoll_resource_single_read(resource);

    print_event_time(item->ready_ns);
    printf("EPOLL DISPATCH PID %u/TID %u (%.*s) epfd=%d fd=%d\n",
           event->pid, event->tid,
           (int)sizeof(event->comm), event->comm,
           event->epoll_fd, item->fd);
    printf("  ready   : %s (interest=%s)",
           ready_flags, interest_flags);
    if (resource[0])
        printf("\n  resource: %s", resource);
    putchar('\n');
    print_wake_source(&item->wake);
    printf("  cycle   :");
    print_interval("total", event->return_to_wait_ns);
    print_interval("off-CPU", event->cycle_offcpu_ns);
    print_interval("blocked", event->cycle_blocked_ns);
    print_interval("run queue", event->cycle_runqueue_ns);
    print_interval(
        "preempt/unknown",
        event->cycle_offcpu_ns >
            event->cycle_blocked_ns + event->cycle_runqueue_ns ?
            event->cycle_offcpu_ns -
                event->cycle_blocked_ns -
                event->cycle_runqueue_ns : 0);
    putchar('\n');
    if (item->flags & CW_EPOLL_DISPATCH_CONSUMED) {
        printf("  dispatch: %s",
               cw_epoll_io_operation_name(item->first_operation));
        print_interval(
            "ready->I/O", dispatch_latency(event, item));
        print_interval("I/O time", item->total_io_ns);
        printf("\n  I/O     : calls=%u read=%u/%llu B "
               "write=%u/%llu B errors=%u last=%s(%d)\n",
               item->io_calls,
               item->read_calls,
               (unsigned long long)item->bytes_read,
               item->write_calls,
               (unsigned long long)item->bytes_written,
               item->io_errors,
               cw_epoll_io_operation_name(item->last_operation),
               item->last_result);
        if (item->requested_bytes ||
            (item->flags & CW_EPOLL_DISPATCH_MSG_PEEK))
            printf("  I/O args: requested=%llu%s\n",
                   (unsigned long long)item->requested_bytes,
                   item->flags & CW_EPOLL_DISPATCH_MSG_PEEK ?
                       " MSG_PEEK" : "");
    } else {
        printf("  dispatch: no matching I/O before next epoll wait");
        print_interval(
            "window", dispatch_latency(event, item));
        putchar('\n');
    }
    printf("  evidence: %s", dispatch_evidence_name(item));
    if (!(item->flags & CW_EPOLL_DISPATCH_CALLBACK_COMPLETED)) {
        if (item->flags & CW_EPOLL_DISPATCH_CONSUMED)
            printf(" (callback boundary unavailable; "
                   "correlated by FD and I/O stack)");
        else
            printf(" (no callback completion or matching I/O observed)");
    }
    putchar('\n');
    printf("  status  : %s\n\n",
           dispatch_status(item, single_read_resource));
}

int cw_epoll_handle_dispatch_event(
    void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct cw_epoll_dispatch_event *event = data;
    const struct cw_epoll_dispatch_item *item;

    if (data_size < sizeof(*event) ||
        !cw_capture_running(output->control))
        return 0;
    item = &event->item;
    cw_fd_cache_one(
        &output->fd_resources, output->target_pid, item->fd);
    if (output->epoll_output_mode == CW_EPOLL_OUTPUT_SUMMARY)
        return 0;
    if (output->json_output) {
        if (write_dispatch_json_item(output, event, item)) {
            fprintf(
                stderr,
                "failed to write epoll dispatch JSON: %s\n",
                strerror(errno ? errno : EIO));
            output->export_failed = true;
            cw_capture_request_stop(
                output->control, CW_STOP_OUTPUT_ERROR);
            return 0;
        }
    } else {
        print_dispatch_item(output, event, item);
    }
    return 0;
}

static int write_callback_json(
    struct output_options *output,
    const struct cw_epoll_callback_event *event)
{
    FILE *stream = output->json_stream;
    uint64_t realtime_ns =
        event_realtime_nanoseconds(event->start_ns);
    uint64_t oncpu_ns =
        event->duration_ns > event->offcpu_ns ?
            event->duration_ns - event->offcpu_ns : 0;
    uint64_t unknown_ns =
        event->offcpu_ns >
            event->blocked_ns + event->runqueue_ns ?
            event->offcpu_ns -
                event->blocked_ns - event->runqueue_ns : 0;
    char ready_flags[128];
    char resource[PATH_MAX];
    uint64_t callback_key = event->callback_key;

    if (!stream)
        return 0;
    cw_epoll_format_events(
        event->ready_events, ready_flags, sizeof(ready_flags));
    cw_fd_resolve(
        &output->fd_resources, output->target_pid,
        event->fd, resource, sizeof(resource));
    if (fprintf(
            stream,
            "{\"type\":\"epoll_callback\","
            "\"timestamp_ns\":%llu,\"pid\":%u,\"tid\":%u,"
            "\"global_pid\":%u,\"global_tid\":%u,"
            "\"epoll_fd\":%d,\"fd\":%d,"
            "\"epoll_generation\":%u,\"fd_generation\":%u,"
            "\"data\":\"0x%016llx\",\"ready_events\":%u,"
            "\"match\":\"%s\","
            "\"evidence\":\"exact\","
            "\"callback_key\":\"0x%016llx\","
            "\"ready_flags\":",
            (unsigned long long)realtime_ns,
            event->pid, event->tid,
            event->global_pid, event->global_tid,
            event->epoll_fd, event->fd,
            event->epoll_generation, event->fd_generation,
            (unsigned long long)event->data,
            event->ready_events,
            cw_epoll_callback_match_name(event->match_kind),
            (unsigned long long)callback_key) < 0 ||
        cw_epoll_write_json_string(
            stream, ready_flags, strlen(ready_flags)) ||
        fputs(",\"callback\":", stream) == EOF ||
        cw_epoll_write_json_string(
            stream, output->epoll_callback_name,
            strlen(output->epoll_callback_name)) ||
        fprintf(
            stream,
            ",\"ready_to_callback_ns\":%llu,"
            "\"duration_ns\":%llu,\"oncpu_ns\":%llu,"
            "\"offcpu_ns\":%llu,\"blocked_ns\":%llu,"
            "\"runqueue_ns\":%llu,\"preempt_unknown_ns\":%llu,"
            "\"stack_id\":%d,\"resource\":",
            (unsigned long long)event->delay_ns,
            (unsigned long long)event->duration_ns,
            (unsigned long long)oncpu_ns,
            (unsigned long long)event->offcpu_ns,
            (unsigned long long)event->blocked_ns,
            (unsigned long long)event->runqueue_ns,
            (unsigned long long)unknown_ns,
            event->stack_id) < 0 ||
        cw_epoll_write_json_string(
            stream, resource, strlen(resource)) ||
        fputs(",\"wake\":", stream) == EOF ||
        write_wake_json(stream, &event->wake) ||
        fputs(",\"futex\":", stream) == EOF ||
        write_callback_futex_json(stream, event) ||
        fputs("}\n", stream) == EOF ||
        fflush(stream))
        return -1;
    return 0;
}

static void print_callback_event(
    struct output_options *output,
    const struct cw_epoll_callback_event *event)
{
    uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
    uint64_t oncpu_ns =
        event->duration_ns > event->offcpu_ns ?
            event->duration_ns - event->offcpu_ns : 0;
    uint64_t unknown_ns =
        event->offcpu_ns >
            event->blocked_ns + event->runqueue_ns ?
            event->offcpu_ns -
                event->blocked_ns - event->runqueue_ns : 0;
    char ready_flags[128];
    char resource[PATH_MAX];
    char callback_key[48];

    cw_epoll_format_events(
        event->ready_events, ready_flags, sizeof(ready_flags));
    cw_fd_resolve(
        &output->fd_resources, output->target_pid,
        event->fd, resource, sizeof(resource));
    if (event->match_kind == CW_EPOLL_CALLBACK_MATCH_FD)
        snprintf(
            callback_key, sizeof(callback_key),
            "%d -> fd=%d", event->fd, event->fd);
    else if (event->match_kind ==
             CW_EPOLL_CALLBACK_MATCH_LIBUV)
        snprintf(
            callback_key, sizeof(callback_key),
            "handle=0x%llx -> fd=%d",
            (unsigned long long)event->callback_key,
            event->fd);
    else if (event->match_kind ==
             CW_EPOLL_CALLBACK_MATCH_LIBEVENT)
        snprintf(
            callback_key, sizeof(callback_key),
            "object/fd=0x%llx -> fd=%d",
            (unsigned long long)event->callback_key,
            event->fd);
    else
        snprintf(
            callback_key, sizeof(callback_key),
            "0x%016llx -> fd=%d",
            (unsigned long long)event->data, event->fd);
    print_event_time(event->start_ns);
    printf(
        "%s %s PID %u/TID %u (%.*s) "
        "epfd=%d match=%s key=%s events=%s\n",
        output->libuv_mode ? "LIBUV CALLBACK" :
            (output->libevent_mode ?
                "LIBEVENT CALLBACK" : "EPOLL CALLBACK"),
        output->epoll_callback_name,
        event->pid, event->tid,
        (int)sizeof(event->comm), event->comm,
        event->epoll_fd,
        cw_epoll_callback_match_name(event->match_kind),
        callback_key,
        ready_flags);
    if (resource[0])
        printf("  resource: %s\n", resource);
    printf("  evidence: exact (ready event and completed callback)\n");
    print_wake_source(&event->wake);
    printf("  timing  :");
    print_interval("ready->callback", event->delay_ns);
    print_interval("callback", event->duration_ns);
    print_interval("on-CPU", oncpu_ns);
    print_interval("off-CPU", event->offcpu_ns);
    print_interval("blocked", event->blocked_ns);
    print_interval("run queue", event->runqueue_ns);
    print_interval("preempt/unknown", unknown_ns);
    putchar('\n');
    if (event->futex_waits)
        cw_epoll_print_callback_futex(
            &event->longest_futex_wait,
            event->futex_waits, event->futex_wait_ns,
            output, "  ");
    else if (event->blocked_ns)
        printf("  blocking: no futex wait observed "
               "(possible sleep, timer, I/O, or other wait)\n");
    printf("  callback stack:\n");
    if (event->stack_id < 0 ||
        output->epoll_stack_map_fd < 0 ||
        bpf_map_lookup_elem(
            output->epoll_stack_map_fd,
            &event->stack_id, stack)) {
        printf("    unavailable (stack_id=%d)\n\n",
               event->stack_id);
    } else if (output->target_maps) {
        print_stack_frames(
            stack, sizeof(stack), output->target_maps,
            "  ", NULL, NULL, 0, output->control);
        putchar('\n');
    } else {
        printf("    process maps unavailable\n\n");
    }
}

int cw_epoll_handle_callback_event(
    void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct cw_epoll_callback_event *event = data;

    if (data_size < sizeof(*event) ||
        !cw_capture_running(output->control))
        return 0;
    cw_fd_cache_one(
        &output->fd_resources, output->target_pid, event->fd);
    if (output->epoll_output_mode == CW_EPOLL_OUTPUT_SUMMARY)
        return 0;
    if (output->json_output) {
        if (write_callback_json(output, event)) {
            fprintf(
                stderr,
                "failed to write epoll callback JSON: %s\n",
                strerror(errno ? errno : EIO));
            output->export_failed = true;
            cw_capture_request_stop(
                output->control, CW_STOP_OUTPUT_ERROR);
        }
    } else {
        print_callback_event(output, event);
    }
    return 0;
}
