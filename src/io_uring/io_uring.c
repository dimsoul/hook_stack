// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/io_uring.h>
#include <bpf/bpf.h>

#include "callweave_internal.h"
#include "io_uring.h"
#include "io_uring_internal.h"

const char *cw_io_uring_opcode_name(uint8_t opcode)
{
    switch (opcode) {
    case IORING_OP_NOP:
        return "NOP";
    case IORING_OP_READV:
        return "READV";
    case IORING_OP_WRITEV:
        return "WRITEV";
    case IORING_OP_FSYNC:
        return "FSYNC";
    case IORING_OP_READ_FIXED:
        return "READ_FIXED";
    case IORING_OP_WRITE_FIXED:
        return "WRITE_FIXED";
    case IORING_OP_POLL_ADD:
        return "POLL_ADD";
    case IORING_OP_POLL_REMOVE:
        return "POLL_REMOVE";
    case IORING_OP_SYNC_FILE_RANGE:
        return "SYNC_FILE_RANGE";
    case IORING_OP_SENDMSG:
        return "SENDMSG";
    case IORING_OP_RECVMSG:
        return "RECVMSG";
    case IORING_OP_TIMEOUT:
        return "TIMEOUT";
    case IORING_OP_TIMEOUT_REMOVE:
        return "TIMEOUT_REMOVE";
    case IORING_OP_ACCEPT:
        return "ACCEPT";
    case IORING_OP_ASYNC_CANCEL:
        return "ASYNC_CANCEL";
    case IORING_OP_LINK_TIMEOUT:
        return "LINK_TIMEOUT";
    case IORING_OP_CONNECT:
        return "CONNECT";
    case IORING_OP_FALLOCATE:
        return "FALLOCATE";
    case IORING_OP_OPENAT:
        return "OPENAT";
    case IORING_OP_CLOSE:
        return "CLOSE";
    case IORING_OP_FILES_UPDATE:
        return "FILES_UPDATE";
    case IORING_OP_STATX:
        return "STATX";
    case IORING_OP_READ:
        return "READ";
    case IORING_OP_WRITE:
        return "WRITE";
    default:
        return "UNKNOWN";
    }
}

int cw_io_uring_write_json_string(
    FILE *stream, const char *text, size_t size)
{
    size_t index;

    if (fputc('"', stream) == EOF)
        return -1;
    for (index = 0; index < size && text[index]; index++) {
        unsigned char character = (unsigned char)text[index];

        switch (character) {
        case '"':
            if (fputs("\\\"", stream) == EOF)
                return -1;
            break;
        case '\\':
            if (fputs("\\\\", stream) == EOF)
                return -1;
            break;
        case '\b':
            if (fputs("\\b", stream) == EOF)
                return -1;
            break;
        case '\f':
            if (fputs("\\f", stream) == EOF)
                return -1;
            break;
        case '\n':
            if (fputs("\\n", stream) == EOF)
                return -1;
            break;
        case '\r':
            if (fputs("\\r", stream) == EOF)
                return -1;
            break;
        case '\t':
            if (fputs("\\t", stream) == EOF)
                return -1;
            break;
        default:
            if (character < 0x20) {
                if (fprintf(stream, "\\u%04x", character) < 0)
                    return -1;
            } else if (fputc(character, stream) == EOF) {
                return -1;
            }
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

int cw_io_uring_handle_event(void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct io_uring_event *event = data;
    const char *operation;

    if (data_size < sizeof(*event))
        return 0;
    if (!cw_capture_running(output->control))
        return 0;

    cw_io_uring_cache_fd_resource(output, event->fd);
    operation = cw_io_uring_opcode_name(event->opcode);

    if (output->json_output) {
        FILE *stream = output->json_stream;
        uint64_t realtime_ns =
            event_realtime_nanoseconds(event->timestamp_ns);

        if (!stream)
            return 0;
        if (fprintf(stream,
                    "{\"type\":\"io_uring\",\"timestamp_ns\":%llu,"
                    "\"submit_pid\":%u,\"submit_tid\":%u,"
                    "\"submit_global_pid\":%u,"
                    "\"submit_global_tid\":%u,"
                    "\"complete_global_pid\":%u,"
                    "\"complete_global_tid\":%u,"
                    "\"opcode\":%u,\"operation\":",
                    (unsigned long long)realtime_ns,
                    event->submit_pid, event->submit_tid,
                    event->submit_global_pid,
                    event->submit_global_tid,
                    event->complete_global_pid,
                    event->complete_global_tid,
                    event->opcode) < 0 ||
            cw_io_uring_write_json_string(stream, operation, strlen(operation)) ||
            fprintf(stream,
                    ",\"fd\":%d,\"user_data\":\"0x%016llx\","
                    "\"result\":%d,\"cqe_flags\":%u,"
                    "\"duration_ns\":%llu,"
                    "\"defer_delay_ns\":%llu,"
                    "\"io_wq_queue_ns\":%llu,"
                    "\"after_io_wq_ns\":%llu,"
                    "\"deferred\":%s,\"io_wq\":%s,"
                    "\"io_wq_hashed\":%s,\"poll_armed\":%s,"
                    "\"sq_thread\":%s,"
                    "\"submit_comm\":",
                    event->fd, (unsigned long long)event->user_data,
                    event->result, event->cqe_flags,
                    (unsigned long long)event->duration_ns,
                    (unsigned long long)event->defer_delay_ns,
                    (unsigned long long)event->io_wq_queue_ns,
                    (unsigned long long)event->after_io_wq_ns,
                    event->deferred ? "true" : "false",
                    event->io_wq ? "true" : "false",
                    event->io_wq_hashed ? "true" : "false",
                    event->poll_armed ? "true" : "false",
                    event->sq_thread ? "true" : "false") < 0 ||
            cw_io_uring_write_json_string(stream, event->submit_comm,
                              sizeof(event->submit_comm)) ||
            fputs(",\"complete_comm\":", stream) == EOF ||
            cw_io_uring_write_json_string(stream, event->complete_comm,
                              sizeof(event->complete_comm)) ||
            fputs("}\n", stream) == EOF ||
            fflush(stream)) {
            fprintf(stderr, "failed to write io_uring JSON output: %s\n",
                    strerror(errno ? errno : EIO));
            output->export_failed = true;
            cw_capture_request_stop(
                output->control, CW_STOP_OUTPUT_ERROR);
            return 0;
        }
    } else {
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};

        print_event_time(event->timestamp_ns);
        printf("IO_URING request user_data=0x%016llx\n",
               (unsigned long long)event->user_data);
        printf("  SQE submit: PID %u/TID %u (%.*s) opcode=%s(%u)",
               event->submit_pid, event->submit_tid,
               (int)sizeof(event->submit_comm), event->submit_comm,
               operation, event->opcode);
        if (event->fd >= 0)
            printf(" fd=%d", event->fd);
        if (event->sq_thread)
            printf(" via=sqpoll");
        putchar('\n');
        printf("  CQE complete: global PID %u/TID %u (%.*s) "
               "result=%d",
               event->complete_global_pid, event->complete_global_tid,
               (int)sizeof(event->complete_comm), event->complete_comm,
               event->result);
        if (event->result < 0 && event->result >= -4095)
            printf(" (%s)", strerror(-event->result));
        printf(" flags=0x%x", event->cqe_flags);
        if (event->cqe_flags & IORING_CQE_F_MORE)
            printf(" [MORE]");
        putchar('\n');
        printf("  latency:");
        print_interval("SQE->CQE", event->duration_ns);
        putchar('\n');
        printf("  path: %s",
               event->io_wq ? "io-wq" :
               event->deferred ? "deferred" :
               event->poll_armed ? "poll" : "inline/async-device");
        if (event->io_wq_hashed)
            printf(" (hashed)");
        if (event->defer_delay_ns)
            print_interval("submit->defer",
                           event->defer_delay_ns);
        if (event->io_wq_queue_ns)
            print_interval("io-wq-queue",
                           event->io_wq_queue_ns);
        if (event->after_io_wq_ns)
            print_interval("worker-start->CQE",
                           event->after_io_wq_ns);
        putchar('\n');
        printf("  submit stack:\n");

        if (event->stack_id >= 0 &&
            output->io_uring_stack_map_fd >= 0) {
            struct map_list *maps;

            if (bpf_map_lookup_elem(output->io_uring_stack_map_fd,
                                    &event->stack_id, stack)) {
                printf("  unable to read submitter stack %d: %s\n",
                       event->stack_id, strerror(errno));
            } else {
                maps = cw_io_uring_get_maps(output, event);
                if (!maps) {
                    printf("  warning: cannot read submitter maps for "
                           "PID %u (global PID %u): %s\n",
                           event->submit_pid, event->submit_global_pid,
                           strerror(errno));
                } else {
                    print_stack_frames(stack, sizeof(stack), maps,
                                       "  ", NULL, NULL, 0,
                                       output->control);
                }
            }
        } else if (event->sq_thread) {
            printf("    unavailable: request was issued by "
                   "an io_uring SQPOLL thread\n");
        } else {
            printf("    unavailable\n");
        }
        putchar('\n');
    }

    output->emitted_events++;
    if (output->max_events &&
        output->emitted_events >= output->max_events)
        cw_capture_request_stop(
            output->control, CW_STOP_MAX_EVENTS);
    return 0;
}

int cw_io_uring_handle_callback_event(
    void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct io_uring_callback_event *event = data;
    const char *operation;

    if (data_size < sizeof(*event) ||
        !cw_capture_running(output->control))
        return 0;
    operation = cw_io_uring_opcode_name(event->opcode);
    if (output->json_output) {
        FILE *stream = output->json_stream;
        uint64_t realtime_ns =
            event_realtime_nanoseconds(event->timestamp_ns);

        if (!stream)
            return 0;
        if (fprintf(
                stream,
                "{\"type\":\"io_uring_callback\","
                "\"timestamp_ns\":%llu,\"pid\":%u,\"tid\":%u,"
                "\"global_pid\":%u,\"global_tid\":%u,"
                "\"ring_ctx\":\"0x%016llx\","
                "\"request\":\"0x%016llx\","
                "\"user_data\":\"0x%016llx\","
                "\"opcode\":%u,\"operation\":",
                (unsigned long long)realtime_ns,
                event->pid, event->tid, event->global_pid,
                event->global_tid,
                (unsigned long long)event->ring_ctx,
                (unsigned long long)event->request,
                (unsigned long long)event->user_data,
                event->opcode) < 0 ||
            cw_io_uring_write_json_string(stream, operation, strlen(operation)) ||
            fprintf(
                stream,
                ",\"result\":%d,\"cqe_flags\":%u,"
                "\"request_duration_ns\":%llu,"
                "\"callback_delay_ns\":%llu,\"callback\":",
                event->result, event->cqe_flags,
                (unsigned long long)event->request_duration_ns,
                (unsigned long long)event->callback_delay_ns) < 0 ||
            cw_io_uring_write_json_string(
                stream, output->io_uring_callback_name,
                strlen(output->io_uring_callback_name)) ||
            fputs(",\"comm\":", stream) == EOF ||
            cw_io_uring_write_json_string(stream, event->comm,
                              sizeof(event->comm)) ||
            fputs("}\n", stream) == EOF ||
            fflush(stream)) {
            fprintf(stderr,
                    "failed to write io_uring callback JSON: %s\n",
                    strerror(errno ? errno : EIO));
            output->export_failed = true;
            cw_capture_request_stop(
                output->control, CW_STOP_OUTPUT_ERROR);
        }
        return 0;
    }

    print_event_time(event->timestamp_ns);
    printf("IO_URING CQE -> callback user_data=0x%016llx "
           "opcode=%s(%u)\n",
           (unsigned long long)event->user_data,
           operation, event->opcode);
    printf("  callback: %s PID %u/TID %u (%.*s)",
           output->io_uring_callback_name,
           event->pid, event->tid,
           (int)sizeof(event->comm), event->comm);
    print_interval("CQE->callback", event->callback_delay_ns);
    putchar('\n');
    printf("  callback stack:\n");
    if (event->stack_id >= 0 && output->io_uring_stack_map_fd >= 0) {
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        struct io_uring_event map_event = {
            .submit_pid = event->pid,
            .submit_global_pid = event->global_pid,
        };
        struct map_list *maps;

        if (bpf_map_lookup_elem(output->io_uring_stack_map_fd,
                                &event->stack_id, stack)) {
            printf("    unavailable: cannot read stack %d: %s\n",
                   event->stack_id, strerror(errno));
        } else {
            maps = cw_io_uring_get_maps(output, &map_event);
            if (maps)
                print_stack_frames(stack, sizeof(stack), maps,
                                   "  ", NULL, NULL, 0,
                                   output->control);
            else
                printf("    unavailable: process maps disappeared\n");
        }
    } else {
        printf("    unavailable\n");
    }
    putchar('\n');
    return 0;
}
