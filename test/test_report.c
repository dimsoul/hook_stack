// SPDX-License-Identifier: MIT

#include "callweave_internal.h"
#include "async/async_lifecycle.h"
#include "report.h"
#include "runtime_report.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t event_realtime_nanoseconds(uint64_t timestamp_ns)
{
    return timestamp_ns;
}

static int verify_report_markers(
    const char *path, const char *const *expected, size_t expected_count)
{
    FILE *stream;
    char *contents;
    long length;
    size_t index;
    int result = -1;

    stream = fopen(path, "rb");
    if (!stream)
        return -1;
    if (fseek(stream, 0, SEEK_END) || (length = ftell(stream)) < 0 ||
        fseek(stream, 0, SEEK_SET))
        goto out;
    contents = malloc((size_t)length + 1);
    if (!contents)
        goto out;
    if (fread(contents, 1, (size_t)length, stream) != (size_t)length) {
        free(contents);
        goto out;
    }
    contents[length] = '\0';
    for (index = 0; index < expected_count; index++) {
        if (!strstr(contents, expected[index])) {
            fprintf(stderr, "missing report marker: %s\n", expected[index]);
            free(contents);
            goto out;
        }
    }
    free(contents);
    result = 0;
out:
    fclose(stream);
    return result;
}

static int verify_async_report(const char *path)
{
    static const char *const expected[] = {
        "role=\"tablist\"",
        "Cross-thread sequence",
        "function renderSequence",
        "\"source\":\"submit_decode_task\"",
        "\"target\":\"persist_result\"",
    };

    return verify_report_markers(
        path, expected, sizeof(expected) / sizeof(expected[0]));
}

static int write_runtime_report(const char *path)
{
    static const char *const expected[] = {
        "const reportMode=\"io_uring\"",
        "\"source\":\"SQE TIMEOUT\"",
        "\"source\":\"SQE READ\"",
        "\"target\":\"CQE result=64\"",
        "\"target\":\"io_uring_callback (process_io_completion)\"",
        "READ user_data=0xc011 → callback",
    };
    struct cw_runtime_report *report =
        cw_runtime_report_create("io_uring");
    struct io_uring_event completion = {
        .timestamp_ns = 1785811426789000000ULL,
        .submit_ns = 1785811426788960000ULL,
        .duration_ns = 40000,
        .io_wq_queue_ns = 9000,
        .after_io_wq_ns = 31000,
        .request = 0xabc,
        .user_data = 0xc011,
        .submit_pid = 42000,
        .submit_tid = 42001,
        .submit_global_pid = 42000,
        .submit_global_tid = 42001,
        .complete_global_pid = 42000,
        .complete_global_tid = 42011,
        .fd = 4,
        .result = 64,
        .opcode = 22,
        .io_wq = 1,
        .submit_comm = "api-main",
        .complete_comm = "iou-worker",
    };
    struct io_uring_event timeout = {
        .timestamp_ns = 1785811426810000000ULL,
        .submit_ns = 1785811426790000000ULL,
        .duration_ns = 20000000,
        /* Deliberately reuse the kernel request address. */
        .request = 0xabc,
        .user_data = 0xc012,
        .submit_pid = 42000,
        .submit_tid = 42001,
        .submit_global_pid = 42000,
        .submit_global_tid = 42001,
        .complete_global_pid = 42000,
        .complete_global_tid = 42011,
        .fd = -1,
        .result = -62,
        .opcode = 11,
        .submit_comm = "api-main",
        .complete_comm = "api-main",
    };
    struct io_uring_callback_event callback = {
        /* Model a completed fast request held behind a slower CQ batch. */
        .timestamp_ns = 1785811426809180000ULL,
        .completion_ns = 1785811426789000000ULL,
        .callback_delay_ns = 20180000,
        .request_duration_ns = 40000,
        .request = 0xabc,
        .user_data = 0xc011,
        .pid = 42000,
        .tid = 42021,
        .global_pid = 42000,
        .global_tid = 42021,
        .result = 64,
        .opcode = 22,
        .comm = "api-loop",
    };
    FILE *stream;
    int result = -1;

    if (!report)
        return -1;
    if (cw_runtime_report_capture_io_uring(
            report, &completion, "READ") ||
        cw_runtime_report_capture_io_uring(
            report, &timeout, "TIMEOUT") ||
        cw_runtime_report_capture_io_uring_callback(
            report, &callback, "READ", "process_io_completion", true))
        goto out;
    stream = fopen(path, "wb");
    if (!stream)
        goto out;
    {
        int write_error = cw_runtime_report_write(report, stream);

        if (fclose(stream) || write_error)
            goto out;
    }
    result = verify_report_markers(
        path, expected, sizeof(expected) / sizeof(expected[0]));
out:
    cw_runtime_report_destroy(report);
    return result;
}

static int write_event_loop_report(
    const char *path, const char *mode, uint32_t match_kind,
    const char *callback_name)
{
    static const char *const libuv_expected[] = {
        "const reportMode=\"libuv\"",
        "renderEventLoopSequence",
        "\"source\":\"eventfd_write\"",
        "\"target\":\"ready fd=4\"",
        "\"target\":\"libuv_callback (poll_callback)\"",
        "\"target\":\"ready fd=5\"",
    };
    static const char *const libevent_expected[] = {
        "const reportMode=\"libevent\"",
        "renderEventLoopSequence",
        "Only observed threads receive lanes",
        "Selected pre-callback",
        "pre-callback dispatch",
        "lane(loopX,callbackName",
        "\"source\":\"send\"",
        "\"tid\":43011,\"target_tid\":43001",
        "\"target\":\"ready fd=6\"",
        "\"tid\":43012,\"target_tid\":43001",
        "\"target\":\"libevent_callback (bufferevent_read_callback)\"",
    };
    const char *const *expected = !strcmp(mode, "libevent") ?
        libevent_expected : libuv_expected;
    size_t expected_count = !strcmp(mode, "libevent") ?
        sizeof(libevent_expected) / sizeof(libevent_expected[0]) :
        sizeof(libuv_expected) / sizeof(libuv_expected[0]);
    struct cw_runtime_report *report =
        cw_runtime_report_create(mode);
    struct cw_epoll_event wait = {
        .timestamp_ns = 1785811426790000000ULL,
        .start_ns = 1785811426788000000ULL,
        .wait_ns = 2000000,
        .pid = 43000,
        .tid = 43001,
        .epoll_fd = 3,
        .result = 1,
        .captured_events = 1,
        .wait_kind = CW_EPOLL_WAIT,
        .comm = "uv-loop",
        .ready = {{.data = 0x1234, .fd = 4, .events = 1}},
    };
    struct cw_epoll_callback_event callback = {
        .timestamp_ns = 1785811426790100000ULL,
        .ready_ns = 1785811426790000000ULL,
        .start_ns = 1785811426790030000ULL,
        .delay_ns = 30000,
        .duration_ns = 70000,
        .offcpu_ns = 20000,
        .blocked_ns = 17000,
        .runqueue_ns = 2000,
        .data = 0x1234,
        .callback_key = 0xbeef,
        .pid = 43000,
        .tid = 43001,
        .epoll_fd = 3,
        .fd = 4,
        .ready_events = 1,
        .match_kind = match_kind,
        .comm = "uv-loop",
        .wake = {
            .latency_ns = 90000,
            .action = CW_EPOLL_WAKE_ACTION_EVENTFD_WRITE,
            .flags = CW_EPOLL_WAKE_LATENCY_VALID,
            .source_pid = 43000,
            .source_tid = 43011,
            .comm = "producer",
        },
    };
    struct cw_epoll_event wait_without_waker = {
        .timestamp_ns = 1785811426840000000ULL,
        .start_ns = 1785811426790000000ULL,
        .wait_ns = 50000000,
        .pid = 43000,
        .tid = 43001,
        .epoll_fd = 3,
        .result = 1,
        .captured_events = 1,
        .wait_kind = CW_EPOLL_WAIT,
        .comm = "uv-loop",
        .ready = {{.data = 0x5678, .fd = 5, .events = 1}},
    };
    struct cw_epoll_callback_event callback_without_waker = {
        .timestamp_ns = 1785811426840060000ULL,
        .ready_ns = 1785811426840000000ULL,
        .start_ns = 1785811426840040000ULL,
        .delay_ns = 40000,
        .duration_ns = 20000,
        .data = 0x5678,
        .callback_key = 0xcafe,
        .pid = 43000,
        .tid = 43001,
        .epoll_fd = 3,
        .fd = 5,
        .ready_events = 1,
        .match_kind = match_kind,
        .comm = "uv-loop",
    };
    struct cw_epoll_callback_event callback_without_wait_record = {
        .timestamp_ns = 1785811426850100000ULL,
        .ready_ns = 1785811426850000000ULL,
        .start_ns = 1785811426850030000ULL,
        .delay_ns = 30000,
        .duration_ns = 70000,
        .data = 0x6789,
        .callback_key = 0xfeed,
        .pid = 43000,
        .tid = 43001,
        .epoll_fd = 3,
        .fd = 6,
        .ready_events = 1,
        .match_kind = match_kind,
        .comm = "uv-loop",
        .wake = {
            .latency_ns = 80000,
            .action = CW_EPOLL_WAKE_ACTION_SOCKET_WRITE,
            .flags = CW_EPOLL_WAKE_LATENCY_VALID,
            .source_pid = 43000,
            .source_tid = 43012,
            .comm = "producer",
        },
    };
    FILE *stream;
    int result = -1;

    if (!strcmp(mode, "libevent"))
        callback.wake.action = CW_EPOLL_WAKE_ACTION_SOCKET_WRITE;

    if (!report)
        return -1;
    if (cw_runtime_report_capture_epoll_wait(report, &wait) ||
        cw_runtime_report_capture_epoll_callback(
            report, &callback, callback_name) ||
        cw_runtime_report_capture_epoll_wait(
            report, &wait_without_waker) ||
        cw_runtime_report_capture_epoll_callback(
            report, &callback_without_waker, callback_name))
        goto out;
    if (!strcmp(mode, "libevent") &&
        cw_runtime_report_capture_epoll_callback(
            report, &callback_without_wait_record, callback_name))
        goto out;
    stream = fopen(path, "wb");
    if (!stream)
        goto out;
    {
        int write_error = cw_runtime_report_write(report, stream);

        if (fclose(stream) || write_error)
            goto out;
    }
    result = verify_report_markers(path, expected, expected_count);
out:
    cw_runtime_report_destroy(report);
    return result;
}

static int write_libuv_work_report(const char *path)
{
    static const char *const expected[] = {
        "function renderLibuvWorkSequence",
        "libuv work lifecycle",
        "libuv event loop",
        "libuv worker",
        "Two real thread lanes",
        "event loop active / backlog",
        "uv_async_send → epoll_wait*",
        "epoll_wait* → ",
        "\"handoff_kind\":1",
        "\"source\":\"work_cb\"",
        "\"target\":\"after_work_cb\"",
    };
    struct cw_report_chain chain = {
        .timestamp_ms = 1785898535422ULL,
        .pid = 44000,
        .tid = 44001,
        .comm = "uv-loop",
        .duration_ns = 50309000,
        .hop_count = 2,
        .hops = {
            {
                .index = 0,
                .pid = 44000,
                .tid = 44001,
                .target_tid = 44011,
                .target_arg = 1,
                .comm = "uv-loop",
                .source = "submit_work",
                .target = "work_cb",
                .key = 0x557afddec7680ULL,
                .queue_ns = 42075,
                .work_ns = 2117000,
                .offcpu_ns = 2080000,
                .blocked_ns = 2070000,
                .runqueue_ns = 4000,
            },
            {
                .index = 1,
                .pid = 44000,
                .tid = 44011,
                .target_tid = 44001,
                .target_arg = 1,
                .comm = "libuv-worker",
                .source = "work_cb",
                .target = "after_work_cb",
                .source_exit = true,
                .handoff_kind = CW_ASYNC_HANDOFF_LIBUV,
                .handoff_flags = CW_ASYNC_LIFECYCLE_NOTIFY_ENTRY |
                    CW_ASYNC_LIFECYCLE_NOTIFY_EXIT |
                    CW_ASYNC_LIFECYCLE_EPOLL_EXIT,
                .key = 0x557afddec7680ULL,
                .queue_ns = 48008000,
                .publish_ns = 12594,
                .notify_ns = 6003,
                .loop_ns = 47970000,
                .poll_ns = 3040,
                .dispatch_ns = 16363,
                .work_ns = 141925,
            },
        },
    };
    FILE *stream;
    bool first = true;

    stream = fopen(path, "wb");
    if (!stream)
        return -1;
    if (cw_html_report_begin(stream) ||
        cw_html_report_write(stream, &chain, &first) ||
        cw_html_report_end(stream, NULL, 0) || fclose(stream))
        return -1;
    return verify_report_markers(
        path, expected, sizeof(expected) / sizeof(expected[0]));
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/tmp/callweave-report-test.html";
    char runtime_path[PATH_MAX];
    char libuv_path[PATH_MAX];
    char libevent_path[PATH_MAX];
    char libuv_work_path[PATH_MAX];
    struct cw_report_chain chain = {
        .timestamp_ms = 1785811426789ULL,
        .pid = 42000,
        .tid = 42001,
        .comm = "api-main",
        .duration_ns = 105400000,
        .hop_count = 3,
        .hops = {
            {
                .index = 0,
                .pid = 42000,
                .tid = 42001,
                .target_tid = 42011,
                .target_arg = 1,
                .comm = "api-main",
                .source = "submit_decode_task",
                .target = "decode_request",
                .key = 0xa001,
                .queue_ns = 8200000,
                .work_ns = 18400000,
                .offcpu_ns = 2300000,
                .blocked_ns = 1800000,
                .runqueue_ns = 300000,
            },
            {
                .index = 1,
                .pid = 42000,
                .tid = 42011,
                .target_tid = 42021,
                .target_arg = 2,
                .comm = "decode-pool",
                .source = "submit_enrich_task",
                .target = "enrich_request",
                .key = 0xa001,
                .queue_ns = 12700000,
                .work_ns = 25100000,
                .offcpu_ns = 9100000,
                .blocked_ns = 7600000,
                .runqueue_ns = 900000,
            },
            {
                .index = 2,
                .pid = 42000,
                .tid = 42021,
                .target_tid = 42031,
                .target_arg = 1,
                .comm = "enrich-pool",
                .source = "submit_persist_task",
                .target = "persist_result",
                .key = 0xa001,
                .queue_ns = 7400000,
                .work_ns = 33600000,
                .offcpu_ns = 22100000,
                .blocked_ns = 20400000,
                .runqueue_ns = 1100000,
            },
        },
    };
    struct cw_queue_diagnostic diagnostics[] = {
        {.index = 0, .source = "submit_decode_task", .target = "decode_request",
         .submitted = 40, .started = 40, .completed = 40,
         .peak_pending = 3, .peak_active = 2, .queue_total_ns = 260000000,
         .work_total_ns = 720000000, .worker_count = 2,
         .busiest_worker_tid = 42011},
        {.index = 1, .source = "submit_enrich_task", .target = "enrich_request",
         .submitted = 40, .started = 40, .completed = 39,
         .pending = 1, .peak_pending = 6, .peak_active = 3,
         .queue_total_ns = 510000000, .work_total_ns = 980000000,
         .worker_count = 3, .busiest_worker_tid = 42021},
        {.index = 2, .source = "submit_persist_task", .target = "persist_result",
         .submitted = 39, .started = 39, .completed = 39,
         .peak_pending = 4, .peak_active = 1, .queue_total_ns = 300000000,
         .work_total_ns = 1310000000, .futex_waits = 17,
         .worker_count = 1, .busiest_worker_tid = 42031},
    };
    FILE *stream;
    bool first = true;

    stream = fopen(path, "wb");
    if (!stream) {
        fprintf(stderr, "cannot create %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (cw_html_report_begin(stream) ||
        cw_html_report_write(stream, &chain, &first) ||
        cw_html_report_end(stream, diagnostics,
                           sizeof(diagnostics) / sizeof(diagnostics[0])) ||
        fclose(stream)) {
        fprintf(stderr, "cannot write %s\n", path);
        return 1;
    }
    if (verify_async_report(path)) {
        fprintf(stderr, "generated report failed validation: %s\n", path);
        return 1;
    }
    if (snprintf(runtime_path, sizeof(runtime_path), "%s.runtime.html", path) >=
            (int)sizeof(runtime_path) ||
        write_runtime_report(runtime_path)) {
        fprintf(stderr, "generated runtime report failed validation\n");
        return 1;
    }
    if (snprintf(libuv_path, sizeof(libuv_path), "%s.libuv.html", path) >=
            (int)sizeof(libuv_path) ||
        write_event_loop_report(
            libuv_path, "libuv", CW_EPOLL_CALLBACK_MATCH_LIBUV,
            "poll_callback")) {
        fprintf(stderr, "generated libuv report failed validation\n");
        return 1;
    }
    if (snprintf(libevent_path, sizeof(libevent_path),
                 "%s.libevent.html", path) >=
            (int)sizeof(libevent_path) ||
        write_event_loop_report(
            libevent_path, "libevent", CW_EPOLL_CALLBACK_MATCH_LIBEVENT,
            "bufferevent_read_callback")) {
        fprintf(stderr, "generated libevent report failed validation\n");
        return 1;
    }
    if (snprintf(libuv_work_path, sizeof(libuv_work_path),
                 "%s.libuv-work.html", path) >=
            (int)sizeof(libuv_work_path) ||
        write_libuv_work_report(libuv_work_path)) {
        fprintf(stderr, "generated libuv work report failed validation\n");
        return 1;
    }
    printf("generated report: %s\n", path);
    printf("generated runtime report: %s\n", runtime_path);
    printf("generated libuv report: %s\n", libuv_path);
    printf("generated libevent report: %s\n", libevent_path);
    printf("generated libuv work report: %s\n", libuv_work_path);
    return 0;
}
