// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_RUNTIME_REPORT_H
#define CALLWEAVE_RUNTIME_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct cw_epoll_callback_event;
struct cw_epoll_dispatch_event;
struct cw_epoll_event;
struct cw_runtime_report;
struct io_uring_callback_event;
struct io_uring_event;

struct cw_runtime_report *cw_runtime_report_create(const char *mode);
void cw_runtime_report_destroy(struct cw_runtime_report *report);

int cw_runtime_report_capture_io_uring(
    struct cw_runtime_report *report,
    const struct io_uring_event *event,
    const char *operation);
int cw_runtime_report_capture_io_uring_callback(
    struct cw_runtime_report *report,
    const struct io_uring_callback_event *event,
    const char *operation,
    const char *callback_name,
    bool allow_pending);
int cw_runtime_report_capture_epoll_wait(
    struct cw_runtime_report *report,
    const struct cw_epoll_event *event);
int cw_runtime_report_capture_epoll_dispatch(
    struct cw_runtime_report *report,
    const struct cw_epoll_dispatch_event *event);
int cw_runtime_report_capture_epoll_callback(
    struct cw_runtime_report *report,
    const struct cw_epoll_callback_event *event,
    const char *callback_name);

int cw_runtime_report_write(
    struct cw_runtime_report *report, FILE *stream);

#endif
