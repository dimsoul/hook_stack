// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "core/capture_control.h"

static void record_signal(struct cw_capture_control *control)
{
    if (control->phase == CW_CAPTURE_RUNNING) {
        control->phase = CW_CAPTURE_FINALIZING;
        control->reason = CW_STOP_SIGNAL;
    } else {
        control->phase = CW_CAPTURE_FORCE_EXIT;
    }
}

int cw_capture_control_init(struct cw_capture_control *control)
{
    sigset_t signals;
    int error;

    memset(control, 0, sizeof(*control));
    control->signal_fd = -1;
    control->phase = CW_CAPTURE_RUNNING;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &signals,
                    &control->previous_signal_mask)) {
        return -errno;
    }
    control->signal_mask_saved = true;
    control->signal_fd = signalfd(
        -1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
    if (control->signal_fd >= 0)
        return 0;

    error = errno;
    sigprocmask(SIG_SETMASK, &control->previous_signal_mask, NULL);
    control->signal_mask_saved = false;
    return -error;
}

void cw_capture_control_destroy(struct cw_capture_control *control)
{
    if (control->signal_fd >= 0) {
        close(control->signal_fd);
        control->signal_fd = -1;
    }
    if (control->signal_mask_saved) {
        sigprocmask(SIG_SETMASK, &control->previous_signal_mask, NULL);
        control->signal_mask_saved = false;
    }
}

int cw_capture_drain_signals(struct cw_capture_control *control)
{
    struct signalfd_siginfo signal_info;

    if (control->signal_fd < 0)
        return 0;
    for (;;) {
        ssize_t size = read(control->signal_fd, &signal_info,
                            sizeof(signal_info));

        if (size == (ssize_t)sizeof(signal_info)) {
            if (signal_info.ssi_signo == SIGINT ||
                signal_info.ssi_signo == SIGTERM) {
                record_signal(control);
            }
            continue;
        }
        if (size < 0 && errno == EINTR)
            continue;
        if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;
        return size < 0 ? -errno : -EIO;
    }
}

int cw_capture_wait(struct cw_capture_control *control, int timeout_ms)
{
    struct pollfd descriptor = {
        .fd = control->signal_fd,
        .events = POLLIN,
    };
    int result;

    if (control->signal_fd < 0)
        return 0;
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
        return -errno;
    return cw_capture_drain_signals(control);
}

int cw_capture_signal_fd(const struct cw_capture_control *control)
{
    return control ? control->signal_fd : -1;
}

void cw_capture_prepare_child(const struct cw_capture_control *control)
{
    if (control && control->signal_mask_saved)
        sigprocmask(SIG_SETMASK, &control->previous_signal_mask, NULL);
}

void cw_capture_request_stop(struct cw_capture_control *control,
                             enum cw_stop_reason reason)
{
    if (!control || control->phase != CW_CAPTURE_RUNNING)
        return;
    control->phase = CW_CAPTURE_FINALIZING;
    control->reason = reason;
}

bool cw_capture_running(const struct cw_capture_control *control)
{
    return !control || control->phase == CW_CAPTURE_RUNNING;
}

bool cw_capture_should_finalize(const struct cw_capture_control *control)
{
    return !control || control->phase != CW_CAPTURE_FORCE_EXIT;
}

bool cw_capture_cancelled(struct cw_capture_control *control)
{
    if (!control)
        return false;
    cw_capture_drain_signals(control);
    return control->phase == CW_CAPTURE_FORCE_EXIT;
}

bool cw_capture_stopped_by_signal(const struct cw_capture_control *control)
{
    return control && control->reason == CW_STOP_SIGNAL &&
           control->phase == CW_CAPTURE_FINALIZING;
}
