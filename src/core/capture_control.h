// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_CAPTURE_CONTROL_H
#define CALLWEAVE_CAPTURE_CONTROL_H

#include <stdbool.h>
#include <signal.h>

enum cw_stop_reason {
    CW_STOP_NONE,
    CW_STOP_SIGNAL,
    CW_STOP_MAX_EVENTS,
    CW_STOP_DURATION,
    CW_STOP_TARGET_EXIT,
    CW_STOP_OUTPUT_ERROR,
};

enum cw_capture_phase {
    CW_CAPTURE_RUNNING,
    CW_CAPTURE_FINALIZING,
    CW_CAPTURE_FORCE_EXIT,
};

struct cw_capture_control {
    int signal_fd;
    sigset_t previous_signal_mask;
    enum cw_capture_phase phase;
    enum cw_stop_reason reason;
    bool signal_mask_saved;
};

#define CW_CAPTURE_CONTROL_INITIALIZER \
    { .signal_fd = -1, .phase = CW_CAPTURE_RUNNING }

int cw_capture_control_init(struct cw_capture_control *control);
void cw_capture_control_destroy(struct cw_capture_control *control);
int cw_capture_drain_signals(struct cw_capture_control *control);
int cw_capture_wait(struct cw_capture_control *control, int timeout_ms);
int cw_capture_signal_fd(const struct cw_capture_control *control);
void cw_capture_prepare_child(const struct cw_capture_control *control);

void cw_capture_request_stop(struct cw_capture_control *control,
                             enum cw_stop_reason reason);
bool cw_capture_running(const struct cw_capture_control *control);
bool cw_capture_accepts_drain_events(
    const struct cw_capture_control *control);
bool cw_capture_should_finalize(const struct cw_capture_control *control);
bool cw_capture_cancelled(struct cw_capture_control *control);
bool cw_capture_stopped_by_signal(const struct cw_capture_control *control);

#endif
