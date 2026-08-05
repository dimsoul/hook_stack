// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <uv.h>

struct work_request {
    uv_work_t work;
    uint64_t worker_finished_ns;
    unsigned int sequence;
};

static uv_loop_t *test_loop;
static uv_timer_t loop_blocker;
static unsigned int iterations = 40;
static unsigned int completed;
static unsigned int block_loop_ms = 50;

static uint64_t monotonic_ns(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void loop_blocker_cb(uv_timer_t *timer)
{
    (void)timer;
    if (block_loop_ms)
        usleep((useconds_t)block_loop_ms * 1000U);
}

__attribute__((noinline))
void work_cb(uv_work_t *work)
{
    struct work_request *request = (struct work_request *)work;

    usleep(2000);
    request->worker_finished_ns = monotonic_ns();
}

__attribute__((noinline))
void after_work_cb(uv_work_t *work, int status);

__attribute__((noinline))
void submit_work(struct work_request *request)
{
    int error = uv_queue_work(
        test_loop, &request->work, work_cb, after_work_cb);

    if (error) {
        fprintf(stderr, "uv_queue_work: %s\n", uv_strerror(error));
        free(request);
        uv_stop(test_loop);
        return;
    }
    uv_timer_start(&loop_blocker, loop_blocker_cb, 0, 0);
}

static int queue_next(void)
{
    struct work_request *request = calloc(1, sizeof(*request));

    if (!request) {
        fprintf(stderr, "calloc: %s\n", strerror(errno));
        return -1;
    }
    request->sequence = completed + 1;
    submit_work(request);
    return 0;
}

__attribute__((noinline))
void after_work_cb(uv_work_t *work, int status)
{
    struct work_request *request = (struct work_request *)work;
    uint64_t callback_ns = monotonic_ns();
    uint64_t delay_ns = callback_ns - request->worker_finished_ns;

    printf("request=%u status=%d work_cb-completed->after_work_cb=%.3f ms\n",
           request->sequence, status, (double)delay_ns / 1000000.0);
    free(request);
    completed++;
    if (completed < iterations) {
        if (queue_next())
            uv_stop(test_loop);
        return;
    }
    uv_close((uv_handle_t *)&loop_blocker, NULL);
}

static int parse_u32(const char *option, const char *text,
                     unsigned int minimum, unsigned int maximum,
                     unsigned int *value)
{
    unsigned long parsed;
    char *end = NULL;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno || !end || *end || parsed < minimum || parsed > maximum) {
        fprintf(stderr, "invalid %s: %s\n", option, text);
        return -1;
    }
    *value = (unsigned int)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned int startup_delay = 5;
    int argument;
    int error;

    for (argument = 1; argument < argc; argument++) {
        if (!strcmp(argv[argument], "--iterations") &&
            argument + 1 < argc) {
            if (parse_u32("iterations", argv[++argument], 1, 100000,
                          &iterations))
                return 2;
        } else if (!strcmp(argv[argument], "--block-loop-ms") &&
                   argument + 1 < argc) {
            if (parse_u32("block-loop-ms", argv[++argument], 0, 60000,
                          &block_loop_ms))
                return 2;
        } else if (!strcmp(argv[argument], "--startup-delay") &&
                   argument + 1 < argc) {
            if (parse_u32("startup-delay", argv[++argument], 0, 60,
                          &startup_delay))
                return 2;
        } else {
            fprintf(stderr,
                    "usage: %s [--iterations N] [--block-loop-ms MS] "
                    "[--startup-delay SEC]\n",
                    argv[0]);
            return 2;
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("trace_libuv_work_test PID=%ld; starting in %u second(s)\n",
           (long)getpid(), startup_delay);
    printf("expected symptom: work_cb completed -> after_work_cb about %u ms\n",
           block_loop_ms);
    sleep(startup_delay);

    test_loop = uv_default_loop();
    error = uv_timer_init(test_loop, &loop_blocker);
    if (error) {
        fprintf(stderr, "uv_timer_init: %s\n", uv_strerror(error));
        return 1;
    }
    if (queue_next())
        return 1;
    error = uv_run(test_loop, UV_RUN_DEFAULT);
    if (error)
        fprintf(stderr, "uv_run left %d active handle(s)\n", error);
    error = uv_loop_close(test_loop);
    if (error) {
        fprintf(stderr, "uv_loop_close: %s\n", uv_strerror(error));
        return 1;
    }
    printf("completed %u request(s)\n", completed);
    return 0;
}
