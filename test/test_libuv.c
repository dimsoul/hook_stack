// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <uv.h>

static uv_poll_t poll_handle;
static uv_timer_t stop_timer;
static int pipe_fds[2] = {-1, -1};
static atomic_bool producer_running = true;
static unsigned callback_count;

static void close_callback(uv_handle_t *handle)
{
    (void)handle;
}

static void poll_callback(
    uv_poll_t *handle, int status, int events)
{
    char buffer[256];
    ssize_t length;

    (void)handle;
    if (status < 0) {
        fprintf(stderr, "poll callback error: %s\n",
                uv_strerror(status));
        return;
    }
    if (!(events & UV_READABLE))
        return;
    do {
        length = read(pipe_fds[0], buffer, sizeof(buffer));
    } while (length > 0);
    if (length < 0 && errno != EAGAIN)
        fprintf(stderr, "read failed: %s\n", strerror(errno));
    callback_count++;
    if (callback_count % 5 == 0)
        usleep(3000);
}

static void stop_callback(uv_timer_t *timer)
{
    uv_loop_t *loop = timer->loop;

    atomic_store_explicit(
        &producer_running, false, memory_order_release);
    uv_poll_stop(&poll_handle);
    uv_timer_stop(&stop_timer);
    uv_close((uv_handle_t *)&poll_handle, close_callback);
    uv_close((uv_handle_t *)&stop_timer, close_callback);
    uv_stop(loop);
}

static void *producer_main(void *argument)
{
    unsigned sequence = 0;

    (void)argument;
    while (atomic_load_explicit(
               &producer_running, memory_order_acquire)) {
        char message[32];
        int length = snprintf(
            message, sizeof(message), "event-%u\n", sequence++);

        if (write(pipe_fds[1], message, (size_t)length) < 0 &&
            errno != EAGAIN && errno != EINTR)
            break;
        usleep(50000);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    unsigned long duration = 15;
    char *end = NULL;
    pthread_t producer;
    uv_loop_t *loop;
    int error;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [duration-seconds]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        errno = 0;
        duration = strtoul(argv[1], &end, 10);
        if (errno || !end || *end || !duration || duration > 3600) {
            fprintf(stderr, "invalid duration: %s\n", argv[1]);
            return 2;
        }
    }
    printf(
        "trace_libuv_test PID %d; initializing uv_poll_t in 5 seconds\n",
        (int)getpid());
    fflush(stdout);
    sleep(5);

    if (pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC)) {
        perror("pipe2");
        return 1;
    }
    loop = uv_default_loop();
    error = uv_poll_init(loop, &poll_handle, pipe_fds[0]);
    if (error) {
        fprintf(stderr, "uv_poll_init: %s\n", uv_strerror(error));
        return 1;
    }
    error = uv_poll_start(
        &poll_handle, UV_READABLE, poll_callback);
    if (error) {
        fprintf(stderr, "uv_poll_start: %s\n", uv_strerror(error));
        return 1;
    }
    error = uv_timer_init(loop, &stop_timer);
    if (error) {
        fprintf(stderr, "uv_timer_init: %s\n", uv_strerror(error));
        return 1;
    }
    error = uv_timer_start(
        &stop_timer, stop_callback,
        duration * 1000, 0);
    if (error) {
        fprintf(stderr, "uv_timer_start: %s\n", uv_strerror(error));
        return 1;
    }
    error = pthread_create(
        &producer, NULL, producer_main, NULL);
    if (error) {
        fprintf(stderr, "pthread_create: %s\n", strerror(error));
        return 1;
    }

    printf(
        "uv_poll_t active: handle=%p fd=%d callback=%p for %lu seconds\n",
        (void *)&poll_handle, pipe_fds[0],
        (void *)poll_callback, duration);
    fflush(stdout);
    uv_run(loop, UV_RUN_DEFAULT);
    atomic_store_explicit(
        &producer_running, false, memory_order_release);
    pthread_join(producer, NULL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    printf("completed %u poll callbacks\n", callback_count);
    return 0;
}
