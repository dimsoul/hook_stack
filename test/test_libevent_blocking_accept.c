// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <event2/event.h>
#include <event2/util.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum listener_mode {
    LISTENER_BLOCKING,
    LISTENER_NONBLOCKING,
};

struct test_context {
    struct event_base *base;
    struct sockaddr_in listener_address;
    enum listener_mode mode;
    int accepted;
    int callback_entries;
    int timer_ticks;
    bool accept_failed;
};

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L,
    };

    while (nanosleep(&delay, &delay) && errno == EINTR)
        ;
}

static int connect_once(const struct sockaddr_in *address, int sequence)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("client socket");
        return -1;
    }
    if (connect(fd, (const struct sockaddr *)address, sizeof(*address))) {
        perror("client connect");
        close(fd);
        return -1;
    }
    printf("client connected #%d\n", sequence);
    close(fd);
    return 0;
}

static void *client_main(void *argument)
{
    const struct test_context *context = argument;

    sleep_milliseconds(800);
    if (connect_once(&context->listener_address, 1))
        return NULL;
    sleep_milliseconds(1500);
    (void)connect_once(&context->listener_address, 2);
    return NULL;
}

__attribute__((noinline))
static void timer_callback(
    evutil_socket_t fd, short events, void *argument)
{
    struct test_context *context = argument;

    (void)fd;
    (void)events;
    printf("timer tick %d\n", ++context->timer_ticks);
    if (context->timer_ticks >= 30) {
        fprintf(stderr, "watchdog: listener scenario did not finish\n");
        event_base_loopbreak(context->base);
    }
}

__attribute__((noinline))
static void accept_callback(
    evutil_socket_t listener_fd, short events, void *argument)
{
    struct test_context *context = argument;
    struct timeval exit_delay = {
        .tv_sec = 0,
        .tv_usec = 600000,
    };

    (void)events;
    context->callback_entries++;
    printf("accept callback entered #%d\n", context->callback_entries);

    for (;;) {
        int client_fd = accept(listener_fd, NULL, NULL);

        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            if (context->mode == LISTENER_NONBLOCKING &&
                (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            perror("accept");
            context->accept_failed = true;
            event_base_loopbreak(context->base);
            return;
        }

        context->accepted++;
        printf("accept returned #%d\n", context->accepted);
        close(client_fd);
        if (context->mode == LISTENER_BLOCKING && context->accepted >= 2)
            break;
    }

    if (context->accepted >= 2)
        event_base_loopexit(context->base, &exit_delay);
    printf("accept callback returned\n");
}

static int parse_mode(int argc, char **argv, enum listener_mode *mode)
{
    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "--blocking"))) {
        *mode = LISTENER_BLOCKING;
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--nonblocking")) {
        *mode = LISTENER_NONBLOCKING;
        return 0;
    }

    fprintf(stderr, "usage: %s [--blocking|--nonblocking]\n", argv[0]);
    return -1;
}

int main(int argc, char **argv)
{
    struct test_context context = {0};
    struct event_base *base = NULL;
    struct event *listener_event = NULL;
    struct event *timer_event = NULL;
    struct timeval timer_interval = {
        .tv_sec = 0,
        .tv_usec = 200000,
    };
    pthread_t client_thread;
    socklen_t address_size = sizeof(context.listener_address);
    bool client_started = false;
    int listener_fd = -1;
    int reuse = 1;
    int result = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (parse_mode(argc, argv, &context.mode))
        return 2;

    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        perror("listener socket");
        goto out;
    }
    (void)setsockopt(
        listener_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    context.listener_address.sin_family = AF_INET;
    context.listener_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    context.listener_address.sin_port = 0;
    if (bind(
            listener_fd,
            (const struct sockaddr *)&context.listener_address,
            sizeof(context.listener_address)) ||
        listen(listener_fd, 16) ||
        getsockname(
            listener_fd,
            (struct sockaddr *)&context.listener_address,
            &address_size)) {
        perror("listener setup");
        goto out;
    }
    if (context.mode == LISTENER_NONBLOCKING &&
        evutil_make_socket_nonblocking(listener_fd)) {
        perror("evutil_make_socket_nonblocking");
        goto out;
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "event_base_new failed\n");
        goto out;
    }
    context.base = base;
    listener_event = event_new(
        base, listener_fd, EV_READ | EV_PERSIST,
        accept_callback, &context);
    timer_event = event_new(
        base, -1, EV_PERSIST, timer_callback, &context);
    if (!listener_event || !timer_event ||
        event_add(listener_event, NULL) ||
        event_add(timer_event, &timer_interval)) {
        fprintf(stderr, "libevent setup failed\n");
        goto out;
    }

    printf(
        "%s listener PID %d fd=%d port=%u\n",
        context.mode == LISTENER_BLOCKING ? "blocking" : "nonblocking",
        (int)getpid(), listener_fd,
        (unsigned int)ntohs(context.listener_address.sin_port));
    if (pthread_create(&client_thread, NULL, client_main, &context)) {
        fprintf(stderr, "pthread_create failed\n");
        goto out;
    }
    client_started = true;
    if (event_base_dispatch(base) < 0)
        fprintf(stderr, "event_base_dispatch failed\n");
    pthread_join(client_thread, NULL);
    client_started = false;

    printf(
        "summary mode=%s accepted=%d callbacks=%d timer_ticks=%d\n",
        context.mode == LISTENER_BLOCKING ? "blocking" : "nonblocking",
        context.accepted, context.callback_entries, context.timer_ticks);
    result = !context.accept_failed && context.accepted == 2 &&
        context.callback_entries ==
            (context.mode == LISTENER_BLOCKING ? 1 : 2)
        ? 0
        : 1;

out:
    if (client_started)
        pthread_join(client_thread, NULL);
    if (listener_event)
        event_free(listener_event);
    if (timer_event)
        event_free(timer_event);
    if (base)
        event_base_free(base);
    if (listener_fd >= 0)
        close(listener_fd);
    return result;
}
