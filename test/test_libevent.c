// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>

struct test_context {
    struct event_base *base;
    int writer_fd;
    int bufferevent_writer_fd;
    struct sockaddr_in listener_address;
    int expected;
    int expected_accepts;
    int handled;
    int bufferevent_handled;
    int accepted;
    int timer_ticks;
};

static void maybe_stop(struct test_context *context)
{
    if (context->handled >= context->expected &&
        context->bufferevent_handled >= context->expected &&
        context->accepted >= context->expected_accepts)
        event_base_loopbreak(context->base);
}

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L,
    };

    while (nanosleep(&delay, &delay) && errno == EINTR)
        ;
}

static void simulate_work(long microseconds)
{
    struct timespec delay = {
        .tv_sec = microseconds / 1000000,
        .tv_nsec = (microseconds % 1000000) * 1000L,
    };

    while (nanosleep(&delay, &delay) && errno == EINTR)
        ;
}

__attribute__((noinline))
static void socket_ready_callback(
    evutil_socket_t fd, short events, void *argument)
{
    struct test_context *context = argument;
    unsigned char value;

    if (!(events & EV_READ))
        return;
    if (recv(fd, &value, sizeof(value), 0) != 1)
        return;
    context->handled++;
    if (context->handled % 10 == 0)
        simulate_work(3000);
    else
        simulate_work(250);
    maybe_stop(context);
}

__attribute__((noinline))
static void bufferevent_read_callback(
    struct bufferevent *bufferevent, void *argument)
{
    struct test_context *context = argument;
    unsigned char buffer[64];
    size_t count;

    while ((count = bufferevent_read(
                bufferevent, buffer, sizeof(buffer))) > 0)
        context->bufferevent_handled += (int)count;
    if (context->bufferevent_handled % 10 == 0)
        simulate_work(2200);
    else
        simulate_work(200);
    maybe_stop(context);
}

__attribute__((noinline))
static void bufferevent_status_callback(
    struct bufferevent *bufferevent, short events, void *argument)
{
    struct test_context *context = argument;

    (void)bufferevent;
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
        maybe_stop(context);
}

__attribute__((noinline))
static void listener_accept_callback(
    struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *address, int address_length, void *argument)
{
    struct test_context *context = argument;

    (void)listener;
    (void)address;
    (void)address_length;
    context->accepted++;
    simulate_work(700);
    close(fd);
    maybe_stop(context);
}

__attribute__((noinline))
static void timer_callback(
    evutil_socket_t fd, short events, void *argument)
{
    struct test_context *context = argument;

    (void)fd;
    (void)events;
    context->timer_ticks++;
    simulate_work(500);
    maybe_stop(context);
    if (context->timer_ticks > context->expected / 5 + 4) {
        fprintf(
            stderr,
            "watchdog: raw=%d bufferevent=%d accepts=%d/%d\n",
            context->handled, context->bufferevent_handled,
            context->accepted, context->expected_accepts);
        event_base_loopbreak(context->base);
    }
}

static void *writer_main(void *argument)
{
    struct test_context *context = argument;
    int index;

    for (index = 0; index < context->expected; index++) {
        unsigned char value = (unsigned char)index;
        int client;

        sleep_milliseconds(100);
        if (send(context->writer_fd, &value, sizeof(value), 0) != 1)
            break;
        if (send(
                context->bufferevent_writer_fd,
                &value, sizeof(value), 0) != 1)
            break;
        if ((index + 1) % 20)
            continue;
        client = socket(AF_INET, SOCK_STREAM, 0);
        if (client < 0)
            break;
        if (connect(
                client,
                (const struct sockaddr *)&context->listener_address,
                sizeof(context->listener_address))) {
            close(client);
            break;
        }
        close(client);
    }
    return NULL;
}

static int parse_positive(const char *text, int *value)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno || !end || *end || parsed < 0 || parsed > 3600)
        return -1;
    *value = (int)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    struct event_base *base = NULL;
    struct event *socket_event = NULL;
    struct event *timer_event = NULL;
    struct bufferevent *bufferevent = NULL;
    struct evconnlistener *listener = NULL;
    struct test_context context = {
        .expected = 60,
    };
    struct timeval timer_interval = {
        .tv_sec = 0,
        .tv_usec = 500000,
    };
    pthread_t writer;
    int sockets[2] = {-1, -1};
    int bufferevent_sockets[2] = {-1, -1};
    int listener_fd = -1;
    int startup_delay = 3;
    int index;
    int error = 1;

    for (index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "--startup-delay") &&
            index + 1 < argc) {
            if (parse_positive(argv[++index], &startup_delay)) {
                fprintf(stderr, "invalid startup delay\n");
                return 2;
            }
        } else if (!strcmp(argv[index], "--iterations") &&
                   index + 1 < argc) {
            if (parse_positive(argv[++index], &context.expected) ||
                !context.expected) {
                fprintf(stderr, "invalid iteration count\n");
                return 2;
            }
        } else {
            fprintf(stderr, "usage: %s [--startup-delay SEC] "
                    "[--iterations N]\n", argv[0]);
            return 2;
        }
    }
    printf("libevent test PID %d; creating events in %d second(s), "
           "%d I/O callbacks expected\n",
           (int)getpid(), startup_delay, context.expected);
    fflush(stdout);
    sleep((unsigned int)startup_delay);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
        perror("socketpair");
        goto out;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, bufferevent_sockets)) {
        perror("bufferevent socketpair");
        goto out;
    }
    base = event_base_new();
    if (!base) {
        fprintf(stderr, "event_base_new failed\n");
        goto out;
    }
    context.base = base;
    context.writer_fd = sockets[1];
    context.bufferevent_writer_fd = bufferevent_sockets[1];
    context.expected_accepts = context.expected / 20;
    socket_event = event_new(
        base, sockets[0], EV_READ | EV_PERSIST,
        socket_ready_callback, &context);
    timer_event = event_new(
        base, -1, EV_PERSIST, timer_callback, &context);
    if (!socket_event || !timer_event) {
        fprintf(stderr, "event_new failed\n");
        goto out;
    }
    bufferevent = bufferevent_socket_new(
        base, bufferevent_sockets[0], BEV_OPT_CLOSE_ON_FREE);
    if (!bufferevent) {
        fprintf(stderr, "bufferevent_socket_new failed\n");
        goto out;
    }
    bufferevent_sockets[0] = -1;
    bufferevent_setcb(
        bufferevent, bufferevent_read_callback, NULL,
        bufferevent_status_callback, &context);
    if (bufferevent_enable(bufferevent, EV_READ)) {
        fprintf(stderr, "bufferevent_enable failed\n");
        goto out;
    }
    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        perror("listener socket");
        goto out;
    }
    {
        int reuse = 1;
        socklen_t address_size = sizeof(context.listener_address);

        context.listener_address.sin_family = AF_INET;
        context.listener_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        context.listener_address.sin_port = 0;
        (void)setsockopt(
            listener_fd, SOL_SOCKET, SO_REUSEADDR,
            &reuse, sizeof(reuse));
        if (bind(
                listener_fd,
                (const struct sockaddr *)&context.listener_address,
                sizeof(context.listener_address)) ||
            listen(listener_fd, 16) ||
            evutil_make_socket_nonblocking(listener_fd) ||
            getsockname(
                listener_fd,
                (struct sockaddr *)&context.listener_address,
                &address_size)) {
            perror("listener setup");
            goto out;
        }
    }
    listener = evconnlistener_new(
        base, listener_accept_callback, &context,
        LEV_OPT_CLOSE_ON_FREE, 16, listener_fd);
    if (!listener) {
        fprintf(stderr, "evconnlistener_new failed\n");
        goto out;
    }
    listener_fd = -1;
    if (event_add(socket_event, NULL) ||
        event_add(timer_event, &timer_interval)) {
        fprintf(stderr, "event_add failed\n");
        goto out;
    }
    if (pthread_create(&writer, NULL, writer_main, &context)) {
        fprintf(stderr, "pthread_create failed\n");
        goto out;
    }
    if (event_base_dispatch(base) < 0)
        fprintf(stderr, "event_base_dispatch failed\n");
    fprintf(stderr,
            "event loop stopped: raw=%d bufferevent=%d accepts=%d/%d "
            "timer=%d\n",
            context.handled, context.bufferevent_handled,
            context.accepted, context.expected_accepts,
            context.timer_ticks);
    pthread_join(writer, NULL);
    printf("handled raw=%d bufferevent=%d accepts=%d timer=%d\n",
           context.handled, context.bufferevent_handled,
           context.accepted, context.timer_ticks);
    error = context.handled == context.expected &&
            context.bufferevent_handled == context.expected &&
            context.accepted == context.expected_accepts ? 0 : 1;

out:
    if (socket_event)
        event_del(socket_event);
    if (timer_event)
        event_del(timer_event);
    if (listener)
        evconnlistener_free(listener);
    if (bufferevent)
        bufferevent_free(bufferevent);
    if (socket_event)
        event_free(socket_event);
    if (timer_event)
        event_free(timer_event);
    if (base)
        event_base_free(base);
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    if (bufferevent_sockets[0] >= 0)
        close(bufferevent_sockets[0]);
    if (bufferevent_sockets[1] >= 0)
        close(bufferevent_sockets[1]);
    if (listener_fd >= 0)
        close(listener_fd);
    return error;
}
