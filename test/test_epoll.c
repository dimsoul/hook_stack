// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

struct test_context {
    int epoll_fd;
    int event_fd;
    int timer_fd;
    int signal_fd;
    int socket_fd;
    int bad_socket_fd;
    int oneshot_fd;
    int reused_fd;
    bool bad_oneshot;
    bool slow_callback;
    unsigned long long bad_et_ready;
    unsigned long long oneshot_ready;
};

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static int add_to_epoll(int epoll_fd, int fd, uint32_t events)
{
    struct epoll_event event = {
        .events = events,
        .data.u64 = 0xe000000000000000ULL | (uint32_t)fd,
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

static int modify_epoll(int epoll_fd, int fd, uint32_t events)
{
    struct epoll_event event = {
        .events = events,
        .data.u64 = 0xe000000000000000ULL | (uint32_t)fd,
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
}

static int create_reused_registration(
    struct test_context *context, int *reused_fd)
{
    int old_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    int alias = fcntl(context->event_fd, F_DUPFD_CLOEXEC, 0);

    if (alias >= 0)
        close(alias);
    if (old_fd < 0)
        return -1;
    if (add_to_epoll(context->epoll_fd, old_fd, EPOLLIN)) {
        close(old_fd);
        return -1;
    }
    if (close(old_fd))
        return -1;
    *reused_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (*reused_fd < 0)
        return -1;
    if (add_to_epoll(context->epoll_fd, *reused_fd, EPOLLIN)) {
        close(*reused_fd);
        *reused_fd = -1;
        return -1;
    }
    context->reused_fd = *reused_fd;
    return 0;
}

static void consume_counter(int fd)
{
    uint64_t value;

    if (read(fd, &value, sizeof(value)) < 0 &&
        errno != EAGAIN)
        fprintf(stderr, "counter read failed: %s\n", strerror(errno));
}

static void consume_signal(int fd)
{
    struct signalfd_siginfo information;

    if (read(fd, &information, sizeof(information)) < 0 &&
        errno != EAGAIN)
        fprintf(stderr, "signalfd read failed: %s\n", strerror(errno));
}

static void consume_socket(int fd)
{
    char first[32];
    char second[32];
    struct iovec vectors[] = {
        {.iov_base = first, .iov_len = sizeof(first)},
        {.iov_base = second, .iov_len = sizeof(second)},
    };
    ssize_t result;

    do {
        result = readv(fd, vectors, 2);
    } while (result > 0);
    if (result < 0 && errno != EAGAIN)
        fprintf(stderr, "socket read failed: %s\n", strerror(errno));
}

static void consume_socket_once(int fd)
{
    char byte;
    struct iovec vector = {
        .iov_base = &byte,
        .iov_len = sizeof(byte),
    };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
    };

    if (recvmsg(fd, &message, MSG_PEEK) < 0 &&
        errno != EAGAIN)
        fprintf(stderr, "socket read failed: %s\n", strerror(errno));
}

static void consume_oneshot(struct test_context *context)
{
    char buffer[64];
    struct iovec vector = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer),
    };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
    };
    ssize_t result;

    do {
        result = recvmsg(context->oneshot_fd, &message, 0);
    } while (result > 0);
    if (result < 0 && errno != EAGAIN)
        fprintf(stderr, "ONESHOT recvmsg failed: %s\n", strerror(errno));
    if (!context->bad_oneshot &&
        modify_epoll(
            context->epoll_fd, context->oneshot_fd,
            EPOLLIN | EPOLLRDHUP | EPOLLONESHOT))
        fprintf(stderr, "ONESHOT rearm failed: %s\n", strerror(errno));
}

__attribute__((noinline))
void epoll_test_callback(
    int fd, struct test_context *context,
    const struct epoll_event *event)
{
    (void)event;

    if (fd == context->event_fd || fd == context->timer_fd ||
        fd == context->reused_fd)
        consume_counter(fd);
    else if (fd == context->signal_fd) {
        consume_signal(fd);
        if (context->slow_callback)
            usleep(2000);
    } else if (fd == context->socket_fd)
        consume_socket(fd);
    else if (fd == context->bad_socket_fd) {
        __atomic_fetch_add(
            &context->bad_et_ready, 1, __ATOMIC_RELAXED);
        consume_socket_once(fd);
    } else if (fd == context->oneshot_fd) {
        __atomic_fetch_add(
            &context->oneshot_ready, 1, __ATOMIC_RELAXED);
        consume_oneshot(context);
    }
}

static void *second_waiter(void *argument)
{
    struct test_context *context = argument;
    struct epoll_event events[8];

    while (!stopping) {
        int ready = epoll_wait(context->epoll_fd, events, 8, 100);
        int index;

        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (index = 0; index < ready; index++) {
            int fd = (int)(uint32_t)events[index].data.u64;

            epoll_test_callback(fd, context, &events[index]);
        }
    }
    return NULL;
}

static int wait_for_events(
    int epoll_fd, struct epoll_event *events,
    unsigned long long iteration)
{
    if (iteration % 3 == 0)
        return epoll_wait(epoll_fd, events, 8, 100);
    if (iteration % 3 == 1)
        return epoll_pwait(epoll_fd, events, 8, 100, NULL);
#ifdef SYS_epoll_pwait2
    {
        struct timespec timeout = {
            .tv_nsec = 100000000,
        };

        return (int)syscall(
            SYS_epoll_pwait2, epoll_fd, events, 8,
            &timeout, NULL, 0);
    }
#else
    return epoll_wait(epoll_fd, events, 8, 100);
#endif
}

int main(int argc, char **argv)
{
    unsigned long long iteration_limit = 0;
    unsigned long long iteration = 0;
    bool demonstrate_bad_et = false;
    bool demonstrate_bad_oneshot = false;
    bool demonstrate_multi_waiter = false;
    bool demonstrate_fd_reuse = false;
    bool demonstrate_slow_callback = false;
    struct itimerspec timer = {
        .it_interval = {
            .tv_nsec = 150000000,
        },
        .it_value = {
            .tv_nsec = 150000000,
        },
    };
    struct epoll_event events[8];
    int sockets[2] = {-1, -1};
    int bad_sockets[2] = {-1, -1};
    int oneshot_sockets[2] = {-1, -1};
    int epoll_fd = -1;
    int event_fd = -1;
    int timer_fd = -1;
    int signal_fd = -1;
    int reused_fd = -1;
    char *end = NULL;
    pthread_t waiter_thread;
    bool waiter_started = false;
    struct test_context context;
    sigset_t signal_mask;

    {
        int argument;

        for (argument = 1; argument < argc; argument++) {
            if (!strcmp(argv[argument], "--bad-et")) {
                demonstrate_bad_et = true;
                continue;
            }
            if (!strcmp(argv[argument], "--bad-oneshot")) {
                demonstrate_bad_oneshot = true;
                continue;
            }
            if (!strcmp(argv[argument], "--multi-waiter")) {
                demonstrate_multi_waiter = true;
                continue;
            }
            if (!strcmp(argv[argument], "--fd-reuse")) {
                demonstrate_fd_reuse = true;
                continue;
            }
            if (!strcmp(argv[argument], "--slow-callback")) {
                demonstrate_slow_callback = true;
                continue;
            }
            if (iteration_limit) {
                fprintf(stderr,
                        "usage: %s [ITERATIONS] [--bad-et] "
                        "[--bad-oneshot] [--multi-waiter] "
                        "[--fd-reuse] [--slow-callback]\n",
                        argv[0]);
                return 2;
            }
            errno = 0;
            iteration_limit = strtoull(argv[argument], &end, 10);
            if (errno || !end || *end || !iteration_limit) {
                fprintf(stderr, "invalid argument: %s\n",
                        argv[argument]);
                return 2;
            }
        }
    }
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    printf("trace_epoll_test PID %d; setup starts in 2 seconds",
           getpid());
    if (iteration_limit)
        printf(" and stops after %llu iterations", iteration_limit);
    else
        printf(" and continues until Ctrl+C");
    if (demonstrate_bad_et)
        printf("; intentionally incomplete EPOLLET drain enabled");
    if (demonstrate_bad_oneshot)
        printf("; intentionally missing EPOLLONESHOT rearm enabled");
    if (demonstrate_multi_waiter)
        printf("; two waiters enabled");
    if (demonstrate_slow_callback)
        printf("; intentionally blocked callback enabled");
    putchar('\n');
    fflush(stdout);
    sleep(2);

    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &signal_mask, NULL)) {
        fprintf(stderr, "failed to block SIGUSR1\n");
        goto failure;
    }
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    timer_fd = timerfd_create(
        CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    signal_fd = signalfd(
        -1, &signal_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (epoll_fd < 0 || event_fd < 0 || timer_fd < 0 ||
        signal_fd < 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK |
                   SOCK_CLOEXEC, 0, sockets) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK |
                   SOCK_CLOEXEC, 0, oneshot_sockets) ||
        (demonstrate_bad_et &&
         socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK |
                    SOCK_CLOEXEC, 0, bad_sockets)) ||
        timerfd_settime(timer_fd, 0, &timer, NULL) ||
        add_to_epoll(epoll_fd, event_fd, EPOLLIN) ||
        add_to_epoll(epoll_fd, timer_fd, EPOLLIN) ||
        add_to_epoll(epoll_fd, signal_fd, EPOLLIN) ||
        add_to_epoll(
            epoll_fd, sockets[0],
            EPOLLIN | EPOLLRDHUP | EPOLLET) ||
        add_to_epoll(
            epoll_fd, oneshot_sockets[0],
            EPOLLIN | EPOLLRDHUP | EPOLLONESHOT) ||
        (demonstrate_bad_et &&
         add_to_epoll(
             epoll_fd, bad_sockets[0],
             EPOLLIN | EPOLLRDHUP | EPOLLET))) {
        fprintf(stderr, "epoll test setup failed: %s\n", strerror(errno));
        goto failure;
    }
    context = (struct test_context){
        .epoll_fd = epoll_fd,
        .event_fd = event_fd,
        .timer_fd = timer_fd,
        .signal_fd = signal_fd,
        .socket_fd = sockets[0],
        .bad_socket_fd = bad_sockets[0],
        .oneshot_fd = oneshot_sockets[0],
        .reused_fd = -1,
        .bad_oneshot = demonstrate_bad_oneshot,
        .slow_callback = demonstrate_slow_callback,
    };
    printf("epoll resources: epfd=%d eventfd=%d timerfd=%d "
           "signalfd=%d socket=%d oneshot=%d bad-et=%d reused=%d\n",
           epoll_fd, event_fd, timer_fd, signal_fd, sockets[0],
           oneshot_sockets[0], bad_sockets[0], context.reused_fd);
    fflush(stdout);
    if (demonstrate_multi_waiter) {
        if (pthread_create(
                &waiter_thread, NULL, second_waiter, &context)) {
            fprintf(stderr, "failed to create second waiter\n");
            goto failure;
        }
        waiter_started = true;
    }

    while (!stopping &&
           (!iteration_limit || iteration < iteration_limit)) {
        uint64_t one = 1;
        int ready;
        int index;

        /*
         * Recreate fault scenarios periodically so a tracer attached from a
         * second terminal does not have to win a one-time startup race.
         * Each cycle restores a clean edge/rearm/lifetime, then deliberately
         * leaves the resulting handler in the broken state.
         */
        if (iteration >= 20 && (iteration - 20) % 40 == 0) {
            if (demonstrate_fd_reuse) {
                if (reused_fd >= 0) {
                    close(reused_fd);
                    reused_fd = -1;
                    context.reused_fd = -1;
                }
                if (create_reused_registration(
                        &context, &reused_fd)) {
                    fprintf(stderr, "FD reuse setup failed: %s\n",
                            strerror(errno));
                    goto failure;
                }
            }
            if (demonstrate_bad_et) {
                consume_socket(bad_sockets[0]);
                if (write(bad_sockets[1], "xx", 2) < 0) {
                    fprintf(stderr, "bad ET trigger failed: %s\n",
                            strerror(errno));
                    goto failure;
                }
            }
            if (demonstrate_bad_oneshot) {
                if (modify_epoll(
                        epoll_fd, oneshot_sockets[0],
                        EPOLLIN | EPOLLRDHUP | EPOLLONESHOT)) {
                    fprintf(stderr,
                            "bad ONESHOT rearm setup failed: %s\n",
                            strerror(errno));
                    goto failure;
                }
                if (write(oneshot_sockets[1], "o", 1) < 0) {
                    fprintf(stderr,
                            "bad ONESHOT trigger failed: %s\n",
                            strerror(errno));
                    goto failure;
                }
            }
        }
        if (iteration % 5) {
            if (write(event_fd, &one, sizeof(one)) < 0 ||
                write(sockets[1], "x", 1) < 0) {
                fprintf(stderr, "event trigger failed: %s\n",
                        strerror(errno));
                goto failure;
            }
            if (!demonstrate_bad_oneshot &&
                write(oneshot_sockets[1], "o", 1) < 0 &&
                errno != EAGAIN) {
                fprintf(stderr, "ONESHOT trigger failed: %s\n",
                        strerror(errno));
                goto failure;
            }
            if (reused_fd >= 0 &&
                write(reused_fd, &one, sizeof(one)) < 0) {
                fprintf(stderr, "reused FD trigger failed: %s\n",
                        strerror(errno));
                goto failure;
            }
        }
        if (iteration % 7 == 1 && kill(getpid(), SIGUSR1)) {
            fprintf(stderr, "signal trigger failed: %s\n",
                    strerror(errno));
            goto failure;
        }
        ready = wait_for_events(epoll_fd, events, iteration);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "epoll_wait failed: %s\n", strerror(errno));
            goto failure;
        }
        for (index = 0; index < ready; index++) {
            int fd = (int)(uint32_t)events[index].data.u64;

            epoll_test_callback(fd, &context, &events[index]);
        }
        iteration++;
        usleep(50000);
    }

    stopping = 1;
    if (waiter_started)
        pthread_join(waiter_thread, NULL);
    printf("stopped after %llu iterations; bad-et ready=%llu; "
           "oneshot ready=%llu\n",
           iteration,
           __atomic_load_n(
               &context.bad_et_ready, __ATOMIC_RELAXED),
           __atomic_load_n(
               &context.oneshot_ready, __ATOMIC_RELAXED));
    close(oneshot_sockets[1]);
    close(oneshot_sockets[0]);
    if (reused_fd >= 0)
        close(reused_fd);
    if (bad_sockets[1] >= 0)
        close(bad_sockets[1]);
    if (bad_sockets[0] >= 0)
        close(bad_sockets[0]);
    close(sockets[1]);
    close(sockets[0]);
    close(timer_fd);
    close(signal_fd);
    close(event_fd);
    close(epoll_fd);
    return 0;

failure:
    stopping = 1;
    if (waiter_started)
        pthread_join(waiter_thread, NULL);
    if (oneshot_sockets[1] >= 0)
        close(oneshot_sockets[1]);
    if (oneshot_sockets[0] >= 0)
        close(oneshot_sockets[0]);
    if (reused_fd >= 0)
        close(reused_fd);
    if (bad_sockets[1] >= 0)
        close(bad_sockets[1]);
    if (bad_sockets[0] >= 0)
        close(bad_sockets[0]);
    if (sockets[1] >= 0)
        close(sockets[1]);
    if (sockets[0] >= 0)
        close(sockets[0]);
    if (timer_fd >= 0)
        close(timer_fd);
    if (signal_fd >= 0)
        close(signal_fd);
    if (event_fd >= 0)
        close(event_fd);
    if (epoll_fd >= 0)
        close(epoll_fd);
    return 1;
}
