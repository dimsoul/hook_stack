// SPDX-License-Identifier: MIT

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t contested_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool holder_ready;
static volatile sig_atomic_t exiting;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

__attribute__((noinline))
static void release_shared_resource(void)
{
    pthread_mutex_unlock(&contested_mutex);
}

__attribute__((noinline))
static void *lock_holder_main(void *argument)
{
    (void)argument;
    pthread_mutex_lock(&contested_mutex);
    atomic_store_explicit(&holder_ready, true, memory_order_release);
    usleep(250000);
    release_shared_resource();
    return NULL;
}

__attribute__((noinline))
static void consume_shared_resource(void)
{
    usleep(10000);
}

__attribute__((noinline))
void function_to_trace(void)
{
    pthread_mutex_lock(&contested_mutex);
    consume_shared_resource();
    pthread_mutex_unlock(&contested_mutex);
}

int main(void)
{
    struct sigaction action = {
        .sa_handler = handle_signal,
    };

    setvbuf(stdout, NULL, _IOLBF, 0);
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    printf("trace_lock_test PID=%ld\n", (long)getpid());
    printf("trace with: sudo ./callweave -p %ld --time --attribution "
           "function_to_trace\n", (long)getpid());

    while (!exiting) {
        pthread_t holder;
        int error;

        atomic_store_explicit(&holder_ready, false, memory_order_relaxed);
        error = pthread_create(&holder, NULL, lock_holder_main, NULL);
        if (error) {
            fprintf(stderr, "pthread_create: %s\n", strerror(error));
            return 1;
        }
        while (!atomic_load_explicit(&holder_ready, memory_order_acquire))
            usleep(1000);
        function_to_trace();
        pthread_join(holder, NULL);
        usleep(200000);
    }
    return 0;
}
