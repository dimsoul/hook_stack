// SPDX-License-Identifier: MIT

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct async_task {
    unsigned int sequence;
};

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_ready = PTHREAD_COND_INITIALIZER;
static struct async_task *pending_task;

__attribute__((noinline)) long function_to_trace(struct async_task *task)
{
    struct stat file_status;

    /*
     * Give --attribution a stable blocking interval to observe. A timer
     * wakeup should appear mostly as blocked time, followed by a usually
     * small run-queue delay.
     */
    usleep(20000);

    if (stat(".", &file_status) == 0) {
        printf("task %u: stat succeeded; inode: %llu\n", task->sequence,
               (unsigned long long)file_status.st_ino);
        return (long)file_status.st_ino;
    }

    perror("stat failed");
    return -1;
}

__attribute__((noinline)) void submit_async_task(struct async_task *task)
{
    pthread_mutex_lock(&queue_lock);
    while (pending_task)
        pthread_cond_wait(&queue_ready, &queue_lock);
    pending_task = task;
    pthread_cond_broadcast(&queue_ready);
    pthread_mutex_unlock(&queue_lock);
}

static void *worker_main(void *unused)
{
    (void)unused;

    for (;;) {
        struct async_task *task;
        volatile long result;

        pthread_mutex_lock(&queue_lock);
        while (!pending_task)
            pthread_cond_wait(&queue_ready, &queue_lock);
        task = pending_task;
        pending_task = NULL;
        pthread_cond_broadcast(&queue_ready);
        pthread_mutex_unlock(&queue_lock);

        result = function_to_trace(task);
        (void)result;
        free(task);
    }

    return NULL;
}

int main(void)
{
    pthread_t worker;
    unsigned int sequence = 1;
    int error;

    error = pthread_create(&worker, NULL, worker_main, NULL);
    if (error) {
        fprintf(stderr, "pthread_create: %s\n", strerror(error));
        return 1;
    }

    for (;;) {
        struct async_task *task = malloc(sizeof(*task));

        if (!task) {
            perror("malloc");
            return 1;
        }
        task->sequence = sequence++;
        submit_async_task(task);
        sleep(1);
    }
}
