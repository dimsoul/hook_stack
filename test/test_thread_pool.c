// SPDX-License-Identifier: MIT

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define POOL_WORKERS 2
#define QUEUE_CAPACITY 64

struct async_request {
    unsigned int sequence;
    char payload[64];
};

struct pool_task {
    void (*function)(void *);
    void *argument;
};

struct thread_pool {
    const char *name;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    struct pool_task queue[QUEUE_CAPACITY];
    pthread_t workers[POOL_WORKERS];
    size_t head;
    size_t tail;
    size_t count;
    bool stopping;
};

static struct thread_pool compute_pool;
static struct thread_pool storage_pool;
static volatile sig_atomic_t exiting;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

static int thread_pool_submit(struct thread_pool *pool,
                              void (*function)(void *), void *argument)
{
    pthread_mutex_lock(&pool->lock);
    while (pool->count == QUEUE_CAPACITY && !pool->stopping)
        pthread_cond_wait(&pool->not_full, &pool->lock);
    if (pool->stopping) {
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }

    pool->queue[pool->tail].function = function;
    pool->queue[pool->tail].argument = argument;
    pool->tail = (pool->tail + 1) % QUEUE_CAPACITY;
    pool->count++;
    pthread_cond_signal(&pool->not_empty);
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

static void *thread_pool_worker(void *argument)
{
    struct thread_pool *pool = argument;

    for (;;) {
        struct pool_task task;

        pthread_mutex_lock(&pool->lock);
        while (!pool->count && !pool->stopping)
            pthread_cond_wait(&pool->not_empty, &pool->lock);
        if (!pool->count && pool->stopping) {
            pthread_mutex_unlock(&pool->lock);
            return NULL;
        }

        task = pool->queue[pool->head];
        pool->head = (pool->head + 1) % QUEUE_CAPACITY;
        pool->count--;
        pthread_cond_signal(&pool->not_full);
        pthread_mutex_unlock(&pool->lock);
        task.function(task.argument);
    }
}

static int thread_pool_start(struct thread_pool *pool, const char *name)
{
    size_t index;
    int error;

    memset(pool, 0, sizeof(*pool));
    pool->name = name;
    if ((error = pthread_mutex_init(&pool->lock, NULL)))
        return error;
    if ((error = pthread_cond_init(&pool->not_empty, NULL)))
        return error;
    if ((error = pthread_cond_init(&pool->not_full, NULL)))
        return error;

    for (index = 0; index < POOL_WORKERS; index++) {
        error = pthread_create(&pool->workers[index], NULL,
                               thread_pool_worker, pool);
        if (error)
            return error;
    }
    return 0;
}

static void thread_pool_stop(struct thread_pool *pool)
{
    size_t index;

    pthread_mutex_lock(&pool->lock);
    pool->stopping = true;
    pthread_cond_broadcast(&pool->not_empty);
    pthread_cond_broadcast(&pool->not_full);
    pthread_mutex_unlock(&pool->lock);

    for (index = 0; index < POOL_WORKERS; index++)
        pthread_join(pool->workers[index], NULL);
    pthread_cond_destroy(&pool->not_full);
    pthread_cond_destroy(&pool->not_empty);
    pthread_mutex_destroy(&pool->lock);
}

__attribute__((noinline))
void write_result(struct async_request *request)
{
    /*
     * Simulate a blocking database or filesystem operation. callweave should
     * classify most of this interval as blocked rather than on-CPU.
     */
    usleep(80000);
    printf("completed request=%u payload=%s key=%p\n",
           request->sequence, request->payload, (void *)request);
    free(request);
}

static void run_storage(void *argument)
{
    write_result(argument);
}

__attribute__((noinline))
void submit_storage_task(struct thread_pool *pool,
                         struct async_request *request)
{
    printf("submit pool=%s request=%u key=%p\n",
           pool->name, request->sequence, (void *)request);
    if (thread_pool_submit(pool, run_storage, request)) {
        fprintf(stderr, "storage pool is stopping\n");
        free(request);
    }
}

__attribute__((noinline))
void process_request(struct async_request *request)
{
    /*
     * Simulate application work before the next asynchronous handoff.
     * The sleep gives the per-hop scheduler attribution a visible blocked
     * component.
     */
    usleep(40000);
    snprintf(request->payload, sizeof(request->payload),
             "processed-%u", request->sequence);
    submit_storage_task(&storage_pool, request);
}

static void run_compute(void *argument)
{
    process_request(argument);
}

__attribute__((noinline))
void submit_compute_task(struct thread_pool *pool,
                         struct async_request *request)
{
    printf("submit pool=%s request=%u key=%p\n",
           pool->name, request->sequence, (void *)request);
    if (thread_pool_submit(pool, run_compute, request)) {
        fprintf(stderr, "compute pool is stopping\n");
        free(request);
    }
}

int main(void)
{
    struct sigaction action = {
        .sa_handler = handle_signal,
    };
    unsigned int sequence = 1;
    int error;

    setvbuf(stdout, NULL, _IOLBF, 0);
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    error = thread_pool_start(&compute_pool, "compute");
    if (error) {
        fprintf(stderr, "cannot start compute pool: %s\n", strerror(error));
        return 1;
    }
    error = thread_pool_start(&storage_pool, "storage");
    if (error) {
        fprintf(stderr, "cannot start storage pool: %s\n", strerror(error));
        thread_pool_stop(&compute_pool);
        return 1;
    }

    printf("trace_thread_pool_test PID=%ld\n", (long)getpid());
    printf("trace with: sudo ./callweave -p %ld "
           "--async-hop submit_compute_task,2,process_request,1 "
           "--async-hop submit_storage_task,2,write_result,1 "
           "write_result\n", (long)getpid());

    while (!exiting) {
        struct async_request *request = calloc(1, sizeof(*request));

        if (!request) {
            fprintf(stderr, "calloc: %s\n", strerror(errno));
            break;
        }
        request->sequence = sequence++;
        submit_compute_task(&compute_pool, request);
        usleep(15000);
    }

    thread_pool_stop(&compute_pool);
    thread_pool_stop(&storage_pool);
    return 0;
}
