// SPDX-License-Identifier: MIT

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct async_request {
    unsigned int id;
    char payload[64];
};

static pthread_mutex_t request_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t request_changed = PTHREAD_COND_INITIALIZER;
static struct async_request *pending_request;
static pthread_mutex_t storage_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t storage_changed = PTHREAD_COND_INITIALIZER;
static struct async_request *pending_storage;

/*
 * Async source probe.
 *
 * The correlation key is deliberately the second argument so the test also
 * verifies --async-source-arg 2.
 */
__attribute__((noinline))
void enqueue_request(const char *queue_name, struct async_request *request)
{
    pthread_mutex_lock(&request_lock);
    while (pending_request)
        pthread_cond_wait(&request_changed, &request_lock);

    printf("enqueue queue=%s request=%u key=%p\n",
           queue_name, request->id, (void *)request);
    pending_request = request;
    pthread_cond_broadcast(&request_changed);
    pthread_mutex_unlock(&request_lock);
}

__attribute__((noinline))
static void dispatch_request(struct async_request *request)
{
    enqueue_request("worker-queue", request);
}

__attribute__((noinline))
static void http_handler(struct async_request *request)
{
    dispatch_request(request);
}

__attribute__((noinline))
void enqueue_storage_task(const char *queue_name,
                          struct async_request *request)
{
    pthread_mutex_lock(&storage_lock);
    while (pending_storage)
        pthread_cond_wait(&storage_changed, &storage_lock);

    printf("enqueue queue=%s request=%u key=%p\n",
           queue_name, request->id, (void *)request);
    pending_storage = request;
    pthread_cond_broadcast(&storage_changed);
    pthread_mutex_unlock(&storage_lock);
}

/*
 * First async target. It submits the same request to a second queue before
 * returning, so the second source probe can inherit the active lineage.
 */
__attribute__((noinline))
void process_request(struct async_request *request)
{
    usleep(10000);
    printf("process request=%u payload=%s key=%p\n",
           request->id, request->payload, (void *)request);
    enqueue_storage_task("storage-queue", request);
}

__attribute__((noinline))
static void run_request(struct async_request *request)
{
    process_request(request);
}

static void *request_worker_main(void *unused)
{
    (void)unused;

    for (;;) {
        struct async_request *request;

        pthread_mutex_lock(&request_lock);
        while (!pending_request)
            pthread_cond_wait(&request_changed, &request_lock);
        request = pending_request;
        pending_request = NULL;
        pthread_cond_broadcast(&request_changed);
        pthread_mutex_unlock(&request_lock);

        run_request(request);
    }

    return NULL;
}

__attribute__((noinline))
void write_result(struct async_request *request)
{
    usleep(20000);
    printf("write result request=%u key=%p\n",
           request->id, (void *)request);
}

__attribute__((noinline))
static void run_storage(struct async_request *request)
{
    write_result(request);
}

static void *storage_worker_main(void *unused)
{
    (void)unused;

    for (;;) {
        struct async_request *request;

        pthread_mutex_lock(&storage_lock);
        while (!pending_storage)
            pthread_cond_wait(&storage_changed, &storage_lock);
        request = pending_storage;
        pending_storage = NULL;
        pthread_cond_broadcast(&storage_changed);
        pthread_mutex_unlock(&storage_lock);

        run_storage(request);
        free(request);
    }

    return NULL;
}

int main(void)
{
    pthread_t request_worker;
    pthread_t storage_worker;
    unsigned int request_id = 1;
    int error;

    setvbuf(stdout, NULL, _IOLBF, 0);
    error = pthread_create(&request_worker, NULL, request_worker_main, NULL);
    if (error) {
        fprintf(stderr, "pthread_create request worker: %s\n",
                strerror(error));
        return 1;
    }
    error = pthread_create(&storage_worker, NULL,
                           storage_worker_main, NULL);
    if (error) {
        fprintf(stderr, "pthread_create storage worker: %s\n",
                strerror(error));
        return 1;
    }

    printf("trace_async_test PID=%ld\n", (long)getpid());
    printf("trace with: sudo ./hook_stack -p %ld "
           "--async-hop enqueue_request,2,process_request,1 "
           "--async-hop enqueue_storage_task,2,write_result,1 "
           "write_result\n",
           (long)getpid());

    for (;;) {
        struct async_request *request = calloc(1, sizeof(*request));

        if (!request) {
            perror("calloc");
            return 1;
        }
        request->id = request_id++;
        snprintf(request->payload, sizeof(request->payload),
                 "payload-%u", request->id);
        http_handler(request);
        sleep(1);
    }
}
