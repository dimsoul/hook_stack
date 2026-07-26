// SPDX-License-Identifier: MIT

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUEUE_CAPACITY 16

struct complex_request;

struct stage_token {
    struct complex_request *request;
    uint64_t marker;
};

struct complex_request {
    uint64_t id;
    char payload[96];
    uint64_t checksum;
    struct stage_token enrich_token;
    struct stage_token persist_token;
};

enum stage_kind {
    STAGE_DECODE,
    STAGE_ENRICH,
    STAGE_PERSIST,
};

struct stage_queue {
    const char *name;
    enum stage_kind stage;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    void *items[QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    bool stopping;
    pthread_t worker;
};

static struct stage_queue decode_queue;
static struct stage_queue enrich_queue;
static struct stage_queue persist_queue;
static volatile sig_atomic_t exiting;

__attribute__((noinline))
void decode_request(const char *stage_name, struct complex_request *request,
                    unsigned int flags);

__attribute__((noinline))
void enrich_request(unsigned int shard, const char *stage_name,
                    struct stage_token *token, uint64_t deadline_ns);

__attribute__((noinline))
void persist_result(const char *backend, unsigned int flags,
                    uint64_t attempt, int status, const char *region,
                    uint64_t epoch, void *observer,
                    struct stage_token *token);

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

static int queue_push(struct stage_queue *queue, void *item)
{
    pthread_mutex_lock(&queue->lock);
    while (queue->count == QUEUE_CAPACITY && !queue->stopping)
        pthread_cond_wait(&queue->not_full, &queue->lock);
    if (queue->stopping) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }
    queue->items[queue->tail] = item;
    queue->tail = (queue->tail + 1) % QUEUE_CAPACITY;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
    return 0;
}

static void *queue_pop(struct stage_queue *queue)
{
    void *item;

    pthread_mutex_lock(&queue->lock);
    while (!queue->count && !queue->stopping)
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    if (!queue->count && queue->stopping) {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }
    item = queue->items[queue->head];
    queue->head = (queue->head + 1) % QUEUE_CAPACITY;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return item;
}

static uint64_t mix_checksum(uint64_t value)
{
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

__attribute__((noinline))
static void validate_envelope(struct complex_request *request)
{
    request->checksum = mix_checksum(request->id);
    usleep(4000);
}

__attribute__((noinline))
static void normalize_payload(struct complex_request *request)
{
    snprintf(request->payload, sizeof(request->payload),
             "normalized-request-%llu",
             (unsigned long long)request->id);
    usleep(6000);
}

__attribute__((noinline))
static void parse_request_layers(struct complex_request *request)
{
    validate_envelope(request);
    normalize_payload(request);
}

/*
 * Hop 1 source key is arg1. It deliberately differs from hop 0's request
 * pointer: the next queue carries a token embedded in the request.
 */
__attribute__((noinline))
void submit_enrich_task(struct stage_token *token,
                        struct stage_queue *queue,
                        unsigned int priority)
{
    printf("handoff decode->enrich request=%llu priority=%u key=%p\n",
           (unsigned long long)token->request->id, priority, (void *)token);
    if (queue_push(queue, token))
        fprintf(stderr, "cannot submit enrichment task\n");
}

__attribute__((noinline))
static void build_enrichment_plan(struct complex_request *request)
{
    request->enrich_token.request = request;
    request->enrich_token.marker = 0xe1000000ULL | request->id;
    submit_enrich_task(&request->enrich_token, &enrich_queue, 7);
}

/*
 * Hop 0 target key is arg2. Auto target-argument discovery must skip
 * stage_name in arg1 and flags in arg3.
 */
__attribute__((noinline))
void decode_request(const char *stage_name, struct complex_request *request,
                    unsigned int flags)
{
    printf("decode stage=%s request=%llu flags=%u key=%p\n",
           stage_name, (unsigned long long)request->id,
           flags, (void *)request);
    parse_request_layers(request);
    build_enrichment_plan(request);
}

__attribute__((noinline))
static void lookup_customer_profile(struct complex_request *request,
                                    unsigned int shard)
{
    request->checksum ^= mix_checksum(request->id + shard);
    usleep(7000);
}

__attribute__((noinline))
static void apply_business_rules(struct complex_request *request)
{
    request->checksum ^= mix_checksum(request->checksum);
    usleep(8000);
}

/*
 * Hop 2 source key is arg2, with unrelated scalar and pointer arguments on
 * both sides of it.
 */
__attribute__((noinline))
void submit_persist_task(int priority, struct stage_token *token,
                         struct stage_queue *queue, const char *reason)
{
    printf("handoff enrich->persist request=%llu priority=%d reason=%s key=%p\n",
           (unsigned long long)token->request->id, priority,
           reason, (void *)token);
    if (queue_push(queue, token))
        fprintf(stderr, "cannot submit persistence task\n");
}

__attribute__((noinline))
static void prepare_persistence(struct complex_request *request)
{
    request->persist_token.request = request;
    request->persist_token.marker = 0xf2000000ULL | request->id;
    submit_persist_task(3, &request->persist_token, &persist_queue,
                        "enrichment-complete");
}

/*
 * Hop 1 target key is arg3. This stage performs several nested calls before
 * handing a different token to the persistence thread.
 */
__attribute__((noinline))
void enrich_request(unsigned int shard, const char *stage_name,
                    struct stage_token *token, uint64_t deadline_ns)
{
    struct complex_request *request = token->request;

    printf("enrich stage=%s request=%llu shard=%u deadline=%llu key=%p\n",
           stage_name, (unsigned long long)request->id, shard,
           (unsigned long long)deadline_ns, (void *)token);
    lookup_customer_profile(request, shard);
    apply_business_rules(request);
    prepare_persistence(request);
}

__attribute__((noinline))
static void encode_storage_record(struct complex_request *request)
{
    request->checksum ^= mix_checksum(request->id << 1);
    usleep(9000);
}

__attribute__((noinline))
static void flush_storage_record(struct complex_request *request)
{
    usleep(11000);
    printf("completed request=%llu payload=%s checksum=0x%llx\n",
           (unsigned long long)request->id, request->payload,
           (unsigned long long)request->checksum);
}

/*
 * Hop 2 target key is arg8. On x86-64 this forces auto discovery to read the
 * second stack-passed integer/pointer argument after checking six registers.
 */
__attribute__((noinline))
void persist_result(const char *backend, unsigned int flags,
                    uint64_t attempt, int status, const char *region,
                    uint64_t epoch, void *observer,
                    struct stage_token *token)
{
    struct complex_request *request = token->request;

    printf("persist backend=%s request=%llu flags=%u attempt=%llu "
           "status=%d region=%s epoch=%llu observer=%p key=%p\n",
           backend, (unsigned long long)request->id, flags,
           (unsigned long long)attempt, status, region,
           (unsigned long long)epoch, observer, (void *)token);
    encode_storage_record(request);
    flush_storage_record(request);
    free(request);
}

/*
 * Hop 0 source key is arg2.
 */
__attribute__((noinline))
void submit_decode_task(struct stage_queue *queue,
                        struct complex_request *request)
{
    printf("handoff producer->decode request=%llu key=%p\n",
           (unsigned long long)request->id, (void *)request);
    if (queue_push(queue, request)) {
        fprintf(stderr, "cannot submit decode task\n");
        free(request);
    }
}

static void *stage_worker(void *argument)
{
    struct stage_queue *queue = argument;

    for (;;) {
        void *item = queue_pop(queue);

        if (!item)
            return NULL;
        switch (queue->stage) {
        case STAGE_DECODE:
            decode_request("decode-worker", item, 0x21);
            break;
        case STAGE_ENRICH:
            enrich_request(4, "enrich-worker", item,
                           5000000000ULL);
            break;
        case STAGE_PERSIST:
            persist_result("local-store", 0x42, 1, 0, "primary",
                           1700000000ULL, queue, item);
            break;
        }
    }
}

static int stage_queue_start(struct stage_queue *queue, const char *name,
                             enum stage_kind stage)
{
    int error;

    memset(queue, 0, sizeof(*queue));
    queue->name = name;
    queue->stage = stage;
    if ((error = pthread_mutex_init(&queue->lock, NULL)) ||
        (error = pthread_cond_init(&queue->not_empty, NULL)) ||
        (error = pthread_cond_init(&queue->not_full, NULL)))
        return error;
    return pthread_create(&queue->worker, NULL, stage_worker, queue);
}

static void stage_queue_stop(struct stage_queue *queue)
{
    pthread_mutex_lock(&queue->lock);
    queue->stopping = true;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    pthread_join(queue->worker, NULL);
    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->lock);
}

int main(void)
{
    struct sigaction action = {
        .sa_handler = handle_signal,
    };
    uint64_t next_id = 1;
    int error;

    setvbuf(stdout, NULL, _IOLBF, 0);
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    if ((error = stage_queue_start(&decode_queue, "decode",
                                   STAGE_DECODE)) ||
        (error = stage_queue_start(&enrich_queue, "enrich",
                                   STAGE_ENRICH)) ||
        (error = stage_queue_start(&persist_queue, "persist",
                                   STAGE_PERSIST))) {
        fprintf(stderr, "cannot start stage worker: %s\n", strerror(error));
        return 1;
    }

    printf("trace_complex_async_test PID=%ld\n", (long)getpid());
    printf("trace with: sudo ./callweave -p %ld "
           "--async-hop submit_decode_task,2,decode_request "
           "--async-hop submit_enrich_task,1,enrich_request "
           "--async-hop submit_persist_task,2,persist_result "
           "persist_result\n",
           (long)getpid());

    while (!exiting) {
        struct complex_request *request = calloc(1, sizeof(*request));

        if (!request) {
            fprintf(stderr, "calloc: %s\n", strerror(errno));
            break;
        }
        request->id = next_id++;
        submit_decode_task(&decode_queue, request);
        usleep(250000);
    }

    stage_queue_stop(&decode_queue);
    stage_queue_stop(&enrich_queue);
    stage_queue_stop(&persist_queue);
    return 0;
}
