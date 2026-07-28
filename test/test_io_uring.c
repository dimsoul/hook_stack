// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct test_ring {
    int fd;
    void *sq_ring;
    size_t sq_ring_size;
    void *cq_ring;
    size_t cq_ring_size;
    struct io_uring_sqe *sqes;
    size_t sqes_size;
    unsigned *sq_head;
    unsigned *sq_tail;
    unsigned *sq_mask;
    unsigned *sq_array;
    unsigned *cq_head;
    unsigned *cq_tail;
    unsigned *cq_mask;
    struct io_uring_cqe *cqes;
};

static volatile sig_atomic_t stopping;

__attribute__((noinline))
void process_io_completion(uint64_t user_data)
{
    __asm__ volatile("" : : "r"(user_data) : "memory");
}

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static void destroy_ring(struct test_ring *ring)
{
    if (ring->sqes && ring->sqes != MAP_FAILED)
        munmap(ring->sqes, ring->sqes_size);
    if (ring->cq_ring && ring->cq_ring != MAP_FAILED &&
        ring->cq_ring != ring->sq_ring)
        munmap(ring->cq_ring, ring->cq_ring_size);
    if (ring->sq_ring && ring->sq_ring != MAP_FAILED)
        munmap(ring->sq_ring, ring->sq_ring_size);
    if (ring->fd >= 0)
        close(ring->fd);
}

static int create_ring(struct test_ring *ring, unsigned entries)
{
    struct io_uring_params parameters = {0};

    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
    ring->fd = syscall(__NR_io_uring_setup, entries, &parameters);
    if (ring->fd < 0)
        return -1;

    ring->sq_ring_size = parameters.sq_off.array +
                         parameters.sq_entries * sizeof(unsigned);
    ring->cq_ring_size = parameters.cq_off.cqes +
                         parameters.cq_entries *
                             sizeof(struct io_uring_cqe);
    if (parameters.features & IORING_FEAT_SINGLE_MMAP) {
        if (ring->cq_ring_size > ring->sq_ring_size)
            ring->sq_ring_size = ring->cq_ring_size;
        ring->cq_ring_size = ring->sq_ring_size;
    }

    ring->sq_ring = mmap(NULL, ring->sq_ring_size,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_POPULATE,
                         ring->fd, IORING_OFF_SQ_RING);
    if (ring->sq_ring == MAP_FAILED)
        goto error;
    if (parameters.features & IORING_FEAT_SINGLE_MMAP) {
        ring->cq_ring = ring->sq_ring;
    } else {
        ring->cq_ring = mmap(NULL, ring->cq_ring_size,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE,
                             ring->fd, IORING_OFF_CQ_RING);
        if (ring->cq_ring == MAP_FAILED)
            goto error;
    }

    ring->sqes_size =
        parameters.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = mmap(NULL, ring->sqes_size,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE,
                      ring->fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED)
        goto error;

    ring->sq_head = ring->sq_ring + parameters.sq_off.head;
    ring->sq_tail = ring->sq_ring + parameters.sq_off.tail;
    ring->sq_mask = ring->sq_ring + parameters.sq_off.ring_mask;
    ring->sq_array = ring->sq_ring + parameters.sq_off.array;
    ring->cq_head = ring->cq_ring + parameters.cq_off.head;
    ring->cq_tail = ring->cq_ring + parameters.cq_off.tail;
    ring->cq_mask = ring->cq_ring + parameters.cq_off.ring_mask;
    ring->cqes = ring->cq_ring + parameters.cq_off.cqes;
    return 0;

error:
    destroy_ring(ring);
    return -1;
}

static const char *operation_name(uint8_t opcode)
{
    switch (opcode) {
    case IORING_OP_NOP:
        return "NOP";
    case IORING_OP_READ:
        return "READ";
    case IORING_OP_WRITE:
        return "WRITE";
    case IORING_OP_TIMEOUT:
        return "TIMEOUT";
    default:
        return "UNKNOWN";
    }
}

static int submit_demo_batch(struct test_ring *ring, int file_fd,
                             uint64_t first_request, unsigned count)
{
    struct __kernel_timespec timeouts[4] = {0};
    char write_buffers[4][64] = {{0}};
    char read_buffers[4][64] = {{0}};
    uint8_t opcodes[4] = {0};
    bool invalid_fd[4] = {0};
    uint64_t user_data[4] = {0};
    unsigned tail =
        __atomic_load_n(ring->sq_tail, __ATOMIC_RELAXED);
    unsigned request;
    unsigned completed = 0;

    for (request = 0; request < count; request++) {
        uint64_t sequence = first_request + request;
        unsigned sqe_index = (tail + request) & *ring->sq_mask;
        struct io_uring_sqe *sqe = &ring->sqes[sqe_index];
        uint8_t opcode;

        if (request < 2) {
            opcode = IORING_OP_NOP;
        } else if (request + 1 == count &&
                   ((first_request / 4) & 1)) {
            opcode = 0xff;
        } else {
            switch (sequence % 5) {
        case 0:
            opcode = IORING_OP_NOP;
            break;
        case 1:
            opcode = IORING_OP_WRITE;
            break;
        case 2:
            opcode = IORING_OP_READ;
            break;
        case 3:
            opcode = IORING_OP_TIMEOUT;
            break;
        case 4:
            opcode = IORING_OP_READ;
            invalid_fd[request] = true;
            break;
        default:
            opcode = IORING_OP_NOP;
            break;
            }
        }
        opcodes[request] = opcode;
        user_data[request] = 0xc0110000ULL + sequence;
        memset(sqe, 0, sizeof(*sqe));
        sqe->opcode = opcode;
        sqe->user_data = user_data[request];
        switch (opcode) {
        case IORING_OP_WRITE:
            snprintf(write_buffers[request],
                     sizeof(write_buffers[request]),
                     "callweave request %llu\n",
                     (unsigned long long)sequence);
            sqe->fd = file_fd;
            sqe->addr = (uint64_t)(uintptr_t)write_buffers[request];
            sqe->len = strlen(write_buffers[request]);
            sqe->off = 128 + sequence * 64;
            break;
        case IORING_OP_READ:
            sqe->fd = invalid_fd[request] ? -1 : file_fd;
            sqe->addr = (uint64_t)(uintptr_t)read_buffers[request];
            sqe->len = sizeof(read_buffers[request]);
            sqe->off = 0;
            break;
        case IORING_OP_TIMEOUT:
            timeouts[request].tv_nsec = 20000000;
            sqe->fd = -1;
            sqe->addr = (uint64_t)(uintptr_t)&timeouts[request];
            sqe->len = 1;
            break;
        default:
            break;
        }
        if (!request && request + 1 < count)
            sqe->flags |= IOSQE_IO_LINK;
        ring->sq_array[sqe_index] = sqe_index;
    }
    __atomic_store_n(ring->sq_tail, tail + count, __ATOMIC_RELEASE);

    if (syscall(__NR_io_uring_enter, ring->fd, count, count,
                IORING_ENTER_GETEVENTS, NULL, 0) < 0)
        return -1;

    while (completed < count) {
        unsigned cq_head =
            __atomic_load_n(ring->cq_head, __ATOMIC_RELAXED);
        unsigned cq_tail =
            __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);

        while (cq_head != cq_tail && completed < count) {
            struct io_uring_cqe *cqe =
                &ring->cqes[cq_head & *ring->cq_mask];
            const char *name = "UNKNOWN";
            unsigned submitted;

            for (submitted = 0; submitted < count; submitted++) {
                if (user_data[submitted] == cqe->user_data) {
                    name = invalid_fd[submitted] ?
                        "READ_BAD_FD" :
                        operation_name(opcodes[submitted]);
                    break;
                }
            }
            printf("completed %-7s user_data=0x%llx "
                   "result=%d flags=0x%x\n",
                   name, (unsigned long long)cqe->user_data,
                   cqe->res, cqe->flags);
            process_io_completion(cqe->user_data);
            cq_head++;
            completed++;
        }
        __atomic_store_n(ring->cq_head, cq_head, __ATOMIC_RELEASE);
        if (completed < count &&
            syscall(__NR_io_uring_enter, ring->fd, 0,
                    count - completed, IORING_ENTER_GETEVENTS,
                    NULL, 0) < 0)
            return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct test_ring ring;
    unsigned long long request_count = 0;
    unsigned long long index;
    char temporary_path[] = "/tmp/callweave-io-uring-XXXXXX";
    char *end = NULL;
    int file_fd = -1;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [REQUEST_COUNT]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        errno = 0;
        request_count = strtoull(argv[1], &end, 10);
        if (errno || !end || *end || !request_count) {
            fprintf(stderr, "invalid request count: %s\n", argv[1]);
            return 2;
        }
    }
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("trace_io_uring_test PID %d; requests start in 2 seconds",
           getpid());
    if (request_count)
        printf(" and stop after %llu requests", request_count);
    else
        printf(" and continue until Ctrl+C");
    putchar('\n');
    fflush(stdout);
    sleep(2);

    if (create_ring(&ring, 8)) {
        fprintf(stderr, "io_uring_setup failed: %s\n", strerror(errno));
        return 1;
    }
    file_fd = mkstemp(temporary_path);
    if (file_fd < 0 || unlink(temporary_path) ||
        pwrite(file_fd, "callweave io_uring read source\n", 31, 0) < 0) {
        fprintf(stderr, "cannot prepare temporary test file: %s\n",
                strerror(errno));
        if (file_fd >= 0)
            close(file_fd);
        destroy_ring(&ring);
        return 1;
    }
    for (index = 0; !stopping &&
         (!request_count || index < request_count);) {
        unsigned batch_count = 4;

        if (request_count && request_count - index < batch_count)
            batch_count = request_count - index;
        if (submit_demo_batch(&ring, file_fd, index, batch_count)) {
            fprintf(stderr, "io_uring batch at request %llu failed: %s\n",
                    index, strerror(errno));
            close(file_fd);
            destroy_ring(&ring);
            return 1;
        }
        index += batch_count;
        usleep(200000);
    }
    close(file_fd);
    destroy_ring(&ring);
    printf("stopped after %llu requests\n", index);
    return 0;
}
