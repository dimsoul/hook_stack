// SPDX-License-Identifier: MIT

#include <uv.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_DNS_JOBS 4U
#define DEFAULT_SERIAL_JOBS 6U
#define DEFAULT_DNS_DELAY_MS 5000U
#define DEFAULT_STARTUP_DELAY_MS 3000U
#define MAX_JOBS 64U
#define MAX_DELAY_MS 60000U

enum task_kind {
    TASK_DNS,
    TASK_SERIAL,
};

struct task {
    uv_work_t request;
    enum task_kind kind;
    unsigned int id;
    unsigned int delay_ms;
    int output_fd;
    uint64_t submitted_ms;
    uint64_t work_started_ms;
    uint64_t work_finished_ms;
};

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static void sleep_ms(unsigned int delay_ms)
{
    struct timespec request = {
        .tv_sec = delay_ms / 1000U,
        .tv_nsec = (long)(delay_ms % 1000U) * 1000000L,
    };

    while (nanosleep(&request, &request) != 0) {
        if (errno != EINTR) {
            perror("nanosleep");
            exit(EXIT_FAILURE);
        }
    }
}

__attribute__((noinline)) void dns_lookup_work(uv_work_t *request)
{
    struct task *task = request->data;

    task->work_started_ms = monotonic_ms();
    sleep_ms(task->delay_ms);
    task->work_finished_ms = monotonic_ms();
}

__attribute__((noinline)) void serial_write_work(uv_work_t *request)
{
    struct task *task = request->data;
    const char byte = 'x';
    ssize_t written;

    task->work_started_ms = monotonic_ms();
    do {
        written = write(task->output_fd, &byte, sizeof(byte));
    } while (written < 0 && errno == EINTR);
    task->work_finished_ms = monotonic_ms();

    if (written != (ssize_t)sizeof(byte))
        fprintf(stderr, "serial-like write %u failed: %s\n",
                task->id, strerror(errno));
}

static void after_work(uv_work_t *request, int status)
{
    struct task *task = request->data;
    const char *kind = task->kind == TASK_DNS ? "dns" : "serial";

    printf("%-6s %u: queue=%llu ms work=%llu ms status=%d\n",
           kind,
           task->id,
           (unsigned long long)(task->work_started_ms - task->submitted_ms),
           (unsigned long long)(task->work_finished_ms - task->work_started_ms),
           status);
}

__attribute__((noinline)) int submit_dns(struct task *task, uv_loop_t *loop)
{
    task->submitted_ms = monotonic_ms();
    return uv_queue_work(loop, &task->request, dns_lookup_work, after_work);
}

__attribute__((noinline)) int submit_serial(struct task *task, uv_loop_t *loop)
{
    task->submitted_ms = monotonic_ms();
    return uv_queue_work(loop, &task->request, serial_write_work, after_work);
}

static unsigned int parse_uint(const char *option, const char *value,
                               unsigned int minimum, unsigned int maximum)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed < minimum || parsed > maximum) {
        fprintf(stderr, "%s must be between %u and %u\n",
                option, minimum, maximum);
        exit(EXIT_FAILURE);
    }

    return (unsigned int)parsed;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--dns-jobs N] [--serial-jobs N] "
            "[--dns-delay-ms N] [--startup-delay-ms N]\n",
            program);
}

int main(int argc, char **argv)
{
    unsigned int dns_jobs = DEFAULT_DNS_JOBS;
    unsigned int serial_jobs = DEFAULT_SERIAL_JOBS;
    unsigned int dns_delay_ms = DEFAULT_DNS_DELAY_MS;
    unsigned int startup_delay_ms = DEFAULT_STARTUP_DELAY_MS;
    struct task *dns_tasks;
    struct task *serial_tasks;
    uv_loop_t *loop = uv_default_loop();
    int output_fd;
    unsigned int i;

    for (i = 1; i < (unsigned int)argc; i++) {
        const char *option = argv[i];
        const char *value;

        if (i + 1 >= (unsigned int)argc) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        value = argv[++i];
        if (strcmp(option, "--dns-jobs") == 0)
            dns_jobs = parse_uint(option, value, 1U, MAX_JOBS);
        else if (strcmp(option, "--serial-jobs") == 0)
            serial_jobs = parse_uint(option, value, 1U, MAX_JOBS);
        else if (strcmp(option, "--dns-delay-ms") == 0)
            dns_delay_ms = parse_uint(option, value, 1U, MAX_DELAY_MS);
        else if (strcmp(option, "--startup-delay-ms") == 0)
            startup_delay_ms = parse_uint(option, value, 0U, MAX_DELAY_MS);
        else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    dns_tasks = calloc(dns_jobs, sizeof(*dns_tasks));
    serial_tasks = calloc(serial_jobs, sizeof(*serial_tasks));
    if (dns_tasks == NULL || serial_tasks == NULL) {
        perror("calloc");
        free(dns_tasks);
        free(serial_tasks);
        return EXIT_FAILURE;
    }

    output_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (output_fd < 0) {
        perror("open /dev/null");
        free(dns_tasks);
        free(serial_tasks);
        return EXIT_FAILURE;
    }

    printf("PID %ld; attach Callweave now (startup delay %u ms)\n",
           (long)getpid(), startup_delay_ms);
    fflush(stdout);
    sleep_ms(startup_delay_ms);

    for (i = 0; i < dns_jobs; i++) {
        dns_tasks[i].request.data = &dns_tasks[i];
        dns_tasks[i].kind = TASK_DNS;
        dns_tasks[i].id = i;
        dns_tasks[i].delay_ms = dns_delay_ms;
        if (submit_dns(&dns_tasks[i], loop) != 0) {
            fprintf(stderr, "failed to queue DNS task %u\n", i);
            return EXIT_FAILURE;
        }
    }

    /* Let the default four-worker pool enter every blocking DNS task first. */
    sleep_ms(100U);

    for (i = 0; i < serial_jobs; i++) {
        serial_tasks[i].request.data = &serial_tasks[i];
        serial_tasks[i].kind = TASK_SERIAL;
        serial_tasks[i].id = i;
        serial_tasks[i].output_fd = output_fd;
        if (submit_serial(&serial_tasks[i], loop) != 0) {
            fprintf(stderr, "failed to queue serial task %u\n", i);
            return EXIT_FAILURE;
        }
    }

    if (uv_run(loop, UV_RUN_DEFAULT) != 0) {
        fprintf(stderr, "uv_run returned while work remained active\n");
        return EXIT_FAILURE;
    }

    close(output_fd);
    free(dns_tasks);
    free(serial_tasks);
    return EXIT_SUCCESS;
}
