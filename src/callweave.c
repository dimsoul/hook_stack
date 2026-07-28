// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <libelf.h>
#include <gelf.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/types.h>
#include <linux/io_uring.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "callweave.skel.h"
#include "report.h"

#define MAX_STACK_DEPTH 128
#define MAX_ASYNC_STACK_DEPTH 127
#define MAX_ASYNC_HOPS 8
#define ASYNC_HOP_ID_MASK 0xffffU
#define ASYNC_TARGET_ARG_SHIFT 16

enum event_type {
    EVENT_ENTRY,
    EVENT_RETURN,
};

enum wait_kind {
    WAIT_KIND_NONE,
    WAIT_KIND_FUTEX,
};

struct wait_resource {
    uint64_t address;
    uint64_t duration_ns;
    uint64_t wake_ns;
    uint32_t kind;
    uint32_t operation;
    uint32_t waker_pid;
    uint32_t waker_tid;
    uint32_t waker_global_pid;
    uint32_t waker_global_tid;
    int32_t waker_stack_id;
    int32_t waker_pidns_error;
    char waker_comm[16];
};

struct async_hop_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_id;
    uint32_t reserved;
    uint64_t key;
    uint64_t queue_ns;
    uint64_t target_ns;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    struct wait_resource wait;
};

struct discovery_wakeup {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_id;
    int32_t pidns_error;
    uint64_t wake_ns;
};

struct stack_trace_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_size;
    int32_t pidns_error;
    uint32_t event_type;
    uint32_t reserved;
    uint64_t timestamp_ns;
    uint64_t duration_ns;
    int64_t return_value;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    struct wait_resource wait;
    uint32_t async_hop_count;
    uint32_t async_truncated;
    struct async_hop_event async_hops[MAX_ASYNC_HOPS];
    uint32_t discovery_valid;
    uint32_t discovery_reserved;
    struct discovery_wakeup discovery_waker;
    uint64_t discovery_wakeup_ns;
    uint64_t stack[MAX_STACK_DEPTH];
};

struct async_hop_config {
    char *source;
    uint32_t source_arg;
    char *target;
    uint32_t target_arg;
};

struct async_hop_stats {
    uint64_t submitted;
    uint64_t started;
    uint64_t completed;
    uint64_t pending;
    uint64_t peak_pending;
    uint64_t active;
    uint64_t peak_active;
    uint64_t queue_total_ns;
    uint64_t work_total_ns;
    uint64_t futex_waits;
    uint64_t futex_wait_ns;
    uint64_t duplicate_keys;
    uint64_t expired;
    uint64_t unmatched_targets;
    uint64_t dropped;
};

struct async_worker_key {
    uint32_t hop_index;
    uint32_t global_tid;
};

struct async_worker_stats {
    uint64_t started;
    uint64_t completed;
    uint64_t active;
    uint64_t peak_active;
    uint64_t work_total_ns;
    uint64_t blocked_total_ns;
    uint64_t futex_waits;
    uint32_t pid;
    uint32_t tid;
    char comm[16];
};

struct io_uring_event {
    uint64_t timestamp_ns;
    uint64_t submit_ns;
    uint64_t duration_ns;
    uint64_t defer_delay_ns;
    uint64_t io_wq_queue_ns;
    uint64_t after_io_wq_ns;
    uint64_t ring_ctx;
    uint64_t request;
    uint64_t user_data;
    uint64_t request_flags;
    uint32_t submit_pid;
    uint32_t submit_tid;
    uint32_t submit_global_pid;
    uint32_t submit_global_tid;
    uint32_t complete_global_pid;
    uint32_t complete_global_tid;
    int32_t fd;
    int32_t result;
    uint32_t cqe_flags;
    int32_t stack_id;
    uint8_t opcode;
    uint8_t sq_thread;
    uint8_t deferred;
    uint8_t io_wq;
    uint8_t io_wq_hashed;
    uint8_t poll_armed;
    uint16_t reserved;
    char submit_comm[16];
    char complete_comm[16];
};

struct io_uring_counters {
    uint64_t submitted;
    uint64_t completions;
    uint64_t finished;
    uint64_t pending;
    uint64_t peak_pending;
    uint64_t unmatched;
    uint64_t dropped_events;
    uint64_t errors;
    uint64_t expected_timeouts;
    uint64_t callback_matched;
    uint64_t callback_unmatched;
    uint64_t callback_dropped;
};

struct io_uring_aggregate_key {
    uint64_t ring_ctx;
    int32_t stack_id;
    int32_t fd;
    uint32_t opcode;
    uint32_t reserved;
};

struct io_uring_aggregate {
    uint64_t count;
    uint64_t errors;
    uint64_t total_ns;
    uint64_t maximum_ns;
    uint64_t slow_count;
    uint64_t deferred_count;
    uint64_t io_wq_count;
    uint64_t io_wq_queue_total_ns;
    uint64_t io_wq_queue_maximum_ns;
};

struct io_uring_aggregate_row {
    struct io_uring_aggregate_key key;
    struct io_uring_aggregate value;
};

struct io_uring_result_key {
    int32_t result;
    uint32_t opcode;
};

struct io_uring_result_row {
    struct io_uring_result_key key;
    uint64_t count;
};

struct io_uring_error_code_summary {
    int32_t result;
    uint64_t count;
};

struct io_uring_operation_summary {
    uint64_t completions;
    uint64_t errors;
    uint64_t expected_timeouts;
    uint64_t total_ns;
    uint64_t maximum_ns;
    uint64_t deferred;
    uint64_t io_wq;
    uint64_t io_wq_queue_total_ns;
    uint64_t io_wq_queue_maximum_ns;
    int32_t top_error_result;
    uint64_t top_error_count;
};

struct io_uring_ring_stats {
    uint64_t submitted;
    uint64_t completions;
    uint64_t errors;
    uint64_t expected_timeouts;
    uint64_t pending;
    uint64_t peak_pending;
    uint64_t total_ns;
    uint64_t maximum_ns;
    uint64_t deferred;
    uint64_t io_wq;
    uint64_t io_wq_hashed;
    uint64_t io_wq_queue_total_ns;
    uint64_t io_wq_queue_maximum_ns;
    uint64_t poll_armed;
    uint64_t cq_waits;
    uint64_t cq_overflows;
    uint64_t request_failures;
    uint64_t links;
    uint64_t failed_links;
    uint64_t registrations;
    uint32_t owner_pid;
    int32_t ring_fd;
    uint32_t flags;
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t registered_files;
    uint32_t registered_buffers;
};

struct io_uring_ring_row {
    uint64_t ring_ctx;
    struct io_uring_ring_stats value;
};

struct io_uring_failure_key {
    uint64_t ring_ctx;
    int32_t error;
    uint32_t opcode;
};

struct io_uring_failure_stats {
    uint64_t count;
    uint64_t user_data;
    uint64_t offset;
    uint64_t address;
    uint64_t address3;
    uint32_t length;
    uint32_t operation_flags;
    uint32_t file_index;
    uint16_t buffer_index;
    uint8_t sqe_flags;
    uint8_t ioprio;
};

struct io_uring_failure_row {
    struct io_uring_failure_key key;
    struct io_uring_failure_stats value;
};

struct io_uring_link_key {
    uint64_t ring_ctx;
    uint64_t parent_user_data;
    uint64_t child_user_data;
};

struct io_uring_link_stats {
    uint64_t parent_request;
    uint64_t child_request;
    uint64_t count;
    uint64_t failures;
    uint8_t parent_opcode;
    uint8_t child_opcode;
    uint16_t reserved;
    uint32_t reserved2;
};

struct io_uring_link_row {
    struct io_uring_link_key key;
    struct io_uring_link_stats value;
};

struct io_uring_callback_event {
    uint64_t timestamp_ns;
    uint64_t completion_ns;
    uint64_t callback_delay_ns;
    uint64_t request_duration_ns;
    uint64_t ring_ctx;
    uint64_t request;
    uint64_t user_data;
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    int32_t result;
    uint32_t cqe_flags;
    int32_t stack_id;
    uint8_t opcode;
    uint8_t reserved[3];
    char comm[16];
};

struct map_list;

struct io_uring_fd_resource {
    int fd;
    char path[PATH_MAX];
};

struct output_options;
static void cache_io_uring_fd_resource(
    struct output_options *output, int fd);

struct output_options {
    bool show_return_value;
    bool show_duration;
    bool show_attribution;
    bool show_async;
    bool show_discovery;
    int async_stack_map_fd;
    int discovery_stack_map_fd;
    int wait_stack_map_fd;
    int async_hop_stats_map_fd;
    int async_worker_stats_map_fd;
    int io_uring_stack_map_fd;
    int io_uring_counters_map_fd;
    int io_uring_aggregate_map_fd;
    int io_uring_result_map_fd;
    int io_uring_ring_stats_map_fd;
    int io_uring_failure_map_fd;
    int io_uring_link_map_fd;
    const char *io_uring_callback_name;
    const struct async_hop_config *async_hops;
    size_t async_hop_count;
    const char *async_source_name;
    const char *final_target_name;
    const char *target_path;
    uint32_t discovery_target_arg;
    uint64_t min_total_ns;
    uint64_t min_queue_ns;
    uint64_t min_work_ns;
    uint32_t max_events;
    uint32_t emitted_events;
    bool json_output;
    FILE *json_stream;
    FILE *report_stream;
    bool report_first;
    bool export_failed;
    bool io_uring_mode;
    bool io_uring_errors_only;
    uint64_t io_uring_min_latency_ns;
    uint32_t io_uring_top;
    uint32_t diagnostic_interval_ms;
    uint64_t diagnostic_last_ns;
    struct async_hop_stats diagnostic_previous[MAX_ASYNC_HOPS];
    struct map_list *io_uring_maps;
    struct io_uring_fd_resource *io_uring_resources;
    size_t io_uring_resource_count;
    size_t io_uring_resource_capacity;
    uint32_t io_uring_maps_pid;
    pid_t target_pid;
    int target_pidfd;
    bool target_exited;
};

_Static_assert(offsetof(struct stack_trace_event, stack) == 1520,
               "userspace and BPF event layouts differ");
_Static_assert(sizeof(struct stack_trace_event) == 2544,
               "userspace and BPF event sizes differ");
_Static_assert(sizeof(struct io_uring_event) == 160,
               "userspace and BPF io_uring event sizes differ");
_Static_assert(sizeof(struct io_uring_aggregate_key) == 24,
               "userspace and BPF io_uring aggregate keys differ");
_Static_assert(sizeof(struct io_uring_aggregate) == 72,
               "userspace and BPF io_uring aggregates differ");
_Static_assert(sizeof(struct io_uring_result_key) == 8,
               "userspace and BPF io_uring result keys differ");
_Static_assert(sizeof(struct io_uring_callback_event) == 104,
               "userspace and BPF io_uring callback events differ");

struct proc_map {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char perms[5];
    char path[PATH_MAX];
    bool bias_checked;
    uint64_t load_bias;
};

struct map_list {
    struct proc_map *items;
    size_t count;
    size_t capacity;
};

struct frame_info {
    uint64_t ip;
    uint64_t object_address;
    struct proc_map *map;
    char address_text[19];
    char *symbol;
};

struct elf_symbol_info {
    uint64_t value;
    uint64_t file_offset;
    bool has_file_offset;
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t force_exit;
static volatile sig_atomic_t interrupt_count;

static const char *path_basename(const char *path);

static void handle_signal(int signo)
{
    if (signo == SIGINT) {
        if (interrupt_count < 2)
            interrupt_count++;
        if (interrupt_count > 1)
            force_exit = 1;
    }
    exiting = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action = {
        .sa_handler = handle_signal,
    };

    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
        fprintf(stderr, "failed to install signal handlers: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static bool target_process_exited(struct output_options *output)
{
    if (output->target_exited)
        return true;
    if (output->target_pidfd >= 0) {
        struct pollfd descriptor = {
            .fd = output->target_pidfd,
            .events = POLLIN,
        };
        int result = poll(&descriptor, 1, 0);

        if (result > 0 &&
            (descriptor.revents & (POLLIN | POLLHUP | POLLERR)))
            output->target_exited = true;
    } else if (output->target_pid > 0 &&
               kill(output->target_pid, 0) &&
               errno == ESRCH) {
        output->target_exited = true;
    }
    return output->target_exited;
}

static int configure_pid_namespace(struct callweave_bpf *skeleton)
{
    struct stat namespace_status;
    int saved_error;

    if (stat("/proc/self/ns/pid", &namespace_status)) {
        saved_error = errno;
        fprintf(stderr, "cannot inspect /proc/self/ns/pid: %s\n",
                strerror(saved_error));
        return -saved_error;
    }

    skeleton->rodata->pidns_dev = (uint64_t)namespace_status.st_dev;
    skeleton->rodata->pidns_ino = (uint64_t)namespace_status.st_ino;
    return 0;
}

static int attach_raw_tracepoint(struct bpf_program *program,
                                 struct bpf_link **link,
                                 const char *tracepoint)
{
    int error;

    *link = bpf_program__attach_raw_tracepoint(program, tracepoint);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return 0;

    *link = NULL;
    fprintf(stderr, "failed to attach raw tracepoint %s: %s\n",
            tracepoint, strerror(-error));
    return error;
}

static bool attach_optional_raw_tracepoint(
    struct bpf_program *program, struct bpf_link **link,
    const char *tracepoint)
{
    int error;

    *link = bpf_program__attach_raw_tracepoint(program, tracepoint);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return true;
    *link = NULL;
    fprintf(stderr,
            "warning: optional io_uring tracepoint %s unavailable: %s\n",
            tracepoint, strerror(-error));
    return false;
}

static bool attach_optional_kprobe(struct bpf_program *program,
                                   struct bpf_link **link,
                                   const char *function)
{
    int error;

    *link = bpf_program__attach_kprobe(program, false, function);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return true;
    *link = NULL;
    fprintf(stderr,
            "warning: optional io_uring kprobe %s unavailable: %s\n",
            function, strerror(-error));
    return false;
}

static void detach_link(struct bpf_link **link)
{
    if (!link || !*link)
        return;
    bpf_link__destroy(*link);
    *link = NULL;
}

static void detach_io_uring_links(struct callweave_bpf *skeleton)
{
    if (!skeleton)
        return;
    detach_link(&skeleton->links.trace_io_uring_submit_req);
    detach_link(&skeleton->links.trace_io_uring_file_get);
    detach_link(&skeleton->links.trace_io_uring_complete);
    detach_link(&skeleton->links.trace_io_uring_create);
    detach_link(&skeleton->links.trace_io_uring_register);
    detach_link(&skeleton->links.trace_io_uring_defer);
    detach_link(&skeleton->links.trace_io_uring_queue_async_work);
    detach_link(&skeleton->links.trace_io_wq_submit_work);
    detach_link(&skeleton->links.trace_io_uring_poll_arm);
    detach_link(&skeleton->links.trace_io_uring_cqring_wait);
    detach_link(&skeleton->links.trace_io_uring_cqe_overflow);
    detach_link(&skeleton->links.trace_io_uring_req_failed);
    detach_link(&skeleton->links.trace_io_uring_link);
    detach_link(&skeleton->links.trace_io_uring_fail_link);
    detach_link(&skeleton->links.trace_io_uring_callback);
}

static int attach_named_uprobe(struct bpf_program *program,
                               struct bpf_link **link,
                               const char *path, const char *function,
                               uint64_t cookie, bool return_probe)
{
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
        .func_name = function,
        .bpf_cookie = cookie,
        .retprobe = return_probe,
    };
    int error;

    *link = bpf_program__attach_uprobe_opts(program, -1, path, 0, &options);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return 0;

    *link = NULL;
    fprintf(stderr, "failed to attach async %suprobe to %s:%s: %s\n",
            return_probe ? "return " : "", path, function,
            strerror(-error));
    return error;
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage:\n"
            "  %s [OPTIONS] BINARY FUNCTION\n"
            "  %s -p PID [--module MODULE] FUNCTION\n"
            "  %s -p PID [--module MODULE] --find-symbol SYMBOL\n"
            "  %s --binary BINARY --offset OFFSET\n"
            "  %s -p PID --discover-async FUNCTION\n"
            "  %s -p PID --config PATH\n"
            "  %s -p PID --io-uring\n"
            "  %s --check-config PATH\n"
            "\n"
            "Options:\n"
            "  -p, --pid PID             only emit events from PID\n"
            "  -b, --binary PATH         executable or shared-library path\n"
            "  -m, --module MODULE       mapped module basename or absolute path\n"
            "  -s, --find-symbol SYMBOL  find SYMBOL in mapped ELF modules and exit\n"
            "  -o, --offset OFFSET       attach at an ELF file offset\n"
            "  -r, --ret                 print the raw function return value\n"
            "  -t, --time                print function execution time\n"
            "  -a, --attribution         break time down by scheduler state;\n"
            "                             report the longest futex wait\n"
            "      --async-source FUNC    capture the producer stack at FUNC\n"
            "      --async-source-binary PATH\n"
            "                             ELF containing the producer function\n"
            "      --async-source-arg N   producer key argument, 1-8 (default 1)\n"
            "      --async-target-arg N   target key argument, 1-8 or auto\n"
            "                             (default auto)\n"
            "      --async-max-age-ms MS  discard older contexts (default 30000)\n"
            "      --async-hop S,SA,T[,TA]\n"
            "                             add one async hop (repeat up to 8);\n"
            "                             omitted TA scans target arg1-arg8\n"
            "                             async tracing implies --time and\n"
            "                             --attribution\n"
            "      --discover-async FUNC  show the latest waker stack and a\n"
            "                             candidate async-hop for FUNC\n"
            "      --config PATH          load target, hops, and filters from\n"
            "                             a callweave YAML config\n"
            "      --check-config PATH    validate a config and exit\n"
            "      --min-total-ms MS      only print chains at least MS total\n"
            "      --min-queue-ms MS      require one hop with MS queue time\n"
            "      --min-work-ms MS       require one hop with MS work time\n"
            "      --max-events N         stop after N matching chains\n"
            "      --duration SEC         stop tracing after SEC seconds\n"
            "      --diagnostic-interval-ms MS\n"
            "                             live queue snapshot interval "
            "(default 1000; 0 disables periodic output)\n"
            "      --format FORMAT        text or json (default text)\n"
            "      --output PATH          write JSON Lines to PATH\n"
            "      --report PATH          write a self-contained HTML report\n"
            "      --io-uring             trace io_uring submission-to-CQE "
            "latency\n"
            "      --min-io-latency-us US only emit io_uring requests at "
            "least US\n"
            "      --io-errors-only        only emit failed io_uring "
            "requests\n"
            "      --io-top N              show N slowest opcode/fd/stack "
            "groups\n"
            "      --io-callback FUNC      correlate CQE to a user callback\n"
            "      --io-callback-binary PATH\n"
            "                             ELF containing the callback "
            "(default /proc/PID/exe)\n"
            "      --io-callback-arg N     callback argument containing "
            "user_data, 1-8 (default 1)\n"
            "  -h, --help                show this help\n"
            "\n"
            "When -p is used without --binary or --module, /proc/PID/exe is used.\n"
            "Without -p, an explicit BINARY is required.\n",
            program, program, program, program, program, program, program,
            program);
}

static int parse_pid(const char *text, pid_t *pid)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || !end || *end != '\0' || value <= 0 || value > INT_MAX)
        return -1;
    *pid = (pid_t)value;
    return 0;
}

static int parse_offset(const char *text, size_t *offset)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno || !end || *end != '\0')
        return -1;
#if SIZE_MAX < ULLONG_MAX
    if (value > SIZE_MAX)
        return -1;
#endif
    *offset = (size_t)value;
    return 0;
}

static int parse_u32_range(const char *text, uint32_t minimum,
                           uint32_t maximum, uint32_t *result)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end != '\0' ||
        value < minimum || value > maximum)
        return -1;
    *result = (uint32_t)value;
    return 0;
}

static int validate_target_pid(pid_t pid)
{
    char process_path[64];
    struct stat process_status;
    int saved_error;

    if (pid <= 0)
        return 0;

    snprintf(process_path, sizeof(process_path), "/proc/%d", (int)pid);
    if (!stat(process_path, &process_status))
        return 0;

    saved_error = errno;
    fprintf(stderr,
            "target PID %d is not visible in this PID namespace: %s\n"
            "verify it with `ps -p %d` while the target is still running\n",
            (int)pid, strerror(saved_error), (int)pid);
    return -saved_error;
}

static void map_list_free(struct map_list *maps)
{
    free(maps->items);
    maps->items = NULL;
    maps->count = 0;
    maps->capacity = 0;
}

static int read_process_maps(uint32_t pid, struct map_list *maps);

static struct map_list *get_io_uring_maps(
    struct output_options *output,
    const struct io_uring_event *event)
{
    struct map_list *maps;
    uint32_t maps_pid = event->submit_pid;

    if (output->io_uring_maps &&
        output->io_uring_maps_pid == maps_pid)
        return output->io_uring_maps;

    if (output->io_uring_maps) {
        map_list_free(output->io_uring_maps);
        free(output->io_uring_maps);
        output->io_uring_maps = NULL;
        output->io_uring_maps_pid = 0;
    }
    maps = calloc(1, sizeof(*maps));
    if (!maps)
        return NULL;
    if (read_process_maps(maps_pid, maps) &&
        event->submit_pid != event->submit_global_pid) {
        map_list_free(maps);
        maps_pid = event->submit_global_pid;
        if (read_process_maps(maps_pid, maps)) {
            free(maps);
            return NULL;
        }
    } else if (!maps->count) {
        map_list_free(maps);
        free(maps);
        return NULL;
    }
    output->io_uring_maps = maps;
    output->io_uring_maps_pid = maps_pid;
    return maps;
}

static int map_list_append(struct map_list *maps, const struct proc_map *map)
{
    struct proc_map *new_items;
    size_t new_capacity;

    if (maps->count == maps->capacity) {
        new_capacity = maps->capacity ? maps->capacity * 2 : 32;
        new_items = realloc(maps->items, new_capacity * sizeof(*new_items));
        if (!new_items)
            return -1;
        maps->items = new_items;
        maps->capacity = new_capacity;
    }

    maps->items[maps->count++] = *map;
    return 0;
}

static void trim_deleted_suffix(char *path)
{
    static const char suffix[] = " (deleted)";
    size_t path_length = strlen(path);
    size_t suffix_length = sizeof(suffix) - 1;

    if (path_length >= suffix_length &&
        !strcmp(path + path_length - suffix_length, suffix))
        path[path_length - suffix_length] = '\0';
}

static int read_process_maps(uint32_t pid, struct map_list *maps)
{
    char maps_path[64];
    char *line = NULL;
    size_t line_capacity = 0;
    FILE *file;
    int result = -1;

    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    file = fopen(maps_path, "re");
    if (!file)
        return -1;

    while (getline(&line, &line_capacity, file) >= 0) {
        struct proc_map map = {0};
        unsigned long long start, end, offset;
        char device[32];
        unsigned long inode;
        int path_offset = 0;
        char *path;

        if (sscanf(line, "%llx-%llx %4s %llx %31s %lu %n",
                   &start, &end, map.perms, &offset, device, &inode,
                   &path_offset) < 6)
            continue;

        map.start = start;
        map.end = end;
        map.offset = offset;
        path = line + path_offset;
        path[strcspn(path, "\r\n")] = '\0';
        while (*path == ' ' || *path == '\t')
            path++;

        if (*path == '/') {
            snprintf(map.path, sizeof(map.path), "%s", path);
            trim_deleted_suffix(map.path);
        }

        if (map_list_append(maps, &map))
            goto out;
    }

    result = 0;
out:
    free(line);
    fclose(file);
    return result;
}

static bool is_first_path_occurrence(const struct map_list *maps, size_t index)
{
    size_t i;

    if (!maps->items[index].path[0])
        return false;
    for (i = 0; i < index; i++) {
        if (!strcmp(maps->items[i].path, maps->items[index].path))
            return false;
    }
    return true;
}

static bool module_name_matches(const char *path, const char *module)
{
    if (strchr(module, '/'))
        return !strcmp(path, module);
    return !strcmp(path_basename(path), module);
}

static int resolve_process_executable(pid_t pid, char *path, size_t path_size)
{
    char proc_exe[64];
    char resolved[PATH_MAX];
    ssize_t length;

    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", (int)pid);
    length = readlink(proc_exe, resolved, sizeof(resolved) - 1);
    if (length < 0) {
        fprintf(stderr, "cannot read %s: %s\n", proc_exe, strerror(errno));
        return -errno;
    }
    if ((size_t)length >= sizeof(resolved) - 1) {
        fprintf(stderr, "executable path for PID %d is too long\n", (int)pid);
        return -ENAMETOOLONG;
    }
    resolved[length] = '\0';

    if (!strstr(resolved, " (deleted)") && !access(resolved, R_OK)) {
        if (snprintf(path, path_size, "%s", resolved) >= (int)path_size)
            return -ENAMETOOLONG;
    } else if (snprintf(path, path_size, "%s", proc_exe) >= (int)path_size) {
        return -ENAMETOOLONG;
    }
    return 0;
}

static int resolve_loaded_module(pid_t pid, const char *module,
                                 char *path, size_t path_size)
{
    struct map_list maps = {0};
    size_t match_count = 0;
    size_t i;
    int error = 0;

    if (read_process_maps((uint32_t)pid, &maps)) {
        error = -errno;
        fprintf(stderr, "cannot read /proc/%d/maps: %s\n",
                (int)pid, strerror(errno));
        goto out;
    }

    for (i = 0; i < maps.count; i++) {
        if (!is_first_path_occurrence(&maps, i) ||
            !module_name_matches(maps.items[i].path, module))
            continue;
        match_count++;
        if (match_count == 1 &&
            snprintf(path, path_size, "%s", maps.items[i].path) >=
                (int)path_size) {
            error = -ENAMETOOLONG;
            goto out;
        }
    }

    if (!match_count) {
        fprintf(stderr, "module '%s' is not mapped in PID %d\n",
                module, (int)pid);
        error = -ENOENT;
    } else if (match_count > 1) {
        fprintf(stderr, "module '%s' is ambiguous in PID %d:\n",
                module, (int)pid);
        for (i = 0; i < maps.count; i++) {
            if (is_first_path_occurrence(&maps, i) &&
                module_name_matches(maps.items[i].path, module))
                fprintf(stderr, "  %s\n", maps.items[i].path);
        }
        fprintf(stderr, "use an absolute module path to select one\n");
        error = -ENOTUNIQ;
    }

out:
    map_list_free(&maps);
    return error;
}

static void symbol_file_offset(Elf *elf, uint64_t value,
                               struct elf_symbol_info *info)
{
    size_t program_header_count;
    size_t i;

    if (elf_getphdrnum(elf, &program_header_count))
        return;

    for (i = 0; i < program_header_count; i++) {
        GElf_Phdr program_header;

        if (!gelf_getphdr(elf, (int)i, &program_header) ||
            program_header.p_type != PT_LOAD ||
            value < program_header.p_vaddr ||
            value - program_header.p_vaddr >= program_header.p_filesz)
            continue;

        info->file_offset = program_header.p_offset +
                            (value - program_header.p_vaddr);
        info->has_file_offset = true;
        return;
    }
}

static int find_elf_symbol(const char *path, const char *symbol_name,
                           struct elf_symbol_info *info)
{
    Elf_Scn *section = NULL;
    Elf *elf = NULL;
    int file_descriptor = -1;
    int result = -1;

    memset(info, 0, sizeof(*info));
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
        errno = ENOTSUP;
        return -1;
    }

    file_descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (file_descriptor < 0)
        return -1;
    elf = elf_begin(file_descriptor, ELF_C_READ, NULL);
    if (!elf) {
        errno = ENOEXEC;
        goto out;
    }

    result = 0;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr section_header;
        Elf_Data *data = NULL;

        if (!gelf_getshdr(section, &section_header) ||
            (section_header.sh_type != SHT_SYMTAB &&
             section_header.sh_type != SHT_DYNSYM) ||
            !section_header.sh_entsize)
            continue;

        while ((data = elf_getdata(section, data)) != NULL) {
            size_t symbol_count = data->d_size / section_header.sh_entsize;
            size_t i;

            for (i = 0; i < symbol_count; i++) {
                GElf_Sym symbol;
                const char *name;
                unsigned int type;

                if (!gelf_getsym(data, (int)i, &symbol) ||
                    symbol.st_shndx == SHN_UNDEF)
                    continue;
                type = GELF_ST_TYPE(symbol.st_info);
                if (type != STT_FUNC
#ifdef STT_GNU_IFUNC
                    && type != STT_GNU_IFUNC
#endif
                )
                    continue;
                name = elf_strptr(elf, section_header.sh_link, symbol.st_name);
                if (!name || strcmp(name, symbol_name))
                    continue;

                info->value = symbol.st_value;
                symbol_file_offset(elf, info->value, info);
                result = 1;
                goto out;
            }
        }
    }

out:
    if (elf)
        elf_end(elf);
    if (file_descriptor >= 0)
        close(file_descriptor);
    return result;
}

static int print_symbol_result(const char *path, const char *symbol_name)
{
    struct elf_symbol_info info;
    int result = find_elf_symbol(path, symbol_name, &info);

    if (result <= 0)
        return result;

    printf("%s\n", path);
    printf("  symbol=%s value=0x%llx", symbol_name,
           (unsigned long long)info.value);
    if (info.has_file_offset)
        printf(" offset=0x%llx",
               (unsigned long long)info.file_offset);
    else
        printf(" offset=unavailable");
    putchar('\n');
    return 1;
}

static int find_symbol_in_process(pid_t pid, const char *module,
                                  const char *symbol_name)
{
    struct map_list maps = {0};
    size_t searched = 0;
    size_t matches = 0;
    size_t i;
    int error = 0;

    if (read_process_maps((uint32_t)pid, &maps)) {
        fprintf(stderr, "cannot read /proc/%d/maps: %s\n",
                (int)pid, strerror(errno));
        return -errno;
    }

    for (i = 0; i < maps.count; i++) {
        int result;

        if (!is_first_path_occurrence(&maps, i) ||
            (module && !module_name_matches(maps.items[i].path, module)))
            continue;
        searched++;
        result = print_symbol_result(maps.items[i].path, symbol_name);
        if (result > 0)
            matches++;
    }

    if (!matches) {
        fprintf(stderr,
                "symbol '%s' was not found in %zu mapped ELF module%s\n",
                symbol_name, searched, searched == 1 ? "" : "s");
        error = -ENOENT;
    } else {
        printf("Found %zu matching module%s.\n",
               matches, matches == 1 ? "" : "s");
    }

    map_list_free(&maps);
    return error;
}

static struct proc_map *find_map(struct map_list *maps, uint64_t address)
{
    size_t i;

    for (i = 0; i < maps->count; i++) {
        if (address >= maps->items[i].start && address < maps->items[i].end)
            return &maps->items[i];
    }
    return NULL;
}

static uint64_t align_down(uint64_t value, uint64_t alignment)
{
    return alignment ? value - value % alignment : value;
}

static int load_bias_from_elf64(FILE *file, const Elf64_Ehdr *header,
                                const struct proc_map *map, uint64_t page_size,
                                uint64_t *load_bias)
{
    size_t i;

    if (header->e_phentsize != sizeof(Elf64_Phdr) ||
        fseeko(file, (off_t)header->e_phoff, SEEK_SET))
        return -1;

    for (i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr program_header;

        if (fread(&program_header, sizeof(program_header), 1, file) != 1)
            return -1;
        if (program_header.p_type != PT_LOAD)
            continue;
        if (align_down(program_header.p_offset, page_size) != map->offset)
            continue;

        *load_bias = map->start -
                     align_down(program_header.p_vaddr, page_size);
        return 0;
    }
    return -1;
}

static int load_bias_from_elf32(FILE *file, const Elf32_Ehdr *header,
                                const struct proc_map *map, uint64_t page_size,
                                uint64_t *load_bias)
{
    size_t i;

    if (header->e_phentsize != sizeof(Elf32_Phdr) ||
        fseeko(file, (off_t)header->e_phoff, SEEK_SET))
        return -1;

    for (i = 0; i < header->e_phnum; i++) {
        Elf32_Phdr program_header;

        if (fread(&program_header, sizeof(program_header), 1, file) != 1)
            return -1;
        if (program_header.p_type != PT_LOAD)
            continue;
        if (align_down(program_header.p_offset, page_size) != map->offset)
            continue;

        *load_bias = map->start -
                     align_down(program_header.p_vaddr, page_size);
        return 0;
    }
    return -1;
}

static uint64_t get_load_bias(struct proc_map *map)
{
    unsigned char identity[EI_NIDENT];
    long system_page_size = sysconf(_SC_PAGESIZE);
    uint64_t page_size = system_page_size > 0 ? (uint64_t)system_page_size : 4096;
    FILE *file;

    if (map->bias_checked)
        return map->load_bias;
    map->bias_checked = true;

    file = fopen(map->path, "re");
    if (!file)
        goto fallback;
    if (fread(identity, sizeof(identity), 1, file) != 1 ||
        memcmp(identity, ELFMAG, SELFMAG))
        goto close_and_fallback;
    rewind(file);

    if (identity[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr header;

        if (fread(&header, sizeof(header), 1, file) == 1 &&
            !load_bias_from_elf64(file, &header, map, page_size,
                                  &map->load_bias)) {
            fclose(file);
            return map->load_bias;
        }
    } else if (identity[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr header;

        if (fread(&header, sizeof(header), 1, file) == 1 &&
            !load_bias_from_elf32(file, &header, map, page_size,
                                  &map->load_bias)) {
            fclose(file);
            return map->load_bias;
        }
    }

close_and_fallback:
    fclose(file);
fallback:
    map->load_bias = map->start - map->offset;
    return map->load_bias;
}

static int wait_for_child(pid_t child, int *status)
{
    pid_t result;

    for (;;) {
        if (force_exit) {
            kill(child, SIGTERM);
            do {
                result = waitpid(child, status, 0);
            } while (result < 0 && errno == EINTR);
            return -1;
        }
        result = waitpid(child, status, 0);
        if (result >= 0 || errno != EINTR)
            break;
    }
    return result < 0 ? -1 : 0;
}

static int symbolize_group(struct frame_info *frames, const size_t *indices,
                           size_t count, const char *module_path)
{
    char *arguments[MAX_STACK_DEPTH + 8];
    char *line = NULL;
    size_t line_capacity = 0;
    int pipe_fds[2];
    pid_t child;
    FILE *output;
    size_t i;
    int status;

    if (!count)
        return 0;
    if (pipe(pipe_fds))
        return -1;

    arguments[0] = (char *)"addr2line";
    arguments[1] = (char *)"-C";
    arguments[2] = (char *)"-f";
    arguments[3] = (char *)"-p";
    arguments[4] = (char *)"-e";
    arguments[5] = (char *)module_path;
    for (i = 0; i < count; i++)
        arguments[6 + i] = frames[indices[i]].address_text;
    arguments[6 + count] = NULL;

    child = fork();
    if (child < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    if (child == 0) {
        close(pipe_fds[0]);
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(pipe_fds[1]);
        execvp(arguments[0], arguments);
        _exit(127);
    }

    close(pipe_fds[1]);
    output = fdopen(pipe_fds[0], "r");
    if (!output) {
        close(pipe_fds[0]);
        wait_for_child(child, &status);
        return -1;
    }

    for (i = 0; i < count && getline(&line, &line_capacity, output) >= 0; i++) {
        line[strcspn(line, "\r\n")] = '\0';
        frames[indices[i]].symbol = strdup(line);
    }

    free(line);
    fclose(output);
    if (wait_for_child(child, &status))
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void resolve_frames(struct frame_info *frames, size_t frame_count)
{
    bool grouped[MAX_STACK_DEPTH] = {0};
    size_t indices[MAX_STACK_DEPTH];
    size_t i, j;

    for (i = 0; i < frame_count; i++) {
        if (force_exit)
            break;
        size_t group_count = 0;

        if (grouped[i] || !frames[i].map || !frames[i].map->path[0])
            continue;
        for (j = i; j < frame_count; j++) {
            if (!grouped[j] && frames[j].map &&
                !strcmp(frames[i].map->path, frames[j].map->path)) {
                grouped[j] = true;
                indices[group_count++] = j;
            }
        }
        symbolize_group(frames, indices, group_count, frames[i].map->path);
    }
}

static uint64_t timespec_nanoseconds(const struct timespec *time)
{
    return (uint64_t)time->tv_sec * 1000000000ULL +
           (uint64_t)time->tv_nsec;
}

static uint64_t event_realtime_nanoseconds(uint64_t timestamp_ns)
{
    static bool offset_initialized;
    static int64_t realtime_monotonic_offset_ns;
    struct timespec realtime;
    struct timespec monotonic;
    uint64_t realtime_ns;
    uint64_t monotonic_ns;

    if (!timestamp_ns) {
        if (clock_gettime(CLOCK_REALTIME, &realtime))
            return 0;
        return timespec_nanoseconds(&realtime);
    }
    if (!offset_initialized) {
        if (clock_gettime(CLOCK_MONOTONIC, &monotonic) ||
            clock_gettime(CLOCK_REALTIME, &realtime))
            return 0;
        monotonic_ns = timespec_nanoseconds(&monotonic);
        realtime_ns = timespec_nanoseconds(&realtime);
        realtime_monotonic_offset_ns =
            (int64_t)realtime_ns - (int64_t)monotonic_ns;
        offset_initialized = true;
    }
    if (realtime_monotonic_offset_ns >= 0)
        return timestamp_ns +
               (uint64_t)realtime_monotonic_offset_ns;
    if (timestamp_ns < (uint64_t)-realtime_monotonic_offset_ns)
        return 0;
    return timestamp_ns -
           (uint64_t)-realtime_monotonic_offset_ns;
}

static void print_event_time(uint64_t timestamp_ns)
{
    char buffer[32];
    struct tm local_time;
    uint64_t realtime_ns =
        event_realtime_nanoseconds(timestamp_ns);
    time_t seconds = (time_t)(realtime_ns / 1000000000ULL);
    unsigned long microseconds =
        (unsigned long)(realtime_ns % 1000000000ULL / 1000ULL);

    if (realtime_ns && localtime_r(&seconds, &local_time) &&
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time))
        printf("[%s.%06lu] ", buffer, microseconds);
}

static uint64_t monotonic_time_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL +
           (uint64_t)now.tv_nsec;
}

static void fprint_interval(FILE *stream, const char *label,
                            uint64_t nanoseconds)
{
    if (nanoseconds >= 1000000000ULL)
        fprintf(stream, " %s=%.6f s", label,
                (double)nanoseconds / 1000000000.0);
    else if (nanoseconds >= 1000000ULL)
        fprintf(stream, " %s=%.3f ms", label,
                (double)nanoseconds / 1000000.0);
    else if (nanoseconds >= 1000ULL)
        fprintf(stream, " %s=%.3f us", label,
                (double)nanoseconds / 1000.0);
    else
        fprintf(stream, " %s=%llu ns", label,
                (unsigned long long)nanoseconds);
}

static void print_interval(const char *label, uint64_t nanoseconds)
{
    fprint_interval(stdout, label, nanoseconds);
}

static void format_interval(char *buffer, size_t size, uint64_t nanoseconds)
{
    if (nanoseconds >= 1000000000ULL)
        snprintf(buffer, size, "%.3f s",
                 (double)nanoseconds / 1000000000.0);
    else if (nanoseconds >= 1000000ULL)
        snprintf(buffer, size, "%.3f ms",
                 (double)nanoseconds / 1000000.0);
    else if (nanoseconds >= 1000ULL)
        snprintf(buffer, size, "%.3f us",
                 (double)nanoseconds / 1000.0);
    else
        snprintf(buffer, size, "%llu ns",
                 (unsigned long long)nanoseconds);
}

static void copy_queue_diagnostic(
    struct cw_queue_diagnostic *destination,
    const struct async_hop_stats *source, uint32_t index,
    const struct output_options *output)
{
    memset(destination, 0, sizeof(*destination));
    destination->index = index;
    if (index < output->async_hop_count) {
        destination->source = output->async_hops[index].source;
        destination->target = output->async_hops[index].target;
    } else {
        destination->source = output->async_source_name ?
            output->async_source_name : "source";
        destination->target = output->final_target_name ?
            output->final_target_name : "target";
    }
    destination->submitted = source->submitted;
    destination->started = source->started;
    destination->completed = source->completed;
    destination->pending = source->pending;
    destination->peak_pending = source->peak_pending;
    destination->active = source->active;
    destination->peak_active = source->peak_active;
    destination->queue_total_ns = source->queue_total_ns;
    destination->work_total_ns = source->work_total_ns;
    destination->futex_waits = source->futex_waits;
    destination->futex_wait_ns = source->futex_wait_ns;
    destination->duplicate_keys = source->duplicate_keys;
    destination->expired = source->expired;
    destination->unmatched_targets = source->unmatched_targets;
    destination->dropped = source->dropped;
}

static size_t read_queue_diagnostics(
    const struct output_options *output,
    struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS],
    struct async_hop_stats raw[MAX_ASYNC_HOPS])
{
    struct async_worker_key key;
    struct async_worker_key next;
    size_t count = output->async_hop_count ?
        output->async_hop_count : (output->show_async ? 1 : 0);
    uint32_t index;

    if (count > MAX_ASYNC_HOPS)
        count = MAX_ASYNC_HOPS;
    memset(raw, 0, sizeof(*raw) * MAX_ASYNC_HOPS);
    memset(diagnostics, 0, sizeof(*diagnostics) * MAX_ASYNC_HOPS);
    if (output->async_hop_stats_map_fd < 0)
        return 0;
    for (index = 0; index < count; index++) {
        if (bpf_map_lookup_elem(output->async_hop_stats_map_fd,
                                &index, &raw[index]))
            continue;
        copy_queue_diagnostic(&diagnostics[index], &raw[index],
                              index, output);
    }

    if (output->async_worker_stats_map_fd < 0 ||
        bpf_map_get_next_key(output->async_worker_stats_map_fd,
                             NULL, &next))
        return count;
    do {
        struct async_worker_stats worker;
        struct cw_queue_diagnostic *diagnostic;

        key = next;
        if (!bpf_map_lookup_elem(output->async_worker_stats_map_fd,
                                 &key, &worker) &&
            key.hop_index < count) {
            diagnostic = &diagnostics[key.hop_index];
            diagnostic->worker_count++;
            if (worker.started >
                diagnostic->busiest_worker_started) {
                diagnostic->busiest_worker_tid = worker.tid;
                diagnostic->busiest_worker_started = worker.started;
                diagnostic->busiest_worker_average_work_ns =
                    worker.completed ?
                        worker.work_total_ns / worker.completed : 0;
            }
        }
    } while (!bpf_map_get_next_key(output->async_worker_stats_map_fd,
                                    &key, &next));
    return count;
}

static const char *queue_diagnosis(
    const struct cw_queue_diagnostic *diagnostic,
    uint64_t submitted_delta, uint64_t started_delta)
{
    uint64_t anomalies = diagnostic->duplicate_keys +
        diagnostic->expired + diagnostic->dropped;

    if (!diagnostic->submitted)
        return "waiting for samples";
    if (diagnostic->pending && submitted_delta > started_delta)
        return "backlog growing";
    if (diagnostic->pending && diagnostic->active &&
        diagnostic->active >= diagnostic->peak_active)
        return "workers saturated";
    if (diagnostic->completed &&
        diagnostic->futex_waits * 4 >= diagnostic->completed)
        return "lock contention";
    if (anomalies)
        return "correlation loss observed";
    return "no clear bottleneck";
}

static bool print_queue_diagnostics(struct output_options *output,
                                    bool final)
{
    struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS];
    struct async_hop_stats raw[MAX_ASYNC_HOPS];
    uint64_t now = monotonic_time_ns();
    uint64_t elapsed_ns = output->diagnostic_last_ns ?
        now - output->diagnostic_last_ns : 0;
    FILE *stream = output->json_output ? stderr : stdout;
    size_t count;
    size_t index;
    bool changed = false;

    count = read_queue_diagnostics(output, diagnostics, raw);
    for (index = 0; index < count; index++) {
        if (memcmp(&raw[index], &output->diagnostic_previous[index],
                   sizeof(raw[index]))) {
            changed = true;
            break;
        }
    }
    if (!changed && !final)
        return false;

    fprintf(stream, "\n[queue diagnostics%s]\n",
            final ? " final" : "");
    for (index = 0; index < count; index++) {
        const struct cw_queue_diagnostic *diagnostic =
            &diagnostics[index];
        uint64_t submitted_delta = raw[index].submitted -
            output->diagnostic_previous[index].submitted;
        uint64_t started_delta = raw[index].started -
            output->diagnostic_previous[index].started;
        uint64_t completed_delta = raw[index].completed -
            output->diagnostic_previous[index].completed;
        double seconds = elapsed_ns ?
            (double)elapsed_ns / 1000000000.0 : 0.0;
        char average_queue[32];
        char average_work[32];

        format_interval(
            average_queue, sizeof(average_queue),
            diagnostic->started ?
                diagnostic->queue_total_ns / diagnostic->started : 0);
        format_interval(
            average_work, sizeof(average_work),
            diagnostic->completed ?
                diagnostic->work_total_ns / diagnostic->completed : 0);
        fprintf(stream,
                "  hop %zu %s -> %s: "
                "rate %.1f/%.1f/%.1f per s, "
                "pending %llu (peak %llu), active %llu (peak %llu), "
                "average queue %s, average work %s, workers %u, %s\n",
                index, diagnostic->source, diagnostic->target,
                seconds ? submitted_delta / seconds : 0.0,
                seconds ? started_delta / seconds : 0.0,
                seconds ? completed_delta / seconds : 0.0,
                (unsigned long long)diagnostic->pending,
                (unsigned long long)diagnostic->peak_pending,
                (unsigned long long)diagnostic->active,
                (unsigned long long)diagnostic->peak_active,
                average_queue, average_work, diagnostic->worker_count,
                queue_diagnosis(diagnostic, submitted_delta,
                                started_delta));
        if (diagnostic->duplicate_keys || diagnostic->expired ||
            diagnostic->unmatched_targets || diagnostic->dropped) {
            fprintf(stream,
                    "    anomalies: duplicate=%llu expired=%llu "
                    "unmatched=%llu no-handoff=%llu\n",
                    (unsigned long long)diagnostic->duplicate_keys,
                    (unsigned long long)diagnostic->expired,
                    (unsigned long long)diagnostic->unmatched_targets,
                    (unsigned long long)diagnostic->dropped);
        }
    }
    fflush(stream);
    memcpy(output->diagnostic_previous, raw, sizeof(raw));
    output->diagnostic_last_ns = now;
    return true;
}

static void calculate_attribution(uint64_t duration_ns, uint64_t offcpu_ns,
                                  uint64_t blocked_ns, uint64_t runqueue_ns,
                                  uint64_t *oncpu_ns, uint64_t *unknown_ns)
{
    uint64_t classified_ns;

    if (offcpu_ns > duration_ns)
        offcpu_ns = duration_ns;
    classified_ns = blocked_ns + runqueue_ns;
    *unknown_ns = offcpu_ns > classified_ns ?
                  offcpu_ns - classified_ns : 0;
    *oncpu_ns = duration_ns - offcpu_ns;
}

static const char *dominant_attribution(uint64_t oncpu_ns,
                                        uint64_t blocked_ns,
                                        uint64_t runqueue_ns,
                                        uint64_t unknown_ns)
{
    const char *dominant = "on-CPU";
    uint64_t maximum = oncpu_ns;

    if (blocked_ns > maximum) {
        dominant = "blocked";
        maximum = blocked_ns;
    }
    if (runqueue_ns > maximum) {
        dominant = "run-queue";
        maximum = runqueue_ns;
    }
    if (unknown_ns > maximum)
        dominant = "preempt/unknown";
    return dominant;
}

static void print_attribution(uint64_t duration_ns, uint64_t offcpu_ns,
                              uint64_t blocked_ns, uint64_t runqueue_ns,
                              bool include_dominant)
{
    uint64_t oncpu_ns;
    uint64_t unknown_ns;

    calculate_attribution(duration_ns, offcpu_ns, blocked_ns, runqueue_ns,
                          &oncpu_ns, &unknown_ns);
    print_interval("oncpu", oncpu_ns);
    print_interval("offcpu", offcpu_ns > duration_ns ?
                   duration_ns : offcpu_ns);
    print_interval("blocked", blocked_ns);
    print_interval("runq", runqueue_ns);
    print_interval("preempt/unknown", unknown_ns);
    if (include_dominant)
        printf(" dominant=%s",
               dominant_attribution(oncpu_ns, blocked_ns, runqueue_ns,
                                    unknown_ns));
}

static void print_stack_frames(const uint64_t *stack, int32_t stack_size,
                               struct map_list *maps, const char *prefix,
                               const char *candidate_path,
                               char *candidate, size_t candidate_size)
{
    struct frame_info frames[MAX_STACK_DEPTH] = {0};
    size_t frame_count;
    size_t i;

    if (stack_size < 0) {
        printf("  %sunable to collect user stack: %s (%d)\n",
               prefix, strerror(-stack_size), stack_size);
        return;
    }
    if (!stack_size) {
        printf("  %sempty user stack\n", prefix);
        return;
    }

    frame_count = (size_t)stack_size / sizeof(stack[0]);
    if (frame_count > MAX_STACK_DEPTH)
        frame_count = MAX_STACK_DEPTH;
    while (frame_count && !stack[frame_count - 1])
        frame_count--;
    if (!frame_count) {
        printf("  %sempty user stack\n", prefix);
        return;
    }

    for (i = 0; i < frame_count && !force_exit; i++) {
        frames[i].ip = stack[i];
        frames[i].map = find_map(maps, frames[i].ip);
        if (frames[i].map && frames[i].map->path[0]) {
            uint64_t load_bias = get_load_bias(frames[i].map);

            frames[i].object_address = frames[i].ip - load_bias;
            snprintf(frames[i].address_text, sizeof(frames[i].address_text),
                     "0x%016llx",
                     (unsigned long long)frames[i].object_address);
        }
    }

    resolve_frames(frames, frame_count);
    if (force_exit) {
        for (i = 0; i < frame_count; i++)
            free(frames[i].symbol);
        return;
    }
    for (i = 0; i < frame_count; i++) {
        if (candidate && candidate_size && !candidate[0] &&
            candidate_path && frames[i].map &&
            !strcmp(frames[i].map->path, candidate_path) &&
            frames[i].symbol && strncmp(frames[i].symbol, "??", 2)) {
            const char *separator = strstr(frames[i].symbol, " at ");
            size_t length = separator ?
                            (size_t)(separator - frames[i].symbol) :
                            strlen(frames[i].symbol);

            if (length >= candidate_size)
                length = candidate_size - 1;
            memcpy(candidate, frames[i].symbol, length);
            candidate[length] = '\0';
        }
        if (!frames[i].map) {
            printf("  %s#%-3zu 0x%016llx [unmapped]\n", prefix, i,
                   (unsigned long long)frames[i].ip);
        } else if (!frames[i].map->path[0]) {
            printf("  %s#%-3zu 0x%016llx [anonymous]\n", prefix, i,
                   (unsigned long long)frames[i].ip);
        } else {
            printf("  %s#%-3zu 0x%016llx %-24s %s\n", prefix, i,
                   (unsigned long long)frames[i].ip,
                   path_basename(frames[i].map->path),
                   frames[i].symbol ? frames[i].symbol : "?? at ??:0");
        }
        free(frames[i].symbol);
    }
}

static const char *io_uring_opcode_name(uint8_t opcode)
{
    switch (opcode) {
    case IORING_OP_NOP:
        return "NOP";
    case IORING_OP_READV:
        return "READV";
    case IORING_OP_WRITEV:
        return "WRITEV";
    case IORING_OP_FSYNC:
        return "FSYNC";
    case IORING_OP_READ_FIXED:
        return "READ_FIXED";
    case IORING_OP_WRITE_FIXED:
        return "WRITE_FIXED";
    case IORING_OP_POLL_ADD:
        return "POLL_ADD";
    case IORING_OP_POLL_REMOVE:
        return "POLL_REMOVE";
    case IORING_OP_SYNC_FILE_RANGE:
        return "SYNC_FILE_RANGE";
    case IORING_OP_SENDMSG:
        return "SENDMSG";
    case IORING_OP_RECVMSG:
        return "RECVMSG";
    case IORING_OP_TIMEOUT:
        return "TIMEOUT";
    case IORING_OP_TIMEOUT_REMOVE:
        return "TIMEOUT_REMOVE";
    case IORING_OP_ACCEPT:
        return "ACCEPT";
    case IORING_OP_ASYNC_CANCEL:
        return "ASYNC_CANCEL";
    case IORING_OP_LINK_TIMEOUT:
        return "LINK_TIMEOUT";
    case IORING_OP_CONNECT:
        return "CONNECT";
    case IORING_OP_FALLOCATE:
        return "FALLOCATE";
    case IORING_OP_OPENAT:
        return "OPENAT";
    case IORING_OP_CLOSE:
        return "CLOSE";
    case IORING_OP_FILES_UPDATE:
        return "FILES_UPDATE";
    case IORING_OP_STATX:
        return "STATX";
    case IORING_OP_READ:
        return "READ";
    case IORING_OP_WRITE:
        return "WRITE";
    default:
        return "UNKNOWN";
    }
}

static int write_json_string(FILE *stream, const char *text, size_t size)
{
    size_t index;

    if (fputc('"', stream) == EOF)
        return -1;
    for (index = 0; index < size && text[index]; index++) {
        unsigned char character = (unsigned char)text[index];

        switch (character) {
        case '"':
            if (fputs("\\\"", stream) == EOF)
                return -1;
            break;
        case '\\':
            if (fputs("\\\\", stream) == EOF)
                return -1;
            break;
        case '\b':
            if (fputs("\\b", stream) == EOF)
                return -1;
            break;
        case '\f':
            if (fputs("\\f", stream) == EOF)
                return -1;
            break;
        case '\n':
            if (fputs("\\n", stream) == EOF)
                return -1;
            break;
        case '\r':
            if (fputs("\\r", stream) == EOF)
                return -1;
            break;
        case '\t':
            if (fputs("\\t", stream) == EOF)
                return -1;
            break;
        default:
            if (character < 0x20) {
                if (fprintf(stream, "\\u%04x", character) < 0)
                    return -1;
            } else if (fputc(character, stream) == EOF) {
                return -1;
            }
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

static int handle_io_uring_event(void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct io_uring_event *event = data;
    const char *operation;

    if (data_size < sizeof(*event))
        return 0;
    if (exiting)
        return 0;
    if (output->max_events &&
        output->emitted_events >= output->max_events)
        return 0;

    cache_io_uring_fd_resource(output, event->fd);
    operation = io_uring_opcode_name(event->opcode);

    if (output->json_output) {
        FILE *stream = output->json_stream;
        uint64_t realtime_ns =
            event_realtime_nanoseconds(event->timestamp_ns);

        if (!stream)
            return 0;
        if (fprintf(stream,
                    "{\"type\":\"io_uring\",\"timestamp_ns\":%llu,"
                    "\"submit_pid\":%u,\"submit_tid\":%u,"
                    "\"submit_global_pid\":%u,"
                    "\"submit_global_tid\":%u,"
                    "\"complete_global_pid\":%u,"
                    "\"complete_global_tid\":%u,"
                    "\"opcode\":%u,\"operation\":",
                    (unsigned long long)realtime_ns,
                    event->submit_pid, event->submit_tid,
                    event->submit_global_pid,
                    event->submit_global_tid,
                    event->complete_global_pid,
                    event->complete_global_tid,
                    event->opcode) < 0 ||
            write_json_string(stream, operation, strlen(operation)) ||
            fprintf(stream,
                    ",\"fd\":%d,\"user_data\":\"0x%016llx\","
                    "\"result\":%d,\"cqe_flags\":%u,"
                    "\"duration_ns\":%llu,"
                    "\"defer_delay_ns\":%llu,"
                    "\"io_wq_queue_ns\":%llu,"
                    "\"after_io_wq_ns\":%llu,"
                    "\"deferred\":%s,\"io_wq\":%s,"
                    "\"io_wq_hashed\":%s,\"poll_armed\":%s,"
                    "\"sq_thread\":%s,"
                    "\"submit_comm\":",
                    event->fd, (unsigned long long)event->user_data,
                    event->result, event->cqe_flags,
                    (unsigned long long)event->duration_ns,
                    (unsigned long long)event->defer_delay_ns,
                    (unsigned long long)event->io_wq_queue_ns,
                    (unsigned long long)event->after_io_wq_ns,
                    event->deferred ? "true" : "false",
                    event->io_wq ? "true" : "false",
                    event->io_wq_hashed ? "true" : "false",
                    event->poll_armed ? "true" : "false",
                    event->sq_thread ? "true" : "false") < 0 ||
            write_json_string(stream, event->submit_comm,
                              sizeof(event->submit_comm)) ||
            fputs(",\"complete_comm\":", stream) == EOF ||
            write_json_string(stream, event->complete_comm,
                              sizeof(event->complete_comm)) ||
            fputs("}\n", stream) == EOF ||
            fflush(stream)) {
            fprintf(stderr, "failed to write io_uring JSON output: %s\n",
                    strerror(errno ? errno : EIO));
            output->export_failed = true;
            exiting = 1;
        }
    } else {
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};

        print_event_time(event->timestamp_ns);
        printf("IO_URING request user_data=0x%016llx\n",
               (unsigned long long)event->user_data);
        printf("  SQE submit: PID %u/TID %u (%.*s) opcode=%s(%u)",
               event->submit_pid, event->submit_tid,
               (int)sizeof(event->submit_comm), event->submit_comm,
               operation, event->opcode);
        if (event->fd >= 0)
            printf(" fd=%d", event->fd);
        if (event->sq_thread)
            printf(" via=sqpoll");
        putchar('\n');
        printf("  CQE complete: global PID %u/TID %u (%.*s) "
               "result=%d",
               event->complete_global_pid, event->complete_global_tid,
               (int)sizeof(event->complete_comm), event->complete_comm,
               event->result);
        if (event->result < 0 && event->result >= -4095)
            printf(" (%s)", strerror(-event->result));
        printf(" flags=0x%x", event->cqe_flags);
        if (event->cqe_flags & IORING_CQE_F_MORE)
            printf(" [MORE]");
        putchar('\n');
        printf("  latency:");
        print_interval("SQE->CQE", event->duration_ns);
        putchar('\n');
        printf("  path: %s",
               event->io_wq ? "io-wq" :
               event->deferred ? "deferred" :
               event->poll_armed ? "poll" : "inline/async-device");
        if (event->io_wq_hashed)
            printf(" (hashed)");
        if (event->defer_delay_ns)
            print_interval("submit->defer",
                           event->defer_delay_ns);
        if (event->io_wq_queue_ns)
            print_interval("io-wq-queue",
                           event->io_wq_queue_ns);
        if (event->after_io_wq_ns)
            print_interval("worker-start->CQE",
                           event->after_io_wq_ns);
        putchar('\n');
        printf("  submit stack:\n");

        if (!exiting && event->stack_id >= 0 &&
            output->io_uring_stack_map_fd >= 0) {
            struct map_list *maps;

            if (bpf_map_lookup_elem(output->io_uring_stack_map_fd,
                                    &event->stack_id, stack)) {
                printf("  unable to read submitter stack %d: %s\n",
                       event->stack_id, strerror(errno));
            } else {
                maps = get_io_uring_maps(output, event);
                if (!maps) {
                    printf("  warning: cannot read submitter maps for "
                           "PID %u (global PID %u): %s\n",
                           event->submit_pid, event->submit_global_pid,
                           strerror(errno));
                } else {
                    print_stack_frames(stack, sizeof(stack), maps,
                                       "  ", NULL, NULL, 0);
                }
            }
        } else if (!exiting && event->sq_thread) {
            printf("    unavailable: request was issued by "
                   "an io_uring SQPOLL thread\n");
        } else if (!exiting) {
            printf("    unavailable\n");
        }
        putchar('\n');
    }

    if (exiting)
        return 0;
    output->emitted_events++;
    if (output->max_events &&
        output->emitted_events >= output->max_events) {
        exiting = 1;
    }
    return 0;
}

static int handle_io_uring_callback_event(
    void *context, void *data, size_t data_size)
{
    struct output_options *output = context;
    const struct io_uring_callback_event *event = data;
    const char *operation;

    if (data_size < sizeof(*event) || exiting)
        return 0;
    operation = io_uring_opcode_name(event->opcode);
    if (output->json_output) {
        FILE *stream = output->json_stream;
        uint64_t realtime_ns =
            event_realtime_nanoseconds(event->timestamp_ns);

        if (!stream)
            return 0;
        if (fprintf(
                stream,
                "{\"type\":\"io_uring_callback\","
                "\"timestamp_ns\":%llu,\"pid\":%u,\"tid\":%u,"
                "\"global_pid\":%u,\"global_tid\":%u,"
                "\"ring_ctx\":\"0x%016llx\","
                "\"request\":\"0x%016llx\","
                "\"user_data\":\"0x%016llx\","
                "\"opcode\":%u,\"operation\":",
                (unsigned long long)realtime_ns,
                event->pid, event->tid, event->global_pid,
                event->global_tid,
                (unsigned long long)event->ring_ctx,
                (unsigned long long)event->request,
                (unsigned long long)event->user_data,
                event->opcode) < 0 ||
            write_json_string(stream, operation, strlen(operation)) ||
            fprintf(
                stream,
                ",\"result\":%d,\"cqe_flags\":%u,"
                "\"request_duration_ns\":%llu,"
                "\"callback_delay_ns\":%llu,\"callback\":",
                event->result, event->cqe_flags,
                (unsigned long long)event->request_duration_ns,
                (unsigned long long)event->callback_delay_ns) < 0 ||
            write_json_string(
                stream, output->io_uring_callback_name,
                strlen(output->io_uring_callback_name)) ||
            fputs(",\"comm\":", stream) == EOF ||
            write_json_string(stream, event->comm,
                              sizeof(event->comm)) ||
            fputs("}\n", stream) == EOF ||
            fflush(stream)) {
            fprintf(stderr,
                    "failed to write io_uring callback JSON: %s\n",
                    strerror(errno ? errno : EIO));
            output->export_failed = true;
            exiting = 1;
        }
        return 0;
    }

    print_event_time(event->timestamp_ns);
    printf("IO_URING CQE -> callback user_data=0x%016llx "
           "opcode=%s(%u)\n",
           (unsigned long long)event->user_data,
           operation, event->opcode);
    printf("  callback: %s PID %u/TID %u (%.*s)",
           output->io_uring_callback_name,
           event->pid, event->tid,
           (int)sizeof(event->comm), event->comm);
    print_interval("CQE->callback", event->callback_delay_ns);
    putchar('\n');
    printf("  callback stack:\n");
    if (event->stack_id >= 0 && output->io_uring_stack_map_fd >= 0) {
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        struct io_uring_event map_event = {
            .submit_pid = event->pid,
            .submit_global_pid = event->global_pid,
        };
        struct map_list *maps;

        if (bpf_map_lookup_elem(output->io_uring_stack_map_fd,
                                &event->stack_id, stack)) {
            printf("    unavailable: cannot read stack %d: %s\n",
                   event->stack_id, strerror(errno));
        } else {
            maps = get_io_uring_maps(output, &map_event);
            if (maps)
                print_stack_frames(stack, sizeof(stack), maps,
                                   "  ", NULL, NULL, 0);
            else
                printf("    unavailable: process maps disappeared\n");
        }
    } else {
        printf("    unavailable\n");
    }
    putchar('\n');
    return 0;
}

static int compare_io_uring_aggregate_rows(const void *left,
                                           const void *right)
{
    const struct io_uring_aggregate_row *a = left;
    const struct io_uring_aggregate_row *b = right;
    uint64_t average_a;
    uint64_t average_b;

    if (a->value.maximum_ns < b->value.maximum_ns)
        return 1;
    if (a->value.maximum_ns > b->value.maximum_ns)
        return -1;
    average_a = a->value.count ?
        a->value.total_ns / a->value.count : 0;
    average_b = b->value.count ?
        b->value.total_ns / b->value.count : 0;
    if (average_a < average_b)
        return 1;
    if (average_a > average_b)
        return -1;
    return 0;
}

static size_t read_io_uring_aggregates(
    const struct output_options *output,
    struct io_uring_aggregate_row **rows)
{
    struct io_uring_aggregate_row *items = NULL;
    struct io_uring_aggregate_key current = {0};
    struct io_uring_aggregate_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_aggregate_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_aggregate_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_aggregate value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_aggregate_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 32;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].value = value;
        count++;
    }
    if (count > 1)
        qsort(items, count, sizeof(*items),
              compare_io_uring_aggregate_rows);
    *rows = items;
    return count;
}

static int compare_io_uring_result_rows(const void *left,
                                        const void *right)
{
    const struct io_uring_result_row *a = left;
    const struct io_uring_result_row *b = right;

    if (a->count < b->count)
        return 1;
    if (a->count > b->count)
        return -1;
    if (a->key.result > b->key.result)
        return 1;
    if (a->key.result < b->key.result)
        return -1;
    return 0;
}

static size_t read_io_uring_results(
    const struct output_options *output,
    struct io_uring_result_row **rows)
{
    struct io_uring_result_row *items = NULL;
    struct io_uring_result_key current = {0};
    struct io_uring_result_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_result_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_result_map_fd,
               have_current ? &current : NULL, &next)) {
        uint64_t value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_result_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 16;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].count = value;
        count++;
    }
    if (count > 1)
        qsort(items, count, sizeof(*items),
              compare_io_uring_result_rows);
    *rows = items;
    return count;
}

static bool io_uring_result_is_expected_timeout(
    const struct io_uring_result_key *key)
{
    return key->opcode == IORING_OP_TIMEOUT &&
           key->result == -ETIME;
}

static const char *errno_symbol(int error_number)
{
    if (error_number == EACCES)
        return "EACCES";
    if (error_number == EAGAIN)
        return "EAGAIN";
    if (error_number == EBADF)
        return "EBADF";
    if (error_number == ECANCELED)
        return "ECANCELED";
    if (error_number == ECONNREFUSED)
        return "ECONNREFUSED";
    if (error_number == EEXIST)
        return "EEXIST";
    if (error_number == EFAULT)
        return "EFAULT";
    if (error_number == EFBIG)
        return "EFBIG";
    if (error_number == EINTR)
        return "EINTR";
    if (error_number == EINVAL)
        return "EINVAL";
    if (error_number == EIO)
        return "EIO";
    if (error_number == EISDIR)
        return "EISDIR";
    if (error_number == EMFILE)
        return "EMFILE";
    if (error_number == ENFILE)
        return "ENFILE";
    if (error_number == ENOBUFS)
        return "ENOBUFS";
    if (error_number == ENODEV)
        return "ENODEV";
    if (error_number == ENOENT)
        return "ENOENT";
    if (error_number == ENOMEM)
        return "ENOMEM";
    if (error_number == ENOSPC)
        return "ENOSPC";
    if (error_number == ENOSYS)
        return "ENOSYS";
    if (error_number == ENXIO)
        return "ENXIO";
    if (error_number == EOPNOTSUPP)
        return "EOPNOTSUPP";
    if (error_number == EPERM)
        return "EPERM";
    if (error_number == EPIPE)
        return "EPIPE";
    if (error_number == ETIME)
        return "ETIME";
    if (error_number == ETIMEDOUT)
        return "ETIMEDOUT";
    return "ERRNO";
}

static void collect_io_uring_operation_summaries(
    const struct output_options *output,
    struct io_uring_operation_summary summaries[256])
{
    struct io_uring_aggregate_row *aggregates = NULL;
    struct io_uring_result_row *results = NULL;
    size_t aggregate_count;
    size_t result_count;
    size_t index;

    memset(summaries, 0, 256 * sizeof(*summaries));
    aggregate_count = read_io_uring_aggregates(output, &aggregates);
    for (index = 0; index < aggregate_count; index++) {
        const struct io_uring_aggregate_row *row = &aggregates[index];
        struct io_uring_operation_summary *summary;

        if (row->key.opcode >= 256)
            continue;
        summary = &summaries[row->key.opcode];
        summary->completions += row->value.count;
        summary->errors += row->value.errors;
        summary->total_ns += row->value.total_ns;
        summary->deferred += row->value.deferred_count;
        summary->io_wq += row->value.io_wq_count;
        summary->io_wq_queue_total_ns +=
            row->value.io_wq_queue_total_ns;
        if (row->value.maximum_ns > summary->maximum_ns)
            summary->maximum_ns = row->value.maximum_ns;
        if (row->value.io_wq_queue_maximum_ns >
            summary->io_wq_queue_maximum_ns)
            summary->io_wq_queue_maximum_ns =
                row->value.io_wq_queue_maximum_ns;
    }
    free(aggregates);

    result_count = read_io_uring_results(output, &results);
    for (index = 0; index < result_count; index++) {
        const struct io_uring_result_row *row = &results[index];
        struct io_uring_operation_summary *summary;

        if (row->key.opcode >= 256)
            continue;
        summary = &summaries[row->key.opcode];
        if (io_uring_result_is_expected_timeout(&row->key)) {
            summary->expected_timeouts += row->count;
        } else if (row->key.result < 0 &&
                   row->count > summary->top_error_count) {
            summary->top_error_result = row->key.result;
            summary->top_error_count = row->count;
        }
    }
    free(results);
}

static double io_uring_error_rate(uint64_t errors, uint64_t completions)
{
    if (!completions)
        return 0.0;
    return (double)errors * 100.0 / (double)completions;
}

static int compare_io_uring_error_code_summaries(
    const void *left, const void *right)
{
    const struct io_uring_error_code_summary *a = left;
    const struct io_uring_error_code_summary *b = right;

    if (a->count < b->count)
        return 1;
    if (a->count > b->count)
        return -1;
    if (a->result > b->result)
        return 1;
    if (a->result < b->result)
        return -1;
    return 0;
}

static size_t collect_io_uring_error_codes(
    const struct output_options *output,
    struct io_uring_error_code_summary **summaries)
{
    struct io_uring_result_row *rows = NULL;
    struct io_uring_error_code_summary *items = NULL;
    size_t row_count = read_io_uring_results(output, &rows);
    size_t capacity = 0;
    size_t count = 0;
    size_t row_index;

    *summaries = NULL;
    for (row_index = 0; row_index < row_count; row_index++) {
        const struct io_uring_result_row *row = &rows[row_index];
        size_t index;

        if (row->key.result >= 0 ||
            io_uring_result_is_expected_timeout(&row->key))
            continue;
        for (index = 0; index < count; index++) {
            if (items[index].result == row->key.result) {
                items[index].count += row->count;
                break;
            }
        }
        if (index < count)
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].result = row->key.result;
        items[count].count = row->count;
        count++;
    }
    free(rows);
    if (count > 1)
        qsort(items, count, sizeof(*items),
              compare_io_uring_error_code_summaries);
    *summaries = items;
    return count;
}

static bool format_proc_net_endpoint(
    const char *encoded, bool ipv6, char *buffer, size_t size)
{
    char address_text[INET6_ADDRSTRLEN];
    char copy[80];
    char *separator;
    unsigned long port;

    snprintf(copy, sizeof(copy), "%s", encoded);
    separator = strrchr(copy, ':');
    if (!separator)
        return false;
    *separator++ = '\0';
    errno = 0;
    port = strtoul(separator, NULL, 16);
    if (errno || port > UINT16_MAX)
        return false;
    if (!ipv6) {
        struct in_addr address;
        unsigned long raw = strtoul(copy, NULL, 16);

        if (strlen(copy) != 8 || raw > UINT32_MAX)
            return false;
        address.s_addr = (uint32_t)raw;
        if (!inet_ntop(AF_INET, &address, address_text,
                       sizeof(address_text)))
            return false;
        snprintf(buffer, size, "%s:%lu", address_text, port);
        return true;
    } else {
        struct in6_addr address = {0};
        size_t word;

        if (strlen(copy) != 32)
            return false;
        for (word = 0; word < 4; word++) {
            char hex[9] = {0};
            unsigned long raw;

            memcpy(hex, copy + word * 8, 8);
            raw = strtoul(hex, NULL, 16);
            if (raw > UINT32_MAX)
                return false;
            memcpy(address.s6_addr + word * 4, &raw, 4);
        }
        if (!inet_ntop(AF_INET6, &address, address_text,
                       sizeof(address_text)))
            return false;
        snprintf(buffer, size, "[%s]:%lu", address_text, port);
        return true;
    }
}

static bool lookup_proc_inet_socket(
    pid_t pid, unsigned long long inode, const char *table,
    const char *protocol, bool ipv6, char *buffer, size_t size)
{
    char path[80];
    char line[512];
    FILE *file;

    snprintf(path, sizeof(path), "/proc/%d/net/%s", (int)pid, table);
    file = fopen(path, "r");
    if (!file)
        return false;
    while (fgets(line, sizeof(line), file)) {
        char *tokens[16] = {0};
        char *save = NULL;
        char *token;
        size_t count = 0;
        unsigned long long row_inode;
        char local[INET6_ADDRSTRLEN + 16];
        char remote[INET6_ADDRSTRLEN + 16];

        for (token = strtok_r(line, " \t\r\n", &save);
             token && count < 16;
             token = strtok_r(NULL, " \t\r\n", &save))
            tokens[count++] = token;
        if (count <= 9)
            continue;
        row_inode = strtoull(tokens[9], NULL, 10);
        if (row_inode != inode)
            continue;
        if (!format_proc_net_endpoint(tokens[1], ipv6,
                                      local, sizeof(local)) ||
            !format_proc_net_endpoint(tokens[2], ipv6,
                                      remote, sizeof(remote)))
            continue;
        snprintf(buffer, size, "%s %s -> %s state=%s",
                 protocol, local, remote, tokens[3]);
        fclose(file);
        return true;
    }
    fclose(file);
    return false;
}

static bool lookup_proc_unix_socket(
    pid_t pid, unsigned long long inode, char *buffer, size_t size)
{
    char path[80];
    char line[512];
    FILE *file;

    snprintf(path, sizeof(path), "/proc/%d/net/unix", (int)pid);
    file = fopen(path, "r");
    if (!file)
        return false;
    while (fgets(line, sizeof(line), file)) {
        char *tokens[10] = {0};
        char *save = NULL;
        char *token;
        size_t count = 0;

        for (token = strtok_r(line, " \t\r\n", &save);
             token && count < 10;
             token = strtok_r(NULL, " \t\r\n", &save))
            tokens[count++] = token;
        if (count <= 6 || strtoull(tokens[6], NULL, 10) != inode)
            continue;
        snprintf(buffer, size, "unix %s",
                 count > 7 ? tokens[7] : "(anonymous)");
        fclose(file);
        return true;
    }
    fclose(file);
    return false;
}

static void enrich_socket_resource(
    pid_t pid, char *buffer, size_t size)
{
    unsigned long long inode;
    char endpoint[256];
    char original[64];
    bool found;

    if (sscanf(buffer, "socket:[%llu]", &inode) != 1)
        return;
    snprintf(original, sizeof(original), "%s", buffer);
    found =
        lookup_proc_inet_socket(pid, inode, "tcp", "tcp", false,
                                endpoint, sizeof(endpoint)) ||
        lookup_proc_inet_socket(pid, inode, "tcp6", "tcp6", true,
                                endpoint, sizeof(endpoint)) ||
        lookup_proc_inet_socket(pid, inode, "udp", "udp", false,
                                endpoint, sizeof(endpoint)) ||
        lookup_proc_inet_socket(pid, inode, "udp6", "udp6", true,
                                endpoint, sizeof(endpoint)) ||
        lookup_proc_unix_socket(pid, inode, endpoint,
                                sizeof(endpoint));
    if (found)
        snprintf(buffer, size, "%s %s", original, endpoint);
}

static void resolve_io_uring_fd_resource(
    const struct output_options *output, int fd,
    char *buffer, size_t size)
{
    char path[64];
    ssize_t length;

    if (!buffer || !size)
        return;
    buffer[0] = '\0';
    for (size_t index = 0;
         index < output->io_uring_resource_count; index++) {
        if (output->io_uring_resources[index].fd == fd) {
            snprintf(buffer, size, "%s",
                     output->io_uring_resources[index].path);
            return;
        }
    }
    if (fd < 0 || output->target_pid <= 0)
        return;
    snprintf(path, sizeof(path), "/proc/%d/fd/%d",
             (int)output->target_pid, fd);
    length = readlink(path, buffer, size - 1);
    if (length < 0) {
        buffer[0] = '\0';
        return;
    }
    buffer[length] = '\0';
    enrich_socket_resource(output->target_pid, buffer, size);
}

static void cache_io_uring_fd_resource(
    struct output_options *output, int fd)
{
    struct io_uring_fd_resource *resized;
    char resource[PATH_MAX];
    size_t next_capacity;

    if (fd < 0)
        return;
    for (size_t index = 0;
         index < output->io_uring_resource_count; index++) {
        if (output->io_uring_resources[index].fd == fd)
            return;
    }
    resolve_io_uring_fd_resource(
        output, fd, resource, sizeof(resource));
    if (!resource[0])
        return;
    if (output->io_uring_resource_count ==
        output->io_uring_resource_capacity) {
        next_capacity = output->io_uring_resource_capacity ?
            output->io_uring_resource_capacity * 2 : 16;
        resized = realloc(
            output->io_uring_resources,
            next_capacity * sizeof(*resized));
        if (!resized)
            return;
        output->io_uring_resources = resized;
        output->io_uring_resource_capacity = next_capacity;
    }
    output->io_uring_resources[
        output->io_uring_resource_count].fd = fd;
    snprintf(
        output->io_uring_resources[
            output->io_uring_resource_count].path,
        PATH_MAX, "%s", resource);
    output->io_uring_resource_count++;
}

static void cache_all_io_uring_fd_resources(
    struct output_options *output)
{
    char directory_path[64];
    struct dirent *entry;
    DIR *directory;

    if (output->target_pid <= 0)
        return;
    snprintf(directory_path, sizeof(directory_path), "/proc/%d/fd",
             (int)output->target_pid);
    directory = opendir(directory_path);
    if (!directory)
        return;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long fd;

        errno = 0;
        fd = strtol(entry->d_name, &end, 10);
        if (errno || end == entry->d_name || *end ||
            fd < 0 || fd > INT_MAX)
            continue;
        cache_io_uring_fd_resource(output, (int)fd);
    }
    closedir(directory);
}

static size_t read_io_uring_ring_rows(
    const struct output_options *output,
    struct io_uring_ring_row **rows)
{
    struct io_uring_ring_row *items = NULL;
    uint64_t current = 0;
    uint64_t next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_ring_stats_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_ring_stats_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_ring_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(
                output->io_uring_ring_stats_map_fd,
                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].ring_ctx = next;
        items[count].value = value;
        count++;
    }
    *rows = items;
    return count;
}

static size_t read_io_uring_failure_rows(
    const struct output_options *output,
    struct io_uring_failure_row **rows)
{
    struct io_uring_failure_row *items = NULL;
    struct io_uring_failure_key current = {0};
    struct io_uring_failure_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_failure_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_failure_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_failure_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_failure_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].value = value;
        count++;
    }
    *rows = items;
    return count;
}

static size_t read_io_uring_link_rows(
    const struct output_options *output,
    struct io_uring_link_row **rows)
{
    struct io_uring_link_row *items = NULL;
    struct io_uring_link_key current = {0};
    struct io_uring_link_key next;
    size_t capacity = 0;
    size_t count = 0;
    bool have_current = false;

    *rows = NULL;
    if (output->io_uring_link_map_fd < 0)
        return 0;
    while (!bpf_map_get_next_key(
               output->io_uring_link_map_fd,
               have_current ? &current : NULL, &next)) {
        struct io_uring_link_stats value;

        current = next;
        have_current = true;
        if (bpf_map_lookup_elem(output->io_uring_link_map_fd,
                                &next, &value))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            void *resized = realloc(
                items, next_capacity * sizeof(*items));

            if (!resized)
                break;
            items = resized;
            capacity = next_capacity;
        }
        items[count].key = next;
        items[count].value = value;
        count++;
    }
    *rows = items;
    return count;
}

static void format_io_uring_setup_flags(
    uint32_t flags, char *buffer, size_t size)
{
    bool first = true;

    if (!size)
        return;
    buffer[0] = '\0';
#define APPEND_RING_FLAG(flag, name)                                      \
    do {                                                                 \
        if (flags & (flag)) {                                            \
            snprintf(buffer + strlen(buffer), size - strlen(buffer),     \
                     "%s%s", first ? "" : "|", (name));                  \
            first = false;                                               \
        }                                                                \
    } while (0)
    APPEND_RING_FLAG(IORING_SETUP_SQPOLL, "SQPOLL");
    APPEND_RING_FLAG(IORING_SETUP_IOPOLL, "IOPOLL");
    APPEND_RING_FLAG(IORING_SETUP_ATTACH_WQ, "ATTACH_WQ");
    APPEND_RING_FLAG(IORING_SETUP_DEFER_TASKRUN, "DEFER_TASKRUN");
    APPEND_RING_FLAG(IORING_SETUP_SINGLE_ISSUER, "SINGLE_ISSUER");
    APPEND_RING_FLAG(IORING_SETUP_COOP_TASKRUN, "COOP_TASKRUN");
#undef APPEND_RING_FLAG
    if (first)
        snprintf(buffer, size, "default");
}

static void print_io_uring_diagnostic_sections(
    const struct output_options *output, FILE *stream,
    const struct io_uring_counters *counters)
{
    struct io_uring_ring_row *rings = NULL;
    struct io_uring_failure_row *failures = NULL;
    struct io_uring_link_row *links = NULL;
    size_t ring_count = read_io_uring_ring_rows(output, &rings);
    size_t failure_count =
        read_io_uring_failure_rows(output, &failures);
    size_t link_count = read_io_uring_link_rows(output, &links);
    uint64_t rejected_sqe_count = 0;
    size_t failure_limit;
    size_t link_limit = 0;
    size_t index;

    for (index = 0; index < failure_count; index++)
        rejected_sqe_count += failures[index].value.count;

    fprintf(stream,
            "\n[3] Application errors\n"
            "  These are errors observed in the target application, "
            "not callweave collection failures.\n"
            "  CQE execution errors : %llu (%.2f%% of completions)\n"
            "  Kernel-rejected SQEs : %llu\n"
            "  Expected timeouts    : %llu (reported separately, not errors)\n",
            (unsigned long long)counters->errors,
            io_uring_error_rate(counters->errors,
                                counters->completions),
            (unsigned long long)rejected_sqe_count,
            (unsigned long long)counters->expected_timeouts);
    if (failure_count) {
        failure_limit = failure_count < 10 ? failure_count : 10;
        fprintf(stream,
                "\n  Rejected SQE details "
                "(application submitted invalid/unsupported input)\n"
                "  %-18s %-14s %8s %18s %18s\n"
                "  %-18s %-14s %8s %18s %18s\n",
                "OPERATION", "KERNEL ERROR", "COUNT",
                "RING", "SAMPLE USER_DATA",
                "------------------", "--------------", "--------",
                "------------------", "------------------");
        for (index = 0; index < failure_limit; index++) {
            const struct io_uring_failure_row *row = &failures[index];
            int error_number = row->key.error < 0 ?
                -row->key.error : row->key.error;
            char operation[32];
            char error_text[32];

            snprintf(operation, sizeof(operation), "%s(%u)",
                     io_uring_opcode_name((uint8_t)row->key.opcode),
                     row->key.opcode);
            snprintf(error_text, sizeof(error_text), "%s(%d)",
                     errno_symbol(error_number), row->key.error);
            fprintf(stream,
                    "  %-18s %-14s %8llu 0x%016llx 0x%016llx\n"
                    "    sample SQE: len=%u off=%llu flags=0x%x "
                    "op_flags=0x%x buf=%u file_index=%u\n",
                    operation, error_text,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->key.ring_ctx,
                    (unsigned long long)row->value.user_data,
                    row->value.length,
                    (unsigned long long)row->value.offset,
                    row->value.sqe_flags,
                    row->value.operation_flags,
                    row->value.buffer_index,
                    row->value.file_index);
        }
        if (failure_count > failure_limit)
            fprintf(stream, "  ... %zu additional failure groups omitted\n",
                    failure_count - failure_limit);
    } else {
        fprintf(stream, "  Rejected SQE details: none observed\n");
    }

    fprintf(stream, "\n[4] Ring and queue health\n");
    if (!ring_count)
        fprintf(stream, "  No ring metadata was observed.\n");
    for (index = 0; index < ring_count; index++) {
        const struct io_uring_ring_stats *ring = &rings[index].value;
        char flags[128];
        char average[32];
        char maximum[32];
        char queue_average[32];
        char queue_maximum[32];
        const char *diagnosis = "healthy";

        format_io_uring_setup_flags(ring->flags, flags, sizeof(flags));
        format_interval(
            average, sizeof(average),
            ring->completions ?
                ring->total_ns / ring->completions : 0);
        format_interval(maximum, sizeof(maximum), ring->maximum_ns);
        format_interval(
            queue_average, sizeof(queue_average),
            ring->io_wq ?
                ring->io_wq_queue_total_ns / ring->io_wq : 0);
        format_interval(queue_maximum, sizeof(queue_maximum),
                        ring->io_wq_queue_maximum_ns);
        if (ring->cq_overflows)
            diagnosis = "CQ overflow / consumer too slow";
        else if (ring->io_wq_queue_maximum_ns >
                 ring->maximum_ns / 2 && ring->io_wq)
            diagnosis = "io-wq queue congestion";
        else if (ring->errors &&
                 io_uring_error_rate(ring->errors,
                                     ring->completions) >= 5.0)
            diagnosis = "high application CQE error rate";
        fprintf(stream, "  Ring %zu\n", index + 1);
        if (ring->ring_fd >= 0)
            fprintf(stream,
                    "    identity : ctx=0x%016llx fd=%d owner-pid=%u\n",
                    (unsigned long long)rings[index].ring_ctx,
                    ring->ring_fd, ring->owner_pid);
        else
            fprintf(stream,
                    "    identity : ctx=0x%016llx fd=unknown "
                    "owner-pid=%u\n",
                    (unsigned long long)rings[index].ring_ctx,
                    ring->owner_pid);
        fprintf(stream,
                "    setup    : sq=%u cq=%u flags=%s\n"
                "    load     : submitted=%llu completed=%llu "
                "pending=%llu peak-pending=%llu\n"
                "    latency  : average=%s maximum=%s\n",
                ring->sq_entries, ring->cq_entries, flags,
                (unsigned long long)ring->submitted,
                (unsigned long long)ring->completions,
                (unsigned long long)ring->pending,
                (unsigned long long)ring->peak_pending,
                average, maximum);
        fprintf(stream,
                "    path     : deferred=%llu io-wq=%llu hashed=%llu "
                "poll-armed=%llu\n"
                "    io-wq    : queue-average=%s queue-maximum=%s\n",
                (unsigned long long)ring->deferred,
                (unsigned long long)ring->io_wq,
                (unsigned long long)ring->io_wq_hashed,
                (unsigned long long)ring->poll_armed,
                queue_average, queue_maximum);
        fprintf(stream,
                "    cq       : waits=%llu overflows=%llu\n"
                "    app      : cqe-errors=%llu rejected-sqes=%llu "
                "links=%llu failed-links=%llu\n"
                "    diagnosis: %s\n",
                (unsigned long long)ring->cq_waits,
                (unsigned long long)ring->cq_overflows,
                (unsigned long long)ring->errors,
                (unsigned long long)ring->request_failures,
                (unsigned long long)ring->links,
                (unsigned long long)ring->failed_links,
                diagnosis);
    }

    fprintf(stream, "\n[5] Linked request chains\n");
    if (!link_count) {
        fprintf(stream, "  No linked requests were observed.\n");
    } else {
        link_limit = link_count < 10 ? link_count : 10;
        fprintf(stream,
                "  Showing %zu of %zu observed edge%s. "
                "These are application request dependencies.\n",
                link_limit, link_count, link_count == 1 ? "" : "s");
    }
    for (index = 0; index < link_count && index < link_limit; index++) {
        const struct io_uring_link_row *row = &links[index];

        fprintf(stream,
                "  [%2zu] %s user_data=0x%llx"
                " -> %s user_data=0x%llx%s\n"
                "       req=0x%llx -> req=0x%llx\n",
                index + 1,
                io_uring_opcode_name(row->value.parent_opcode),
                (unsigned long long)row->key.parent_user_data,
                io_uring_opcode_name(row->value.child_opcode),
                (unsigned long long)row->key.child_user_data,
                row->value.failures ? " [link failed/cancelled]" : "",
                (unsigned long long)row->value.parent_request,
                (unsigned long long)row->value.child_request);
    }
    if (link_count > link_limit)
        fprintf(stream, "  ... %zu additional edges omitted\n",
                link_count - link_limit);
    free(rings);
    free(failures);
    free(links);
}

static void print_io_uring_aggregates(struct output_options *output,
                                      FILE *stream)
{
    struct io_uring_aggregate_row *rows = NULL;
    size_t count = read_io_uring_aggregates(output, &rows);
    size_t limit = count;
    size_t index;

    fprintf(stream, "\n[6] Slowest submit groups\n");
    if (!output->io_uring_top) {
        fprintf(stream,
                "  Disabled. Use --io-top N to include Top-N groups.\n");
        free(rows);
        return;
    }
    if (!count) {
        fprintf(stream, "  No completed request groups were observed.\n");
        free(rows);
        return;
    }
    if (limit > output->io_uring_top)
        limit = output->io_uring_top;
    fprintf(stream,
            "  Top %zu by maximum SQE-to-CQE latency\n",
            limit);
    for (index = 0; index < limit; index++) {
        const struct io_uring_aggregate_row *row = &rows[index];
        uint64_t stack[MAX_ASYNC_STACK_DEPTH] = {0};
        size_t duplicate_index;
        char operation[32];
        char average[32];
        char maximum[32];
        char resource[PATH_MAX];

        if (force_exit)
            break;
        snprintf(operation, sizeof(operation), "%s(%u)",
                 io_uring_opcode_name((uint8_t)row->key.opcode),
                 row->key.opcode);
        format_interval(
            average, sizeof(average),
            row->value.count ?
                row->value.total_ns / row->value.count : 0);
        format_interval(maximum, sizeof(maximum),
                        row->value.maximum_ns);
        resolve_io_uring_fd_resource(
            output, row->key.fd, resource, sizeof(resource));
        fprintf(stream,
                "  [%2zu] %-20s ring=0x%llx fd=%-4d count=%-8llu "
                "errors=%-6llu avg=%-12s max=%-12s",
                index + 1,
                operation,
                (unsigned long long)row->key.ring_ctx,
                row->key.fd,
                (unsigned long long)row->value.count,
                (unsigned long long)row->value.errors,
                average, maximum);
        if (output->io_uring_min_latency_ns)
            fprintf(stream, " slow=%-8llu",
                    (unsigned long long)row->value.slow_count);
        if (resource[0])
            fprintf(stream, "\n       resource: %s", resource);
        if (row->value.deferred_count || row->value.io_wq_count) {
            char queue_average[32];
            char queue_maximum[32];

            format_interval(
                queue_average, sizeof(queue_average),
                row->value.io_wq_count ?
                    row->value.io_wq_queue_total_ns /
                        row->value.io_wq_count : 0);
            format_interval(
                queue_maximum, sizeof(queue_maximum),
                row->value.io_wq_queue_maximum_ns);
            fprintf(stream,
                    "\n       phases: deferred=%llu io-wq=%llu "
                    "io-wq-queue-avg=%s max=%s",
                    (unsigned long long)row->value.deferred_count,
                    (unsigned long long)row->value.io_wq_count,
                    queue_average, queue_maximum);
        }
        fprintf(stream, "\n       submit stack:\n");
        duplicate_index = index;
        if (row->key.stack_id >= 0) {
            size_t previous;

            for (previous = 0; previous < index; previous++) {
                if (rows[previous].key.stack_id ==
                    row->key.stack_id) {
                    duplicate_index = previous;
                    break;
                }
            }
        }
        if (duplicate_index < index) {
            fprintf(stream,
                    "         same as group [%zu] (stack_id=%d)\n",
                    duplicate_index + 1, row->key.stack_id);
        } else if (row->key.stack_id < 0 ||
            output->io_uring_stack_map_fd < 0 ||
            bpf_map_lookup_elem(output->io_uring_stack_map_fd,
                                &row->key.stack_id, stack)) {
            if (row->key.stack_id < 0)
                fprintf(stream,
                        "         capture unavailable (stack_id=%d)\n",
                        row->key.stack_id);
            else
                fprintf(stream, "         unavailable\n");
        } else if (output->io_uring_maps) {
            print_stack_frames(stack, sizeof(stack),
                               output->io_uring_maps,
                               "       ", NULL, NULL, 0);
        } else {
            fprintf(stream, "         submitter maps unavailable\n");
        }
    }
    free(rows);
}

static bool print_io_uring_summary(struct output_options *output)
{
    struct io_uring_counters counters = {0};
    struct io_uring_operation_summary summaries[256];
    FILE *stream = output->json_output ? stderr : stdout;
    uint32_t zero = 0;
    size_t opcode;

    if (output->io_uring_counters_map_fd < 0 ||
        bpf_map_lookup_elem(output->io_uring_counters_map_fd,
                            &zero, &counters))
        return false;

    collect_io_uring_operation_summaries(output, summaries);
    if (output->json_output) {
        fprintf(stream,
                "\nio_uring capture stopped: accepted=%llu "
                "completed=%llu errors=%llu rejected/unmatched=%llu "
                "dropped=%llu; structured summary written to JSON output\n",
                (unsigned long long)counters.submitted,
                (unsigned long long)counters.completions,
                (unsigned long long)counters.errors,
                (unsigned long long)counters.unmatched,
                (unsigned long long)counters.dropped_events);
        return true;
    }
    fprintf(stream,
            "\nio_uring summary\n"
            "\n[1] Capture overview\n"
            "  Accepted requests  : %llu\n"
            "  Completion events  : %llu\n"
            "  Finished requests  : %llu\n"
            "  Detailed records   : %u"
            " (after detail filters)\n"
            "  In flight at stop  : %llu\n"
            "  Peak in flight     : %llu\n",
            (unsigned long long)counters.submitted,
            (unsigned long long)counters.completions,
            (unsigned long long)counters.finished,
            output->emitted_events,
            (unsigned long long)counters.pending,
            (unsigned long long)counters.peak_pending);
    fprintf(stream,
            "\n[2] Operation latency and CQE results\n"
            "  %-20s %8s %8s %9s %9s %12s %12s  %s\n",
            "OPERATION", "CQEs", "CQE ERR", "ERR RATE",
            "TIMEOUTS", "AVG", "MAX", "TOP CQE ERROR");
    fprintf(stream,
            "  %-20s %8s %8s %9s %9s %12s %12s  %s\n",
            "--------------------", "--------", "--------",
            "---------", "---------", "------------",
            "------------", "--------------------");
    for (opcode = 0; opcode < 256; opcode++) {
        const struct io_uring_operation_summary *summary =
            &summaries[opcode];
        char operation[32];
        char error_rate[32];
        char average[32];
        char maximum[32];
        char top_error[64] = "-";

        if (!summary->completions)
            continue;
        snprintf(operation, sizeof(operation), "%s(%zu)",
                 io_uring_opcode_name((uint8_t)opcode), opcode);
        snprintf(error_rate, sizeof(error_rate), "%.2f%%",
                 io_uring_error_rate(summary->errors,
                                     summary->completions));
        format_interval(average, sizeof(average),
                        summary->total_ns / summary->completions);
        format_interval(maximum, sizeof(maximum),
                        summary->maximum_ns);
        if (summary->top_error_count) {
            int error_number = -summary->top_error_result;

            snprintf(top_error, sizeof(top_error), "%s(%d) x%llu",
                     errno_symbol(error_number),
                     summary->top_error_result,
                     (unsigned long long)summary->top_error_count);
        }
        fprintf(stream,
                "  %-20s %8llu %8llu %9s %9llu %12s %12s  %s\n",
                operation,
                (unsigned long long)summary->completions,
                (unsigned long long)summary->errors,
                error_rate,
                (unsigned long long)summary->expected_timeouts,
                average, maximum, top_error);
        if (summary->deferred || summary->io_wq) {
            char queue_average[32];
            char queue_maximum[32];

            format_interval(
                queue_average, sizeof(queue_average),
                summary->io_wq ?
                    summary->io_wq_queue_total_ns /
                        summary->io_wq : 0);
            format_interval(
                queue_maximum, sizeof(queue_maximum),
                summary->io_wq_queue_maximum_ns);
            fprintf(stream,
                    "    phases: deferred=%llu io-wq=%llu "
                    "io-wq-queue avg=%s max=%s\n",
                    (unsigned long long)summary->deferred,
                    (unsigned long long)summary->io_wq,
                    queue_average, queue_maximum);
        }
    }
    if (!output->json_output)
        print_io_uring_diagnostic_sections(output, stream, &counters);
    if (!output->json_output)
        print_io_uring_aggregates(output, stream);
    if (!output->json_output) {
        fprintf(stream,
                "\n[7] Correlation and collector health\n"
                "  Request correlation : unmatched completions=%llu\n"
                "  Event transport     : dropped detail events=%llu\n",
                (unsigned long long)counters.unmatched,
                (unsigned long long)counters.dropped_events);
        if (output->io_uring_callback_name)
            fprintf(stream,
                    "  Callback correlation: matched=%llu "
                    "unmatched=%llu dropped=%llu\n",
                    (unsigned long long)counters.callback_matched,
                    (unsigned long long)counters.callback_unmatched,
                    (unsigned long long)counters.callback_dropped);
        if (counters.unmatched ||
            counters.callback_unmatched)
            fprintf(stream,
                    "  Note: kernel-rejected SQEs can increase unmatched "
                    "counts because they never reach io_uring_submit_req; "
                    "see [3].\n");
        if (!counters.dropped_events &&
            !counters.callback_dropped)
            fprintf(stream,
                    "  Collector status    : no ring-buffer event loss "
                    "observed\n");
    }
    return true;
}

static int write_io_uring_summary_json(struct output_options *output)
{
    struct io_uring_counters counters = {0};
    struct io_uring_operation_summary summaries[256];
    struct io_uring_aggregate_row *rows = NULL;
    struct io_uring_error_code_summary *error_codes = NULL;
    size_t aggregate_count;
    size_t aggregate_limit;
    size_t aggregate_index;
    size_t error_code_count;
    size_t error_code_index;
    uint32_t zero = 0;
    size_t opcode;
    bool first = true;

    if (!output->json_stream ||
        output->io_uring_counters_map_fd < 0 ||
        bpf_map_lookup_elem(output->io_uring_counters_map_fd,
                            &zero, &counters))
        return 0;
    collect_io_uring_operation_summaries(output, summaries);
    if (fprintf(output->json_stream,
                "{\"type\":\"io_uring_summary\","
                "\"displayed\":%u,\"submitted\":%llu,"
                "\"completions\":%llu,"
                "\"finished\":%llu,\"pending\":%llu,"
                "\"peak_pending\":%llu,\"unmatched\":%llu,"
                "\"dropped_events\":%llu,\"errors\":%llu,"
                "\"error_rate_percent\":%.6f,"
                "\"expected_timeouts\":%llu,"
                "\"callback_matched\":%llu,"
                "\"callback_unmatched\":%llu,"
                "\"callback_dropped\":%llu,"
                "\"operations\":[",
                output->emitted_events,
                (unsigned long long)counters.submitted,
                (unsigned long long)counters.completions,
                (unsigned long long)counters.finished,
                (unsigned long long)counters.pending,
                (unsigned long long)counters.peak_pending,
                (unsigned long long)counters.unmatched,
                (unsigned long long)counters.dropped_events,
                (unsigned long long)counters.errors,
                io_uring_error_rate(counters.errors,
                                    counters.completions),
                (unsigned long long)counters.expected_timeouts,
                (unsigned long long)counters.callback_matched,
                (unsigned long long)counters.callback_unmatched,
                (unsigned long long)counters.callback_dropped) < 0)
        return -1;
    for (opcode = 0; opcode < 256; opcode++) {
        const struct io_uring_operation_summary *summary =
            &summaries[opcode];
        const char *name;

        if (!summary->completions)
            continue;
        name = io_uring_opcode_name((uint8_t)opcode);
        if ((!first && fputc(',', output->json_stream) == EOF) ||
            fprintf(output->json_stream,
                    "{\"opcode\":%zu,\"operation\":", opcode) < 0 ||
            write_json_string(output->json_stream, name, strlen(name)) ||
            fprintf(output->json_stream,
                    ",\"completions\":%llu,\"errors\":%llu,"
                    "\"error_rate_percent\":%.6f,"
                    "\"expected_timeouts\":%llu,"
                    "\"average_ns\":%llu,\"maximum_ns\":%llu,"
                    "\"deferred\":%llu,\"io_wq\":%llu,"
                    "\"io_wq_queue_average_ns\":%llu,"
                    "\"io_wq_queue_maximum_ns\":%llu,"
                    "\"top_error_result\":%d,"
                    "\"top_error_count\":%llu}",
                    (unsigned long long)summary->completions,
                    (unsigned long long)summary->errors,
                    io_uring_error_rate(summary->errors,
                                        summary->completions),
                    (unsigned long long)summary->expected_timeouts,
                    (unsigned long long)
                        (summary->total_ns / summary->completions),
                    (unsigned long long)summary->maximum_ns,
                    (unsigned long long)summary->deferred,
                    (unsigned long long)summary->io_wq,
                    (unsigned long long)
                        (summary->io_wq ?
                             summary->io_wq_queue_total_ns /
                                 summary->io_wq : 0),
                    (unsigned long long)
                        summary->io_wq_queue_maximum_ns,
                    summary->top_error_result,
                    (unsigned long long)summary->top_error_count) < 0)
            return -1;
        first = false;
    }
    if (fputs("],\"error_codes\":[", output->json_stream) == EOF)
        return -1;
    error_code_count =
        collect_io_uring_error_codes(output, &error_codes);
    for (error_code_index = 0;
         error_code_index < error_code_count; error_code_index++) {
        const struct io_uring_error_code_summary *summary =
            &error_codes[error_code_index];
        int error_number;
        const char *symbol;

        error_number = -summary->result;
        symbol = errno_symbol(error_number);
        if ((error_code_index &&
             fputc(',', output->json_stream) == EOF) ||
            fprintf(output->json_stream,
                    "{\"result\":%d,\"errno\":%d,\"name\":",
                    summary->result, error_number) < 0 ||
            write_json_string(output->json_stream, symbol,
                              strlen(symbol)) ||
            fputs(",\"message\":", output->json_stream) == EOF ||
            write_json_string(output->json_stream,
                              strerror(error_number),
                              strlen(strerror(error_number))) ||
            fprintf(output->json_stream, ",\"count\":%llu}",
                    (unsigned long long)summary->count) < 0) {
            free(error_codes);
            return -1;
        }
    }
    free(error_codes);
    if (fputs("],\"aggregates\":[", output->json_stream) == EOF)
        return -1;
    aggregate_count = read_io_uring_aggregates(output, &rows);
    aggregate_limit = aggregate_count;
    if (aggregate_limit > output->io_uring_top)
        aggregate_limit = output->io_uring_top;
    for (aggregate_index = 0;
         aggregate_index < aggregate_limit; aggregate_index++) {
        const struct io_uring_aggregate_row *row =
            &rows[aggregate_index];
        const char *name =
            io_uring_opcode_name((uint8_t)row->key.opcode);
        char resource[PATH_MAX];

        resolve_io_uring_fd_resource(
            output, row->key.fd, resource, sizeof(resource));
        if ((aggregate_index &&
             fputc(',', output->json_stream) == EOF) ||
            fprintf(output->json_stream,
                    "{\"rank\":%zu,\"opcode\":%u,\"operation\":",
                    aggregate_index + 1, row->key.opcode) < 0 ||
            write_json_string(output->json_stream, name,
                              strlen(name)) ||
            fprintf(output->json_stream,
                    ",\"ring_ctx\":\"0x%016llx\","
                    "\"fd\":%d,\"stack_id\":%d,"
                    "\"count\":%llu,\"errors\":%llu,"
                    "\"slow_count\":%llu,\"average_ns\":%llu,"
                    "\"maximum_ns\":%llu,\"deferred\":%llu,"
                    "\"io_wq\":%llu,"
                    "\"io_wq_queue_average_ns\":%llu,"
                    "\"io_wq_queue_maximum_ns\":%llu,"
                    "\"resource\":",
                    (unsigned long long)row->key.ring_ctx,
                    row->key.fd, row->key.stack_id,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->value.errors,
                    (unsigned long long)row->value.slow_count,
                    (unsigned long long)
                        (row->value.count ?
                             row->value.total_ns / row->value.count : 0),
                    (unsigned long long)row->value.maximum_ns,
                    (unsigned long long)row->value.deferred_count,
                    (unsigned long long)row->value.io_wq_count,
                    (unsigned long long)
                        (row->value.io_wq_count ?
                             row->value.io_wq_queue_total_ns /
                                 row->value.io_wq_count : 0),
                    (unsigned long long)
                        row->value.io_wq_queue_maximum_ns) < 0 ||
            write_json_string(output->json_stream, resource,
                              strlen(resource)) ||
            fputc('}', output->json_stream) == EOF) {
            free(rows);
            return -1;
        }
    }
    free(rows);
    {
        struct io_uring_ring_row *rings = NULL;
        size_t count = read_io_uring_ring_rows(output, &rings);
        size_t index;

        if (fputs("],\"rings\":[", output->json_stream) == EOF) {
            free(rings);
            return -1;
        }
        for (index = 0; index < count; index++) {
            const struct io_uring_ring_stats *ring =
                &rings[index].value;

            if ((index &&
                 fputc(',', output->json_stream) == EOF) ||
                fprintf(
                    output->json_stream,
                    "{\"ring_ctx\":\"0x%016llx\",\"owner_pid\":%u,"
                    "\"fd\":%d,\"flags\":%u,\"sq_entries\":%u,"
                    "\"cq_entries\":%u,\"submitted\":%llu,"
                    "\"completions\":%llu,\"pending\":%llu,"
                    "\"peak_pending\":%llu,\"errors\":%llu,"
                    "\"expected_timeouts\":%llu,\"average_ns\":%llu,"
                    "\"maximum_ns\":%llu,\"deferred\":%llu,"
                    "\"io_wq\":%llu,\"io_wq_hashed\":%llu,"
                    "\"io_wq_queue_average_ns\":%llu,"
                    "\"io_wq_queue_maximum_ns\":%llu,"
                    "\"poll_armed\":%llu,\"cq_waits\":%llu,"
                    "\"cq_overflows\":%llu,\"request_failures\":%llu,"
                    "\"links\":%llu,\"failed_links\":%llu,"
                    "\"registrations\":%llu,"
                    "\"registered_files\":%u,"
                    "\"registered_buffers\":%u}",
                    (unsigned long long)rings[index].ring_ctx,
                    ring->owner_pid, ring->ring_fd, ring->flags,
                    ring->sq_entries, ring->cq_entries,
                    (unsigned long long)ring->submitted,
                    (unsigned long long)ring->completions,
                    (unsigned long long)ring->pending,
                    (unsigned long long)ring->peak_pending,
                    (unsigned long long)ring->errors,
                    (unsigned long long)ring->expected_timeouts,
                    (unsigned long long)
                        (ring->completions ?
                             ring->total_ns / ring->completions : 0),
                    (unsigned long long)ring->maximum_ns,
                    (unsigned long long)ring->deferred,
                    (unsigned long long)ring->io_wq,
                    (unsigned long long)ring->io_wq_hashed,
                    (unsigned long long)
                        (ring->io_wq ?
                             ring->io_wq_queue_total_ns /
                                 ring->io_wq : 0),
                    (unsigned long long)
                        ring->io_wq_queue_maximum_ns,
                    (unsigned long long)ring->poll_armed,
                    (unsigned long long)ring->cq_waits,
                    (unsigned long long)ring->cq_overflows,
                    (unsigned long long)ring->request_failures,
                    (unsigned long long)ring->links,
                    (unsigned long long)ring->failed_links,
                    (unsigned long long)ring->registrations,
                    ring->registered_files,
                    ring->registered_buffers) < 0) {
                free(rings);
                return -1;
            }
        }
        free(rings);
    }
    {
        struct io_uring_failure_row *failures = NULL;
        size_t count =
            read_io_uring_failure_rows(output, &failures);
        size_t index;

        if (fputs("],\"submission_failures\":[",
                  output->json_stream) == EOF) {
            free(failures);
            return -1;
        }
        for (index = 0; index < count; index++) {
            const struct io_uring_failure_row *row =
                &failures[index];

            if ((index &&
                 fputc(',', output->json_stream) == EOF) ||
                fprintf(
                    output->json_stream,
                    "{\"ring_ctx\":\"0x%016llx\",\"opcode\":%u,"
                    "\"operation\":",
                    (unsigned long long)row->key.ring_ctx,
                    row->key.opcode) < 0 ||
                write_json_string(
                    output->json_stream,
                    io_uring_opcode_name(
                        (uint8_t)row->key.opcode),
                    strlen(io_uring_opcode_name(
                        (uint8_t)row->key.opcode))) ||
                fprintf(
                    output->json_stream,
                    ",\"error\":%d,\"count\":%llu,"
                    "\"user_data\":\"0x%016llx\",\"offset\":%llu,"
                    "\"address\":\"0x%016llx\","
                    "\"address3\":\"0x%016llx\",\"length\":%u,"
                    "\"operation_flags\":%u,\"file_index\":%u,"
                    "\"buffer_index\":%u,\"sqe_flags\":%u,"
                    "\"ioprio\":%u}",
                    row->key.error,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->value.user_data,
                    (unsigned long long)row->value.offset,
                    (unsigned long long)row->value.address,
                    (unsigned long long)row->value.address3,
                    row->value.length,
                    row->value.operation_flags,
                    row->value.file_index,
                    row->value.buffer_index,
                    row->value.sqe_flags,
                    row->value.ioprio) < 0) {
                free(failures);
                return -1;
            }
        }
        free(failures);
    }
    {
        struct io_uring_link_row *links = NULL;
        size_t count = read_io_uring_link_rows(output, &links);
        size_t index;

        if (fputs("],\"links\":[", output->json_stream) == EOF) {
            free(links);
            return -1;
        }
        for (index = 0; index < count; index++) {
            const struct io_uring_link_row *row = &links[index];

            if ((index &&
                 fputc(',', output->json_stream) == EOF) ||
                fprintf(
                    output->json_stream,
                    "{\"ring_ctx\":\"0x%016llx\","
                    "\"parent_request\":\"0x%016llx\","
                    "\"parent_user_data\":\"0x%016llx\","
                    "\"parent_opcode\":%u,"
                    "\"child_request\":\"0x%016llx\","
                    "\"child_user_data\":\"0x%016llx\","
                    "\"child_opcode\":%u,\"count\":%llu,"
                    "\"failures\":%llu}",
                    (unsigned long long)row->key.ring_ctx,
                    (unsigned long long)row->value.parent_request,
                    (unsigned long long)row->key.parent_user_data,
                    row->value.parent_opcode,
                    (unsigned long long)row->value.child_request,
                    (unsigned long long)row->key.child_user_data,
                    row->value.child_opcode,
                    (unsigned long long)row->value.count,
                    (unsigned long long)row->value.failures) < 0) {
                free(links);
                return -1;
            }
        }
        free(links);
    }
    return fputs("]}\n", output->json_stream) == EOF ? -1 : 0;
}

static const char *futex_operation_name(uint32_t operation)
{
    switch (operation) {
    case 0:
        return "wait";
    case 9:
        return "wait-bitset";
    default:
        return "wait";
    }
}

static void print_wait_resource(const struct wait_resource *wait,
                                const struct output_options *output,
                                const char *indent)
{
    struct map_list waker_maps = {0};
    uint64_t waker_stack[MAX_ASYNC_STACK_DEPTH] = {0};
    uint32_t maps_pid;

    if (wait->kind != WAIT_KIND_FUTEX || !wait->duration_ns)
        return;
    printf("%swait=futex operation=%s address=0x%016llx",
           indent, futex_operation_name(wait->operation),
           (unsigned long long)wait->address);
    print_interval("duration", wait->duration_ns);
    putchar('\n');
    if (!wait->waker_tid) {
        printf("%s  waker=unobserved (timeout, signal, or unmatched wake)\n",
               indent);
        return;
    }

    printf("%s  waker PID %u/TID %u (%.*s)",
           indent, wait->waker_pid, wait->waker_tid,
           (int)sizeof(wait->waker_comm), wait->waker_comm);
    if (wait->wake_ns)
        print_interval("wake-after-wait-start", wait->wake_ns);
    putchar('\n');
    if (wait->waker_pid != wait->waker_global_pid ||
        wait->waker_tid != wait->waker_global_tid)
        printf("%s  waker global PID %u/TID %u\n", indent,
               wait->waker_global_pid, wait->waker_global_tid);
    if (wait->waker_pidns_error)
        printf("%s  waker PID namespace translation failed: %s (%d)\n",
               indent, strerror(-wait->waker_pidns_error),
               wait->waker_pidns_error);
    if (wait->waker_stack_id < 0) {
        printf("%s  unable to collect waker user stack: %s (%d)\n",
               indent, strerror(-wait->waker_stack_id),
               wait->waker_stack_id);
        return;
    }
    if (output->wait_stack_map_fd < 0) {
        printf("%s  waker stack map is unavailable\n", indent);
        return;
    }
    if (bpf_map_lookup_elem(output->wait_stack_map_fd,
                            &wait->waker_stack_id, waker_stack)) {
        printf("%s  waker stack id %d is unavailable: %s\n",
               indent, wait->waker_stack_id, strerror(errno));
        return;
    }

    maps_pid = wait->waker_pid;
    if (read_process_maps(maps_pid, &waker_maps) &&
        wait->waker_global_pid != maps_pid) {
        map_list_free(&waker_maps);
        maps_pid = wait->waker_global_pid;
        read_process_maps(maps_pid, &waker_maps);
    }
    print_stack_frames(waker_stack, sizeof(waker_stack), &waker_maps,
                       "waker ", NULL, NULL, 0);
    map_list_free(&waker_maps);
}

static bool has_async_chain_filters(const struct output_options *output)
{
    return output->min_total_ns || output->min_queue_ns ||
           output->min_work_ns || output->max_events;
}

static bool async_chain_matches(const struct stack_trace_event *event,
                                const struct output_options *output)
{
    uint64_t total_ns = 0;
    uint64_t maximum_queue_ns = 0;
    uint64_t maximum_work_ns = 0;
    uint32_t count = event->async_hop_count;
    uint32_t index;

    if (!count)
        return false;
    if (count > MAX_ASYNC_HOPS)
        count = MAX_ASYNC_HOPS;
    for (index = 0; index < count; index++) {
        const struct async_hop_event *hop = &event->async_hops[index];

        if (UINT64_MAX - total_ns < hop->queue_ns)
            total_ns = UINT64_MAX;
        else
            total_ns += hop->queue_ns;
        if (UINT64_MAX - total_ns < hop->target_ns)
            total_ns = UINT64_MAX;
        else
            total_ns += hop->target_ns;
        if (hop->queue_ns > maximum_queue_ns)
            maximum_queue_ns = hop->queue_ns;
        if (hop->target_ns > maximum_work_ns)
            maximum_work_ns = hop->target_ns;
    }

    return total_ns >= output->min_total_ns &&
           maximum_queue_ns >= output->min_queue_ns &&
           maximum_work_ns >= output->min_work_ns;
}

static uint64_t event_realtime_milliseconds(uint64_t timestamp_ns)
{
    return event_realtime_nanoseconds(timestamp_ns) / 1000000ULL;
}

static void copy_report_comm(char destination[17],
                             const char source[16])
{
    memcpy(destination, source, 16);
    destination[16] = '\0';
}

static void build_report_chain(const struct stack_trace_event *event,
                               const struct output_options *output,
                               struct cw_report_chain *chain)
{
    uint32_t hop_count = event->async_hop_count;
    uint32_t hop_index;

    memset(chain, 0, sizeof(*chain));
    chain->timestamp_ms =
        event_realtime_milliseconds(event->timestamp_ns);
    chain->pid = event->pid;
    chain->tid = event->tid;
    copy_report_comm(chain->comm, event->comm);
    chain->duration_ns = event->duration_ns;
    chain->offcpu_ns = event->offcpu_ns;
    chain->blocked_ns = event->blocked_ns;
    chain->runqueue_ns = event->runqueue_ns;
    chain->truncated = event->async_truncated;
    if (hop_count > CW_REPORT_MAX_HOPS)
        hop_count = CW_REPORT_MAX_HOPS;
    chain->hop_count = hop_count;

    for (hop_index = 0; hop_index < hop_count; hop_index++) {
        const struct async_hop_event *source =
            &event->async_hops[hop_index];
        struct cw_report_hop *destination =
            &chain->hops[hop_index];
        uint32_t hop_id = source->reserved & ASYNC_HOP_ID_MASK;
        uint32_t configured_hop =
            hop_id ? hop_id - 1 : hop_index;

        destination->index = configured_hop;
        destination->pid = source->pid;
        destination->tid = source->tid;
        destination->target_tid =
            hop_index + 1 < hop_count ?
                event->async_hops[hop_index + 1].tid : event->tid;
        destination->target_arg =
            source->reserved >> ASYNC_TARGET_ARG_SHIFT;
        copy_report_comm(destination->comm, source->comm);
        if (configured_hop < output->async_hop_count) {
            destination->source =
                output->async_hops[configured_hop].source;
            destination->target =
                output->async_hops[configured_hop].target;
        } else {
            destination->source =
                output->async_source_name ?
                    output->async_source_name : "source";
            destination->target =
                output->final_target_name ?
                    output->final_target_name : "target";
        }
        destination->key = source->key;
        destination->queue_ns = source->queue_ns;
        destination->work_ns = source->target_ns;
        destination->offcpu_ns = source->offcpu_ns;
        destination->blocked_ns = source->blocked_ns;
        destination->runqueue_ns = source->runqueue_ns;
        destination->wait_kind = source->wait.kind;
        destination->wait_operation = source->wait.operation;
        destination->wait_address = source->wait.address;
        destination->wait_duration_ns = source->wait.duration_ns;
        destination->wait_wake_ns = source->wait.wake_ns;
        destination->waker_pid = source->wait.waker_pid;
        destination->waker_tid = source->wait.waker_tid;
        copy_report_comm(destination->waker_comm,
                         source->wait.waker_comm);
    }
}

static void export_completed_chain(const struct stack_trace_event *event,
                                   struct output_options *output)
{
    struct cw_report_chain chain;
    bool failed = false;

    if ((!output->json_stream && !output->report_stream) ||
        output->export_failed)
        return;
    build_report_chain(event, output, &chain);
    if (output->json_stream) {
        failed = cw_write_chain_json(output->json_stream, &chain) ||
                 fputc('\n', output->json_stream) == EOF ||
                 fflush(output->json_stream);
    }
    if (!failed && output->report_stream) {
        failed = cw_html_report_write(output->report_stream, &chain,
                                      &output->report_first) ||
                 fflush(output->report_stream);
    }
    if (failed) {
        fprintf(stderr, "failed to write trace export: %s\n",
                strerror(errno ? errno : EIO));
        output->export_failed = true;
        exiting = 1;
    }
}

static void count_completed_chain(struct output_options *output)
{
    output->emitted_events++;
    if (output->max_events &&
        output->emitted_events >= output->max_events)
        exiting = 1;
}

static int handle_event(void *context, void *data, size_t data_size)
{
    const struct stack_trace_event *event = data;
    struct output_options *output = context;
    struct map_list maps = {0};
    size_t header_size = offsetof(struct stack_trace_event, stack);
    size_t entry_size = sizeof(*event);
    uint32_t maps_pid;

    if (output->max_events &&
        output->emitted_events >= output->max_events)
        return 0;
    if (data_size < header_size) {
        fprintf(stderr,
                "short event header received: %zu bytes (expected %zu)\n",
                data_size, header_size);
        return 0;
    }
    if (output->show_async && has_async_chain_filters(output)) {
        if (event->event_type == EVENT_ENTRY)
            return 0;
        if (event->event_type == EVENT_RETURN &&
            !async_chain_matches(event, output))
            return 0;
    }
    if (event->event_type == EVENT_RETURN && event->async_hop_count) {
        export_completed_chain(event, output);
        if (output->json_output) {
            count_completed_chain(output);
            return 0;
        }
    } else if (output->json_output) {
        return 0;
    }
    maps_pid = event->pid;

    print_event_time(event->timestamp_ns);
    printf("PID %u/TID %u (%.*s)", event->pid, event->tid,
           (int)sizeof(event->comm), event->comm);
    if (event->event_type == EVENT_RETURN) {
        printf(" RETURN");
        if (output->show_return_value)
            printf(" ret=0x%016llx (%lld)",
                   (unsigned long long)(uint64_t)event->return_value,
                   (long long)event->return_value);
        if (output->show_duration)
            print_interval("duration", event->duration_ns);
        if (output->show_attribution)
            print_attribution(event->duration_ns, event->offcpu_ns,
                              event->blocked_ns, event->runqueue_ns, false);
        putchar('\n');
        if (output->show_attribution &&
            !(output->show_async && event->async_hop_count))
            print_wait_resource(&event->wait, output, "  ");
    } else {
        if (output->show_return_value || output->show_duration)
            printf(" ENTRY");
        putchar('\n');
    }
    if (event->pidns_error) {
        fprintf(stderr,
                "warning: PID namespace translation failed: %s (%d); "
                "using global PID %u\n",
                strerror(-event->pidns_error), event->pidns_error,
                event->global_pid);
    } else if (event->pid != event->global_pid ||
               event->tid != event->global_tid) {
        printf("  global PID %u/TID %u\n",
               event->global_pid, event->global_tid);
    }
    fflush(stdout);

    if (event->event_type != EVENT_ENTRY) {
        if (event->event_type != EVENT_RETURN) {
            fprintf(stderr, "unknown event type: %u\n", event->event_type);
            return 0;
        }
    }
    if (event->event_type == EVENT_ENTRY && data_size < entry_size) {
        fprintf(stderr, "short entry event received: %zu bytes (expected %zu)\n",
                data_size, entry_size);
        return 0;
    }
    if ((event->event_type == EVENT_ENTRY ||
         (output->show_async && event->async_hop_count)) &&
        read_process_maps(maps_pid, &maps)) {
        int maps_error = errno;

        if (event->global_pid != maps_pid) {
            map_list_free(&maps);
            if (!read_process_maps(event->global_pid, &maps)) {
                maps_pid = event->global_pid;
                printf("  using global /proc/%u/maps\n", maps_pid);
                maps_error = 0;
            }
        }
        if (maps_error) {
            fflush(stdout);
            fprintf(stderr, "warning: cannot read /proc/%u/maps: %s\n",
                    maps_pid, strerror(maps_error));
        }
    }

    if (output->show_async && event->async_hop_count) {
        uint32_t hop_count = event->async_hop_count;
        uint32_t hop_index;

        if (hop_count > MAX_ASYNC_HOPS)
            hop_count = MAX_ASYNC_HOPS;
        if (event->async_truncated)
            printf("  ... %u earlier async hop(s) truncated ...\n",
                   event->async_truncated);
        for (hop_index = 0; hop_index < hop_count; hop_index++) {
            const struct async_hop_event *hop =
                &event->async_hops[hop_index];
            uint64_t async_stack[MAX_ASYNC_STACK_DEPTH] = {0};
            uint32_t hop_id = hop->reserved & ASYNC_HOP_ID_MASK;
            uint32_t configured_hop =
                hop_id ? hop_id - 1 : hop_index;
            uint32_t matched_target_arg =
                hop->reserved >> ASYNC_TARGET_ARG_SHIFT;

            const char *source_name = output->async_source_name;
            const char *target_name = output->final_target_name;

            if (configured_hop < output->async_hop_count) {
                source_name = output->async_hops[configured_hop].source;
                target_name = output->async_hops[configured_hop].target;
            }
            printf("  async hop %u %s -> %s PID %u/TID %u (%.*s) "
                   "key=0x%016llx target-arg=%u\n",
                   configured_hop,
                   source_name ? source_name : "source",
                   target_name ? target_name : "target",
                   hop->pid, hop->tid,
                   (int)sizeof(hop->comm), hop->comm,
                   (unsigned long long)hop->key,
                   matched_target_arg);
            printf("    ");
            print_interval("queue", hop->queue_ns);
            if (hop->target_ns) {
                print_interval("work", hop->target_ns);
                print_attribution(hop->target_ns, hop->offcpu_ns,
                                  hop->blocked_ns, hop->runqueue_ns, true);
            } else {
                printf(" work=unavailable");
            }
            putchar('\n');
            print_wait_resource(&hop->wait, output, "    ");
            if (hop->pid != hop->global_pid ||
                hop->tid != hop->global_tid)
                printf("  async global PID %u/TID %u\n",
                       hop->global_pid, hop->global_tid);
            if (hop->stack_id < 0) {
                printf("  async unable to collect user stack: %s (%d)\n",
                       strerror(-hop->stack_id), hop->stack_id);
            } else if (output->async_stack_map_fd < 0) {
                printf("  async stack map is unavailable\n");
            } else if (bpf_map_lookup_elem(output->async_stack_map_fd,
                                           &hop->stack_id,
                                           async_stack)) {
                printf("  async stack id %d is unavailable: %s\n",
                       hop->stack_id, strerror(errno));
            } else {
                print_stack_frames(async_stack, sizeof(async_stack),
                                   &maps, "async ", NULL, NULL, 0);
            }
        }
    }
    if (output->show_discovery && event->discovery_valid) {
        const struct discovery_wakeup *waker = &event->discovery_waker;
        struct map_list waker_maps = {0};
        uint64_t waker_stack[MAX_ASYNC_STACK_DEPTH] = {0};
        char candidate[256] = {0};
        uint32_t waker_maps_pid = waker->pid;

        printf("  async discovery: latest waker PID %u/TID %u (%.*s)",
               waker->pid, waker->tid, (int)sizeof(waker->comm),
               waker->comm);
        print_interval("wake-to-target", event->discovery_wakeup_ns);
        putchar('\n');
        if (waker->pid != waker->global_pid ||
            waker->tid != waker->global_tid)
            printf("  waker global PID %u/TID %u\n",
                   waker->global_pid, waker->global_tid);
        if (waker->pidns_error)
            printf("  waker PID namespace translation failed: %s (%d)\n",
                   strerror(-waker->pidns_error), waker->pidns_error);

        if (read_process_maps(waker_maps_pid, &waker_maps) &&
            waker->global_pid != waker_maps_pid) {
            map_list_free(&waker_maps);
            waker_maps_pid = waker->global_pid;
            read_process_maps(waker_maps_pid, &waker_maps);
        }

        if (waker->stack_id < 0) {
            printf("  unable to collect waker user stack: %s (%d)\n",
                   strerror(-waker->stack_id), waker->stack_id);
        } else if (output->discovery_stack_map_fd < 0) {
            printf("  discovery stack map is unavailable\n");
        } else if (bpf_map_lookup_elem(output->discovery_stack_map_fd,
                                       &waker->stack_id, waker_stack)) {
            printf("  discovery stack id %d is unavailable: %s\n",
                   waker->stack_id, strerror(errno));
        } else {
            print_stack_frames(waker_stack, sizeof(waker_stack),
                               &waker_maps, "waker ",
                               output->target_path, candidate,
                               sizeof(candidate));
        }

        if (candidate[0]) {
            printf("  candidate source function: %s\n", candidate);
            if (output->discovery_target_arg) {
                printf("  suggested template:\n"
                       "    --async-hop %s,?,%s,%u %s\n",
                       candidate,
                       output->final_target_name ?
                           output->final_target_name : "TARGET",
                       output->discovery_target_arg,
                       output->final_target_name ?
                           output->final_target_name : "TARGET");
            } else {
                printf("  suggested template:\n"
                       "    --async-hop %s,?,%s %s\n",
                       candidate,
                       output->final_target_name ?
                           output->final_target_name : "TARGET",
                       output->final_target_name ?
                           output->final_target_name : "TARGET");
            }
        } else {
            printf("  no source symbol was inferred; inspect the waker "
                   "stack and choose the enqueue/submit frame\n");
        }
        map_list_free(&waker_maps);
    }
    if (event->event_type == EVENT_RETURN) {
        if (output->show_async && event->async_hop_count)
            count_completed_chain(output);
        putchar('\n');
        map_list_free(&maps);
        return 0;
    }
    print_stack_frames(event->stack, event->stack_size, &maps, "",
                       NULL, NULL, 0);
    putchar('\n');

    map_list_free(&maps);
    return 0;
}

enum long_option_id {
    OPT_ASYNC_SOURCE = 1000,
    OPT_ASYNC_SOURCE_BINARY,
    OPT_ASYNC_SOURCE_ARG,
    OPT_ASYNC_TARGET_ARG,
    OPT_ASYNC_MAX_AGE_MS,
    OPT_ASYNC_HOP,
    OPT_DISCOVER_ASYNC,
    OPT_CONFIG,
    OPT_CHECK_CONFIG,
    OPT_MIN_TOTAL_MS,
    OPT_MIN_QUEUE_MS,
    OPT_MIN_WORK_MS,
    OPT_MAX_EVENTS,
    OPT_DURATION,
    OPT_DIAGNOSTIC_INTERVAL_MS,
    OPT_FORMAT,
    OPT_OUTPUT,
    OPT_REPORT,
    OPT_IO_URING,
    OPT_MIN_IO_LATENCY_US,
    OPT_IO_ERRORS_ONLY,
    OPT_IO_TOP,
    OPT_IO_CALLBACK,
    OPT_IO_CALLBACK_BINARY,
    OPT_IO_CALLBACK_ARG,
};

static void free_async_hops(struct async_hop_config *hops, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free(hops[i].source);
        free(hops[i].target);
    }
}

static int parse_async_hop(const char *text, struct async_hop_config *hop)
{
    char *copy = strdup(text);
    char *parts[4] = {0};
    char *save = NULL;
    char *part;
    size_t count = 0;
    int error = -1;

    if (!copy)
        return -1;
    for (part = strtok_r(copy, ",", &save);
         part && count < 4;
         part = strtok_r(NULL, ",", &save))
        parts[count++] = part;
    if (part || count < 3 || count > 4 ||
        !parts[0][0] || !parts[2][0])
        goto cleanup;
    if (parse_u32_range(parts[1], 1, 8, &hop->source_arg))
        goto cleanup;
    hop->target_arg = 0;
    if (count == 4 && strcmp(parts[3], "auto") &&
        parse_u32_range(parts[3], 1, 8, &hop->target_arg))
        goto cleanup;

    hop->source = strdup(parts[0]);
    hop->target = strdup(parts[2]);
    if (!hop->source || !hop->target)
        goto cleanup;
    error = 0;

cleanup:
    if (error) {
        free(hop->source);
        free(hop->target);
        hop->source = NULL;
        hop->target = NULL;
    }
    free(copy);
    return error;
}

static char *trim_config_text(char *text)
{
    char *end;

    while (*text == ' ' || *text == '\t')
        text++;
    end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' ||
            end[-1] == '\n' || end[-1] == '\r'))
        *--end = '\0';
    return text;
}

static char *normalize_config_value(char *value)
{
    size_t length;

    value = trim_config_text(value);
    length = strlen(value);
    if (length >= 2 &&
        ((value[0] == '"' && value[length - 1] == '"') ||
         (value[0] == '\'' && value[length - 1] == '\''))) {
        value[length - 1] = '\0';
        value++;
    }
    return value;
}

static int parse_config_ms(const char *path, size_t line_number,
                           const char *name, const char *value,
                           uint64_t *nanoseconds)
{
    uint32_t milliseconds;

    if (parse_u32_range(value, 0, UINT32_MAX, &milliseconds)) {
        fprintf(stderr, "%s:%zu: invalid %s value '%s'\n",
                path, line_number, name, value);
        return -1;
    }
    *nanoseconds = (uint64_t)milliseconds * 1000000ULL;
    return 0;
}

static int parse_cli_ms(const char *option, const char *value,
                        uint64_t *nanoseconds)
{
    uint32_t milliseconds;

    if (parse_u32_range(value, 0, UINT32_MAX, &milliseconds)) {
        fprintf(stderr, "invalid %s value: %s\n", option, value);
        return -1;
    }
    *nanoseconds = (uint64_t)milliseconds * 1000000ULL;
    return 0;
}

static int parse_cli_us(const char *option, const char *value,
                        uint64_t *nanoseconds)
{
    uint32_t microseconds;

    if (parse_u32_range(value, 1, UINT32_MAX, &microseconds)) {
        fprintf(stderr, "invalid %s value: %s\n", option, value);
        return -1;
    }
    *nanoseconds = (uint64_t)microseconds * 1000ULL;
    return 0;
}

static int parse_trace_config(const char *path,
                              struct async_hop_config *hops,
                              size_t *hop_count,
                              char **configured_function,
                              struct output_options *output,
                              uint32_t *duration_seconds)
{
    enum config_section {
        CONFIG_NONE,
        CONFIG_TARGET,
        CONFIG_HOPS,
        CONFIG_FILTERS,
    } section = CONFIG_NONE;
    bool source_arg_seen[MAX_ASYNC_HOPS] = {0};
    bool target_arg_seen[MAX_ASYNC_HOPS] = {0};
    FILE *file;
    char *line = NULL;
    size_t capacity = 0;
    size_t line_number = 0;
    int result = -1;

    file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "cannot open config %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    while (getline(&line, &capacity, file) >= 0) {
        struct async_hop_config *hop = NULL;
        char *key;
        char *value;
        char *separator;
        bool new_hop = false;

        line_number++;
        key = trim_config_text(line);
        if (!key[0] || key[0] == '#')
            continue;
        if (!strcmp(key, "target:")) {
            section = CONFIG_TARGET;
            continue;
        }
        if (!strcmp(key, "hops:")) {
            section = CONFIG_HOPS;
            continue;
        }
        if (!strcmp(key, "filters:")) {
            section = CONFIG_FILTERS;
            continue;
        }

        if (section == CONFIG_HOPS && key[0] == '-') {
            key = trim_config_text(key + 1);
            if (*hop_count >= MAX_ASYNC_HOPS) {
                fprintf(stderr, "%s:%zu: at most %d hops are supported\n",
                        path, line_number, MAX_ASYNC_HOPS);
                goto cleanup;
            }
            hop = &hops[*hop_count];
            (*hop_count)++;
            new_hop = true;
        } else if (section == CONFIG_HOPS && *hop_count) {
            hop = &hops[*hop_count - 1];
        }

        separator = strchr(key, ':');
        if (!separator) {
            fprintf(stderr, "%s:%zu: expected KEY: VALUE\n",
                    path, line_number);
            goto cleanup;
        }
        *separator = '\0';
        value = normalize_config_value(separator + 1);
        key = trim_config_text(key);
        if (!value[0]) {
            fprintf(stderr, "%s:%zu: %s must not be empty\n",
                    path, line_number, key);
            goto cleanup;
        }

        if (section == CONFIG_TARGET) {
            if (strcmp(key, "function")) {
                fprintf(stderr, "%s:%zu: unknown target key '%s'\n",
                        path, line_number, key);
                goto cleanup;
            }
            if (*configured_function) {
                fprintf(stderr, "%s:%zu: duplicate target function\n",
                        path, line_number);
                goto cleanup;
            }
            *configured_function = strdup(value);
            if (!*configured_function)
                goto cleanup;
        } else if (section == CONFIG_HOPS && hop) {
            size_t index = *hop_count - 1;

            if (new_hop && strcmp(key, "source")) {
                fprintf(stderr,
                        "%s:%zu: each hop must begin with '- source:'\n",
                        path, line_number);
                goto cleanup;
            }
            if (!strcmp(key, "source")) {
                if (hop->source) {
                    fprintf(stderr, "%s:%zu: duplicate hop source\n",
                            path, line_number);
                    goto cleanup;
                }
                hop->source = strdup(value);
                if (!hop->source)
                    goto cleanup;
            } else if (!strcmp(key, "source_arg")) {
                if (parse_u32_range(value, 1, 8, &hop->source_arg)) {
                    fprintf(stderr, "%s:%zu: invalid source_arg '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
                source_arg_seen[index] = true;
            } else if (!strcmp(key, "target")) {
                if (hop->target) {
                    fprintf(stderr, "%s:%zu: duplicate hop target\n",
                            path, line_number);
                    goto cleanup;
                }
                hop->target = strdup(value);
                if (!hop->target)
                    goto cleanup;
            } else if (!strcmp(key, "target_arg")) {
                if (target_arg_seen[index]) {
                    fprintf(stderr, "%s:%zu: duplicate target_arg\n",
                            path, line_number);
                    goto cleanup;
                }
                if (!strcmp(value, "auto")) {
                    hop->target_arg = 0;
                } else if (parse_u32_range(value, 1, 8,
                                           &hop->target_arg)) {
                    fprintf(stderr, "%s:%zu: invalid target_arg '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
                target_arg_seen[index] = true;
            } else {
                fprintf(stderr, "%s:%zu: unknown hop key '%s'\n",
                        path, line_number, key);
                goto cleanup;
            }
        } else if (section == CONFIG_FILTERS) {
            if (!strcmp(key, "min_total_ms")) {
                if (parse_config_ms(path, line_number, key, value,
                                    &output->min_total_ns))
                    goto cleanup;
            } else if (!strcmp(key, "min_queue_ms")) {
                if (parse_config_ms(path, line_number, key, value,
                                    &output->min_queue_ns))
                    goto cleanup;
            } else if (!strcmp(key, "min_work_ms")) {
                if (parse_config_ms(path, line_number, key, value,
                                    &output->min_work_ns))
                    goto cleanup;
            } else if (!strcmp(key, "max_events")) {
                if (parse_u32_range(value, 1, UINT32_MAX,
                                    &output->max_events)) {
                    fprintf(stderr, "%s:%zu: invalid max_events '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
            } else if (!strcmp(key, "duration")) {
                if (parse_u32_range(value, 1, UINT32_MAX,
                                    duration_seconds)) {
                    fprintf(stderr, "%s:%zu: invalid duration '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
            } else if (!strcmp(key, "diagnostic_interval_ms")) {
                if (parse_u32_range(
                        value, 0, UINT32_MAX,
                        &output->diagnostic_interval_ms)) {
                    fprintf(stderr,
                            "%s:%zu: invalid diagnostic_interval_ms '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
            } else {
                fprintf(stderr, "%s:%zu: unknown filter key '%s'\n",
                        path, line_number, key);
                goto cleanup;
            }
        } else {
            fprintf(stderr, "%s:%zu: value appears outside a known section\n",
                    path, line_number);
            goto cleanup;
        }
    }
    if (ferror(file)) {
        fprintf(stderr, "cannot read config %s: %s\n",
                path, strerror(errno));
        goto cleanup;
    }
    if (!*configured_function) {
        fprintf(stderr, "%s: target.function is required\n", path);
        goto cleanup;
    }
    if (!*hop_count) {
        fprintf(stderr, "%s: at least one hop is required\n", path);
        goto cleanup;
    }
    for (size_t index = 0; index < *hop_count; index++) {
        if (!hops[index].source || !hops[index].target ||
            !source_arg_seen[index]) {
            fprintf(stderr,
                    "%s: hop %zu requires source, source_arg, and target; "
                    "target_arg is optional\n",
                    path, index);
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    free(line);
    fclose(file);
    return result;
}

int main(int argc, char **argv)
{
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"pid", required_argument, NULL, 'p'},
        {"binary", required_argument, NULL, 'b'},
        {"module", required_argument, NULL, 'm'},
        {"find-symbol", required_argument, NULL, 's'},
        {"offset", required_argument, NULL, 'o'},
        {"ret", no_argument, NULL, 'r'},
        {"return-value", no_argument, NULL, 'r'},
        {"time", no_argument, NULL, 't'},
        {"latency", no_argument, NULL, 't'},
        {"attribution", no_argument, NULL, 'a'},
        {"breakdown", no_argument, NULL, 'a'},
        {"async-source", required_argument, NULL, OPT_ASYNC_SOURCE},
        {"async-source-binary", required_argument, NULL,
         OPT_ASYNC_SOURCE_BINARY},
        {"async-source-arg", required_argument, NULL, OPT_ASYNC_SOURCE_ARG},
        {"async-target-arg", required_argument, NULL, OPT_ASYNC_TARGET_ARG},
        {"async-max-age-ms", required_argument, NULL, OPT_ASYNC_MAX_AGE_MS},
        {"async-hop", required_argument, NULL, OPT_ASYNC_HOP},
        {"discover-async", required_argument, NULL, OPT_DISCOVER_ASYNC},
        {"config", required_argument, NULL, OPT_CONFIG},
        {"check-config", required_argument, NULL, OPT_CHECK_CONFIG},
        {"min-total-ms", required_argument, NULL, OPT_MIN_TOTAL_MS},
        {"min-queue-ms", required_argument, NULL, OPT_MIN_QUEUE_MS},
        {"min-work-ms", required_argument, NULL, OPT_MIN_WORK_MS},
        {"max-events", required_argument, NULL, OPT_MAX_EVENTS},
        {"duration", required_argument, NULL, OPT_DURATION},
        {"diagnostic-interval-ms", required_argument, NULL,
         OPT_DIAGNOSTIC_INTERVAL_MS},
        {"format", required_argument, NULL, OPT_FORMAT},
        {"output", required_argument, NULL, OPT_OUTPUT},
        {"report", required_argument, NULL, OPT_REPORT},
        {"io-uring", no_argument, NULL, OPT_IO_URING},
        {"min-io-latency-us", required_argument, NULL,
         OPT_MIN_IO_LATENCY_US},
        {"io-errors-only", no_argument, NULL, OPT_IO_ERRORS_ONLY},
        {"io-top", required_argument, NULL, OPT_IO_TOP},
        {"io-callback", required_argument, NULL, OPT_IO_CALLBACK},
        {"io-callback-binary", required_argument, NULL,
         OPT_IO_CALLBACK_BINARY},
        {"io-callback-arg", required_argument, NULL,
         OPT_IO_CALLBACK_ARG},
        {0, 0, 0, 0},
    };
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
    };
    struct bpf_uprobe_opts return_options = {
        .sz = sizeof(return_options),
        .retprobe = true,
    };
    struct output_options output = {
        .async_stack_map_fd = -1,
        .discovery_stack_map_fd = -1,
        .wait_stack_map_fd = -1,
        .async_hop_stats_map_fd = -1,
        .async_worker_stats_map_fd = -1,
        .io_uring_stack_map_fd = -1,
        .io_uring_counters_map_fd = -1,
        .io_uring_aggregate_map_fd = -1,
        .io_uring_result_map_fd = -1,
        .io_uring_ring_stats_map_fd = -1,
        .io_uring_failure_map_fd = -1,
        .io_uring_link_map_fd = -1,
        .target_pidfd = -1,
        .diagnostic_interval_ms = 1000,
    };
    struct callweave_bpf *skeleton = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct async_hop_config async_hops[MAX_ASYNC_HOPS] = {0};
    struct bpf_link *async_links[MAX_ASYNC_HOPS * 3] = {0};
    char target_path[PATH_MAX] = {0};
    char async_source_path[PATH_MAX] = {0};
    char io_callback_path[PATH_MAX] = {0};
    const char *binary_argument = NULL;
    const char *module_name = NULL;
    const char *find_symbol_name = NULL;
    const char *offset_text = NULL;
    const char *function_name = NULL;
    const char *async_source_name = NULL;
    const char *async_source_binary = NULL;
    const char *discover_function = NULL;
    const char *config_path = NULL;
    const char *output_path = NULL;
    const char *report_path = NULL;
    const char *io_callback_name = NULL;
    const char *io_callback_binary = NULL;
    char *configured_function = NULL;
    size_t function_offset = 0;
    uint32_t async_source_arg = 1;
    uint32_t async_target_arg = 0;
    uint32_t async_max_age_ms = 30000;
    uint32_t duration_seconds = 0;
    uint32_t io_callback_arg = 1;
    uint64_t stop_time_ns = 0;
    size_t async_hop_count = 0;
    size_t async_link_count = 0;
    pid_t target_pid = -1;
    bool async_option_seen = false;
    bool io_callback_option_seen = false;
    bool check_config = false;
    bool json_output = false;
    int remaining_arguments;
    int option;
    int error = 0;
    int argument_index;

    for (argument_index = 1; argument_index < argc; argument_index++) {
        const char *argument = argv[argument_index];

        if (!strcmp(argument, "--config")) {
            if (++argument_index >= argc || config_path) {
                fprintf(stderr,
                        "--config requires one path and may appear once\n");
                return 2;
            }
            config_path = argv[argument_index];
        } else if (!strcmp(argument, "--check-config")) {
            if (++argument_index >= argc || config_path) {
                fprintf(stderr,
                        "--check-config requires one path and cannot be "
                        "combined with --config\n");
                return 2;
            }
            config_path = argv[argument_index];
            check_config = true;
        } else if (!strncmp(argument, "--config=", 9)) {
            if (config_path || !argument[9]) {
                fprintf(stderr,
                        "--config requires one path and may appear once\n");
                return 2;
            }
            config_path = argument + 9;
        } else if (!strncmp(argument, "--check-config=", 15)) {
            if (config_path || !argument[15]) {
                fprintf(stderr,
                        "--check-config requires one path and cannot be "
                        "combined with --config\n");
                return 2;
            }
            config_path = argument + 15;
            check_config = true;
        }
    }
    if (config_path) {
        if (parse_trace_config(config_path, async_hops, &async_hop_count,
                               &configured_function, &output,
                               &duration_seconds)) {
            error = 2;
            goto cleanup;
        }
        output.show_async = true;
    }

    while ((option = getopt_long(argc, argv, "hp:b:m:s:o:rta",
                                 long_options, NULL)) != -1) {
        switch (option) {
        case 'h':
            usage(stdout, argv[0]);
            return 0;
        case 'p':
            if (parse_pid(optarg, &target_pid)) {
                fprintf(stderr, "invalid PID: %s\n", optarg);
                return 2;
            }
            break;
        case 'b':
            binary_argument = optarg;
            break;
        case 'm':
            module_name = optarg;
            break;
        case 's':
            find_symbol_name = optarg;
            break;
        case 'o':
            offset_text = optarg;
            break;
        case 'r':
            output.show_return_value = true;
            break;
        case 't':
            output.show_duration = true;
            break;
        case 'a':
            output.show_attribution = true;
            output.show_duration = true;
            break;
        case OPT_ASYNC_SOURCE:
            async_source_name = optarg;
            output.show_async = true;
            break;
        case OPT_ASYNC_SOURCE_BINARY:
            async_source_binary = optarg;
            async_option_seen = true;
            break;
        case OPT_ASYNC_SOURCE_ARG:
            async_option_seen = true;
            if (parse_u32_range(optarg, 1, 8, &async_source_arg)) {
                fprintf(stderr, "invalid async source argument: %s\n",
                        optarg);
                return 2;
            }
            break;
        case OPT_ASYNC_TARGET_ARG:
            async_option_seen = true;
            if (!strcmp(optarg, "auto")) {
                async_target_arg = 0;
            } else if (parse_u32_range(optarg, 1, 8,
                                       &async_target_arg)) {
                fprintf(stderr, "invalid async target argument: %s\n",
                        optarg);
                return 2;
            }
            break;
        case OPT_ASYNC_MAX_AGE_MS:
            if (parse_u32_range(optarg, 1, UINT32_MAX,
                                &async_max_age_ms)) {
                fprintf(stderr, "invalid async maximum age: %s\n", optarg);
                return 2;
            }
            break;
        case OPT_ASYNC_HOP:
            if (config_path) {
                fprintf(stderr,
                        "--async-hop cannot be combined with --config\n");
                error = 2;
                goto cleanup;
            }
            if (async_hop_count >= MAX_ASYNC_HOPS) {
                fprintf(stderr, "at most %d async hops are supported\n",
                        MAX_ASYNC_HOPS);
                error = 2;
                goto cleanup;
            }
            if (parse_async_hop(optarg, &async_hops[async_hop_count])) {
                fprintf(stderr,
                        "invalid async hop '%s'; expected "
                        "SOURCE,SOURCE_ARG,TARGET[,TARGET_ARG]\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            async_hop_count++;
            output.show_async = true;
            break;
        case OPT_DISCOVER_ASYNC:
            discover_function = optarg;
            output.show_discovery = true;
            break;
        case OPT_CONFIG:
            break;
        case OPT_CHECK_CONFIG:
            break;
        case OPT_MIN_TOTAL_MS:
            if (parse_cli_ms("--min-total-ms", optarg,
                             &output.min_total_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MIN_QUEUE_MS:
            if (parse_cli_ms("--min-queue-ms", optarg,
                             &output.min_queue_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MIN_WORK_MS:
            if (parse_cli_ms("--min-work-ms", optarg,
                             &output.min_work_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MAX_EVENTS:
            if (parse_u32_range(optarg, 1, UINT32_MAX,
                                &output.max_events)) {
                fprintf(stderr, "invalid maximum event count: %s\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_DURATION:
            if (parse_u32_range(optarg, 1, UINT32_MAX,
                                &duration_seconds)) {
                fprintf(stderr, "invalid duration: %s\n", optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_DIAGNOSTIC_INTERVAL_MS:
            if (parse_u32_range(optarg, 0, UINT32_MAX,
                                &output.diagnostic_interval_ms)) {
                fprintf(stderr, "invalid diagnostic interval: %s\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_FORMAT:
            if (!strcmp(optarg, "json")) {
                json_output = true;
            } else if (!strcmp(optarg, "text")) {
                json_output = false;
            } else {
                fprintf(stderr,
                        "invalid output format '%s'; expected text or json\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_OUTPUT:
            output_path = optarg;
            break;
        case OPT_REPORT:
            report_path = optarg;
            break;
        case OPT_IO_URING:
            output.io_uring_mode = true;
            break;
        case OPT_MIN_IO_LATENCY_US:
            if (parse_cli_us("--min-io-latency-us", optarg,
                             &output.io_uring_min_latency_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_IO_ERRORS_ONLY:
            output.io_uring_errors_only = true;
            break;
        case OPT_IO_TOP:
            if (parse_u32_range(optarg, 1, 1000,
                                &output.io_uring_top)) {
                fprintf(stderr, "invalid --io-top value: %s\n", optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_IO_CALLBACK:
            io_callback_name = optarg;
            io_callback_option_seen = true;
            break;
        case OPT_IO_CALLBACK_BINARY:
            io_callback_binary = optarg;
            io_callback_option_seen = true;
            break;
        case OPT_IO_CALLBACK_ARG:
            io_callback_option_seen = true;
            if (parse_u32_range(optarg, 1, 8, &io_callback_arg)) {
                fprintf(stderr, "invalid --io-callback-arg value: %s\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        default:
            usage(stderr, argv[0]);
            return 2;
        }
    }

    remaining_arguments = argc - optind;
    if (check_config) {
        if (remaining_arguments) {
            fprintf(stderr,
                    "--check-config does not accept positional arguments\n");
            error = 2;
            goto cleanup;
        }
        printf("%s: valid (%zu async hop%s)\n",
               config_path, async_hop_count,
               async_hop_count == 1 ? "" : "s");
        goto cleanup;
    }
    if (output.show_async) {
        output.show_duration = true;
        output.show_attribution = true;
    }
    if (output_path && !json_output) {
        fprintf(stderr, "--output requires --format json\n");
        error = 2;
        goto cleanup;
    }
    if (json_output && !output.show_async && !output.io_uring_mode) {
        fprintf(stderr,
                "--format json requires async tracing or --io-uring\n");
        error = 2;
        goto cleanup;
    }
    if (report_path && !output.show_async) {
        fprintf(stderr,
                "--report requires async tracing via --config, "
                "--async-hop, or --async-source\n");
        error = 2;
        goto cleanup;
    }
    if (output_path && report_path && !strcmp(output_path, report_path)) {
        fprintf(stderr,
                "--output and --report must use different paths\n");
        error = 2;
        goto cleanup;
    }
    output.json_output = json_output;
    if (module_name && target_pid <= 0) {
        fprintf(stderr, "--module requires --pid\n");
        return 2;
    }
    if (module_name && binary_argument) {
        fprintf(stderr, "--module and --binary are mutually exclusive\n");
        return 2;
    }
    if (output.show_discovery &&
        (output.show_async || async_source_name || async_hop_count)) {
        fprintf(stderr,
                "--discover-async cannot be combined with async tracing\n");
        error = 2;
        goto cleanup;
    }
    if (((output.min_total_ns || output.min_queue_ns ||
          output.min_work_ns) && !output.show_async) ||
        (output.max_events && !output.show_async &&
         !output.io_uring_mode)) {
        fprintf(stderr,
                "chain filters require --config, --async-hop, or "
                "--async-source\n");
        error = 2;
        goto cleanup;
    }
    if (output.show_discovery && target_pid <= 0) {
        fprintf(stderr, "--discover-async requires --pid\n");
        error = 2;
        goto cleanup;
    }
    if (async_hop_count && (async_source_name || async_option_seen)) {
        fprintf(stderr,
                "--async-hop cannot be combined with the legacy "
                "--async-source options\n");
        error = 2;
        goto cleanup;
    }
    if (!async_hop_count && async_option_seen && !async_source_name &&
        !output.show_discovery) {
        fprintf(stderr,
                "async tuning options require --async-source FUNCTION\n");
        error = 2;
        goto cleanup;
    }
    if (async_source_name && !async_source_name[0]) {
        fprintf(stderr, "async source function must not be empty\n");
        return 2;
    }

    error = validate_target_pid(target_pid);
    if (error)
        return 1;

    if (!output.io_uring_mode &&
        (output.io_uring_min_latency_ns ||
         output.io_uring_errors_only || output.io_uring_top ||
         io_callback_option_seen)) {
        fprintf(stderr,
                "io_uring filters and callback options require "
                "--io-uring\n");
        error = 2;
        goto cleanup;
    }
    if (output.io_uring_mode) {
        if (target_pid <= 0) {
            fprintf(stderr, "--io-uring requires --pid\n");
            error = 2;
            goto cleanup;
        }
        if (remaining_arguments || binary_argument || module_name ||
            find_symbol_name || offset_text || configured_function ||
            output.show_return_value || output.show_duration ||
            output.show_attribution || output.show_async ||
            output.show_discovery || async_source_name ||
            async_source_binary || async_option_seen || async_hop_count ||
            report_path) {
            fprintf(stderr,
                    "--io-uring is a standalone mode; combine it only with "
                    "--pid, its io_uring filters/callback options, "
                    "--duration, --max-events, --format, and --output\n");
            error = 2;
            goto cleanup;
        }
        if (io_callback_option_seen &&
            (!io_callback_name || !io_callback_name[0])) {
            fprintf(stderr,
                    "--io-callback-binary and --io-callback-arg require "
                    "--io-callback FUNCTION\n");
            error = 2;
            goto cleanup;
        }
        if (io_callback_name) {
            if (io_callback_binary) {
                if (!realpath(io_callback_binary, io_callback_path)) {
                    fprintf(stderr,
                            "cannot resolve callback binary %s: %s\n",
                            io_callback_binary, strerror(errno));
                    error = 1;
                    goto cleanup;
                }
            } else {
                error = resolve_process_executable(
                    target_pid, io_callback_path,
                    sizeof(io_callback_path));
                if (error)
                    goto cleanup;
            }
            output.io_uring_callback_name = io_callback_name;
        }
        goto trace_target_ready;
    }

    if (find_symbol_name) {
        int result;

        if (offset_text || remaining_arguments ||
            output.show_return_value || output.show_duration ||
            output.show_async || output.show_discovery) {
            fprintf(stderr,
                    "--find-symbol cannot be combined with --offset, "
                    "--ret, --time, --attribution, --async-source, or a "
                    "positional FUNCTION\n");
            return 2;
        }
        if (!find_symbol_name[0]) {
            fprintf(stderr, "symbol name must not be empty\n");
            return 2;
        }
        if (binary_argument) {
            if (!realpath(binary_argument, target_path)) {
                fprintf(stderr, "cannot resolve %s: %s\n",
                        binary_argument, strerror(errno));
                return 1;
            }
            result = print_symbol_result(target_path, find_symbol_name);
            if (result < 0)
                fprintf(stderr, "cannot inspect %s: %s\n",
                        target_path, strerror(errno));
            else if (!result)
                fprintf(stderr, "symbol '%s' was not found in %s\n",
                        find_symbol_name, target_path);
            return result > 0 ? 0 : 1;
        }
        if (target_pid <= 0) {
            fprintf(stderr,
                    "--find-symbol requires --pid or --binary\n");
            return 2;
        }
        if (module_name) {
            error = resolve_loaded_module(target_pid, module_name,
                                          target_path,
                                          sizeof(target_path));
            if (error)
                return 1;
            result = print_symbol_result(target_path, find_symbol_name);
            if (result < 0)
                fprintf(stderr, "cannot inspect %s: %s\n",
                        target_path, strerror(errno));
            else if (!result)
                fprintf(stderr, "symbol '%s' was not found in %s\n",
                        find_symbol_name, target_path);
            return result > 0 ? 0 : 1;
        }
        return find_symbol_in_process(target_pid, module_name,
                                      find_symbol_name) ? 1 : 0;
    }

    if (configured_function) {
        if (discover_function || offset_text || remaining_arguments) {
            fprintf(stderr,
                    "--config supplies target.function and cannot be "
                    "combined with another target function\n");
            error = 2;
            goto cleanup;
        }
        function_name = configured_function;
    } else if (discover_function) {
        if (offset_text || remaining_arguments || !discover_function[0]) {
            fprintf(stderr,
                    "--discover-async accepts its target as the option "
                    "argument and cannot be combined with --offset or a "
                    "positional FUNCTION\n");
            return 2;
        }
        function_name = discover_function;
    } else if (offset_text) {
        if (remaining_arguments || !binary_argument || module_name) {
            fprintf(stderr,
                    "--offset requires --binary and no positional FUNCTION\n");
            return 2;
        }
        if (parse_offset(offset_text, &function_offset)) {
            fprintf(stderr, "invalid ELF file offset: %s\n", offset_text);
            return 2;
        }
    } else if (remaining_arguments == 2 &&
               !binary_argument && !module_name) {
        binary_argument = argv[optind];
        function_name = argv[optind + 1];
    } else if (remaining_arguments == 1) {
        function_name = argv[optind];
    } else {
        usage(stderr, argv[0]);
        return 2;
    }

    if (!offset_text && (!function_name || !function_name[0])) {
        fprintf(stderr, "function name must not be empty\n");
        return 2;
    }
    output.async_hops = async_hops;
    output.async_hop_count = async_hop_count;
    output.async_source_name = async_source_name;
    output.final_target_name = function_name;
    output.discovery_target_arg = async_target_arg;

    if (module_name) {
        error = resolve_loaded_module(target_pid, module_name,
                                      target_path, sizeof(target_path));
        if (error)
            return 1;
    } else if (binary_argument) {
        if (!realpath(binary_argument, target_path)) {
            fprintf(stderr, "cannot resolve %s: %s\n",
                    binary_argument, strerror(errno));
            return 1;
        }
    } else if (target_pid > 0) {
        error = resolve_process_executable(target_pid, target_path,
                                           sizeof(target_path));
        if (error)
            return 1;
    } else {
        fprintf(stderr,
                "BINARY is required when --pid is not specified\n");
        return 2;
    }
    output.target_path = target_path;

    if (async_hop_count) {
        const struct async_hop_config *last =
            &async_hops[async_hop_count - 1];

        if (offset_text) {
            fprintf(stderr,
                    "--async-hop requires a named final target function\n");
            error = 2;
            goto cleanup;
        }
        if (strcmp(last->target, function_name)) {
            fprintf(stderr,
                    "the last async-hop target '%s' must match the traced "
                    "function '%s'\n",
                    last->target, function_name);
            error = 2;
            goto cleanup;
        }
        async_target_arg = last->target_arg;
    }

    if (output.show_async) {
        if (async_source_binary) {
            if (!realpath(async_source_binary, async_source_path)) {
                fprintf(stderr, "cannot resolve async source %s: %s\n",
                        async_source_binary, strerror(errno));
                return 1;
            }
        } else {
            snprintf(async_source_path, sizeof(async_source_path), "%s",
                     target_path);
        }
    }

trace_target_ready:
    output.target_pid = target_pid;
#ifdef SYS_pidfd_open
    if (target_pid > 0)
        output.target_pidfd =
            syscall(SYS_pidfd_open, target_pid, 0);
#endif
    if (output.io_uring_mode && target_pid > 0) {
        cache_all_io_uring_fd_resources(&output);
        output.io_uring_maps = calloc(1, sizeof(*output.io_uring_maps));
        if (output.io_uring_maps &&
            !read_process_maps((uint32_t)target_pid,
                               output.io_uring_maps)) {
            output.io_uring_maps_pid = (uint32_t)target_pid;
        } else {
            if (output.io_uring_maps) {
                map_list_free(output.io_uring_maps);
                free(output.io_uring_maps);
                output.io_uring_maps = NULL;
            }
        }
    }
    if (install_signal_handlers()) {
        error = -errno;
        goto cleanup;
    }

    skeleton = callweave_bpf__open();
    if (!skeleton) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }
    error = configure_pid_namespace(skeleton);
    if (error)
        goto cleanup;
    skeleton->rodata->target_pid =
        target_pid > 0 ? (uint32_t)target_pid : 0;
    skeleton->rodata->trace_returns =
        output.show_return_value || output.show_duration;
    skeleton->rodata->trace_attribution = output.show_attribution;
    skeleton->rodata->trace_async = output.show_async;
    skeleton->rodata->trace_discovery = output.show_discovery;
    skeleton->rodata->trace_io_uring = output.io_uring_mode;
    skeleton->rodata->enable_io_uring_callback =
        output.io_uring_callback_name != NULL;
    skeleton->rodata->io_uring_callback_arg = io_callback_arg;
    skeleton->rodata->io_uring_min_latency_ns =
        output.io_uring_min_latency_ns;
    skeleton->rodata->io_uring_errors_only =
        output.io_uring_errors_only;
    skeleton->rodata->async_source_arg = async_source_arg;
    skeleton->rodata->async_target_arg = async_target_arg;
    skeleton->rodata->async_max_age_ns =
        (uint64_t)async_max_age_ms * 1000000ULL;
    skeleton->rodata->async_final_hop_id =
        output.show_async ?
            (uint32_t)(async_hop_count ? async_hop_count : 1) : 0;
    skeleton->rodata->futex_syscall_nr = SYS_futex;
    if (!output.io_uring_mode) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_io_uring_submit_req, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_file_get, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_complete, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_create, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_register, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_defer, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_queue_async_work, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_wq_submit_work, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_poll_arm, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_cqring_wait, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_cqe_overflow, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_req_failed, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_link, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_io_uring_fail_link, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable io_uring programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    } else {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_function, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_function_return, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable function tracing programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (!output.show_attribution) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_sched_switch, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_sched_wakeup, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_sys_enter, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_sys_exit, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable scheduler attribution programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (!output.io_uring_callback_name) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_io_uring_callback, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable io_uring callback program: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (!output.show_discovery) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_sched_waking, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable async discovery program: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (!output.show_async) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_async_source, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable async source program: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (async_hop_count <= 1) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_async_target, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_async_target_return, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable multi-hop target programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }

    error = callweave_bpf__load(skeleton);
    if (error) {
        fprintf(stderr, "failed to load BPF program: %s\n", strerror(-error));
        goto cleanup;
    }
    output.async_stack_map_fd = bpf_map__fd(skeleton->maps.async_stacks);
    output.discovery_stack_map_fd =
        bpf_map__fd(skeleton->maps.discovery_stacks);
    output.wait_stack_map_fd = output.discovery_stack_map_fd;
    output.async_hop_stats_map_fd =
        bpf_map__fd(skeleton->maps.async_hop_stats);
    output.async_worker_stats_map_fd =
        bpf_map__fd(skeleton->maps.async_worker_stats);
    output.io_uring_stack_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_stacks);
    output.io_uring_counters_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_counters);
    output.io_uring_aggregate_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_aggregates);
    output.io_uring_result_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_results);
    output.io_uring_ring_stats_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_ring_stats);
    output.io_uring_failure_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_failures);
    output.io_uring_link_map_fd =
        bpf_map__fd(skeleton->maps.io_uring_links);

    if (output.io_uring_mode) {
        error = attach_raw_tracepoint(
            skeleton->progs.trace_io_uring_submit_req,
            &skeleton->links.trace_io_uring_submit_req,
            "io_uring_submit_req");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_io_uring_file_get,
                &skeleton->links.trace_io_uring_file_get,
                "io_uring_file_get");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_io_uring_complete,
                &skeleton->links.trace_io_uring_complete,
                "io_uring_complete");
        if (error)
            goto cleanup;
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_create,
            &skeleton->links.trace_io_uring_create,
            "io_uring_create");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_register,
            &skeleton->links.trace_io_uring_register,
            "io_uring_register");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_defer,
            &skeleton->links.trace_io_uring_defer,
            "io_uring_defer");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_queue_async_work,
            &skeleton->links.trace_io_uring_queue_async_work,
            "io_uring_queue_async_work");
        attach_optional_kprobe(
            skeleton->progs.trace_io_wq_submit_work,
            &skeleton->links.trace_io_wq_submit_work,
            "io_wq_submit_work");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_poll_arm,
            &skeleton->links.trace_io_uring_poll_arm,
            "io_uring_poll_arm");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_cqring_wait,
            &skeleton->links.trace_io_uring_cqring_wait,
            "io_uring_cqring_wait");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_cqe_overflow,
            &skeleton->links.trace_io_uring_cqe_overflow,
            "io_uring_cqe_overflow");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_req_failed,
            &skeleton->links.trace_io_uring_req_failed,
            "io_uring_req_failed");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_link,
            &skeleton->links.trace_io_uring_link,
            "io_uring_link");
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_io_uring_fail_link,
            &skeleton->links.trace_io_uring_fail_link,
            "io_uring_fail_link");
        if (output.io_uring_callback_name) {
            error = attach_named_uprobe(
                skeleton->progs.trace_io_uring_callback,
                &skeleton->links.trace_io_uring_callback,
                io_callback_path, output.io_uring_callback_name,
                0, false);
            if (error)
                goto cleanup;
        }
    } else if (output.show_attribution) {
        error = attach_raw_tracepoint(
            skeleton->progs.trace_sched_switch,
            &skeleton->links.trace_sched_switch, "sched_switch");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_sched_wakeup,
                &skeleton->links.trace_sched_wakeup, "sched_wakeup");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_sys_enter,
                &skeleton->links.trace_sys_enter, "sys_enter");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_sys_exit,
                &skeleton->links.trace_sys_exit, "sys_exit");
        if (error)
            goto cleanup;
    } else if (output.show_discovery) {
        error = attach_raw_tracepoint(
            skeleton->progs.trace_sched_waking,
            &skeleton->links.trace_sched_waking, "sched_waking");
        if (error)
            goto cleanup;
    }

    if (output.show_return_value || output.show_duration) {
        return_options.func_name = offset_text ? NULL : function_name;
        skeleton->links.trace_function_return =
            bpf_program__attach_uprobe_opts(
                skeleton->progs.trace_function_return, -1, target_path,
                function_offset, &return_options);
        error = skeleton->links.trace_function_return ?
                libbpf_get_error(skeleton->links.trace_function_return) :
                (errno ? -errno : -EINVAL);
        if (error) {
            skeleton->links.trace_function_return = NULL;
            if (offset_text)
                fprintf(stderr,
                        "failed to attach uretprobe to %s+0x%zx: %s\n",
                        target_path, function_offset, strerror(-error));
            else
                fprintf(stderr,
                        "failed to attach uretprobe to %s:%s: %s\n",
                        target_path, function_name, strerror(-error));
            goto cleanup;
        }
    }

    if (async_hop_count) {
        size_t i;

        for (i = 0; i + 1 < async_hop_count; i++) {
            uint64_t target_cookie =
                ((uint64_t)(i + 1) << 32) |
                async_hops[i].target_arg;

            error = attach_named_uprobe(
                skeleton->progs.trace_async_target_return,
                &async_links[async_link_count], target_path,
                async_hops[i].target, 0, true);
            if (error)
                goto cleanup;
            async_link_count++;
            error = attach_named_uprobe(
                skeleton->progs.trace_async_target,
                &async_links[async_link_count], target_path,
                async_hops[i].target, target_cookie, false);
            if (error)
                goto cleanup;
            async_link_count++;
        }
        for (i = 0; i < async_hop_count; i++) {
            uint64_t source_cookie =
                ((uint64_t)(i + 1) << 32) |
                async_hops[i].source_arg;

            error = attach_named_uprobe(
                skeleton->progs.trace_async_source,
                &async_links[async_link_count], target_path,
                async_hops[i].source, source_cookie, false);
            if (error)
                goto cleanup;
            async_link_count++;
        }
    } else if (output.show_async) {
        error = attach_named_uprobe(
            skeleton->progs.trace_async_source,
            &skeleton->links.trace_async_source, async_source_path,
            async_source_name, 0, false);
        if (error)
            goto cleanup;
    }

    if (!output.io_uring_mode) {
        options.func_name = offset_text ? NULL : function_name;
        skeleton->links.trace_function = bpf_program__attach_uprobe_opts(
            skeleton->progs.trace_function, -1, target_path,
            function_offset, &options);
        error = skeleton->links.trace_function ?
                libbpf_get_error(skeleton->links.trace_function) :
                (errno ? -errno : -EINVAL);
        if (error) {
            skeleton->links.trace_function = NULL;
            if (offset_text)
                fprintf(stderr,
                        "failed to attach uprobe to %s+0x%zx: %s\n",
                        target_path, function_offset, strerror(-error));
            else
                fprintf(stderr, "failed to attach uprobe to %s:%s: %s\n",
                        target_path, function_name, strerror(-error));
            goto cleanup;
        }
    }

    ring_buffer = ring_buffer__new(
        output.io_uring_mode ?
            bpf_map__fd(skeleton->maps.io_uring_events) :
            bpf_map__fd(skeleton->maps.events),
        output.io_uring_mode ? handle_io_uring_event : handle_event,
        &output, NULL);
    if (!ring_buffer) {
        error = errno ? -errno : -ENOMEM;
        fprintf(stderr, "failed to create ring buffer: %s\n",
                strerror(-error));
        goto cleanup;
    }
    if (output.io_uring_callback_name) {
        error = ring_buffer__add(
            ring_buffer,
            bpf_map__fd(skeleton->maps.io_uring_callback_events),
            handle_io_uring_callback_event, &output);
        if (error) {
            fprintf(stderr,
                    "failed to add io_uring callback ring buffer: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }

    if (json_output) {
        if (output_path) {
            output.json_stream = fopen(output_path, "w");
            if (!output.json_stream) {
                error = -errno;
                fprintf(stderr, "cannot create JSON output %s: %s\n",
                        output_path, strerror(errno));
                goto cleanup;
            }
        } else {
            output.json_stream = stdout;
        }
    }
    if (report_path) {
        FILE *report_stream = fopen(report_path, "w");

        if (!report_stream) {
            error = -errno;
            fprintf(stderr, "cannot create HTML report %s: %s\n",
                    report_path, strerror(errno));
            goto cleanup;
        }
        output.report_first = true;
        if (cw_html_report_begin(report_stream)) {
            error = -(errno ? errno : EIO);
            fprintf(stderr, "cannot initialize HTML report %s: %s\n",
                    report_path, strerror(-error));
            fclose(report_stream);
            goto cleanup;
        }
        output.report_stream = report_stream;
    }

    if (json_output) {
        if (output.io_uring_mode)
            fprintf(stderr, "Tracing io_uring");
        else if (offset_text)
            fprintf(stderr, "Tracing %s+0x%zx", target_path,
                    function_offset);
        else
            fprintf(stderr, "Tracing %s:%s", target_path, function_name);
        if (target_pid > 0)
            fprintf(stderr, " in PID %d", target_pid);
        else
            fprintf(stderr, " in all processes");
        fprintf(stderr, ", JSON Lines output");
        if (output_path)
            fprintf(stderr, " to %s", output_path);
        if (output.io_uring_min_latency_ns)
            fprintf(stderr, ", minimum io latency %.3f us",
                    (double)output.io_uring_min_latency_ns / 1000.0);
        if (output.io_uring_errors_only)
            fprintf(stderr, ", io errors only");
        if (output.io_uring_top)
            fprintf(stderr, ", top %u submit groups",
                    output.io_uring_top);
        if (report_path)
            fprintf(stderr, ", HTML report %s", report_path);
        fprintf(stderr, ". Press Ctrl+C to stop.\n");
    } else {
        if (output.io_uring_mode)
            printf("Tracing io_uring");
        else if (offset_text)
            printf("Tracing %s+0x%zx", target_path, function_offset);
        else
            printf("Tracing %s:%s", target_path, function_name);
        if (target_pid > 0)
            printf(" in PID %d", target_pid);
        else
            printf(" in all processes");
        if (output.io_uring_mode)
            printf(", submit-to-CQE latency enabled");
        if (output.io_uring_min_latency_ns) {
            printf(",");
            print_interval("min-io-latency",
                           output.io_uring_min_latency_ns);
        }
        if (output.io_uring_errors_only)
            printf(", io errors only");
        if (output.io_uring_top)
            printf(", top %u submit groups",
                   output.io_uring_top);
        if (output.io_uring_callback_name)
            printf(", CQE -> callback %s arg%u",
                   output.io_uring_callback_name, io_callback_arg);
        if (output.show_return_value)
            printf(", return values enabled");
        if (output.show_duration)
            printf(", timing enabled");
        if (output.show_attribution)
            printf(", scheduler attribution enabled");
        if (async_hop_count)
            printf(", %zu async hop%s enabled", async_hop_count,
                   async_hop_count == 1 ? "" : "s");
        else if (output.show_async) {
            if (async_target_arg)
                printf(", async source %s:%s arg%u -> target arg%u",
                       async_source_path, async_source_name,
                       async_source_arg, async_target_arg);
            else
                printf(", async source %s:%s arg%u -> target auto",
                       async_source_path, async_source_name,
                       async_source_arg);
        }
        if (output.show_discovery) {
            if (async_target_arg)
                printf(", async discovery enabled for target arg%u",
                       async_target_arg);
            else
                printf(", async discovery enabled for target auto");
        }
        if (output.min_total_ns) {
            printf(",");
            print_interval("min-total", output.min_total_ns);
        }
        if (output.min_queue_ns) {
            printf(",");
            print_interval("min-queue", output.min_queue_ns);
        }
        if (output.min_work_ns) {
            printf(",");
            print_interval("min-work", output.min_work_ns);
        }
        if (output.max_events)
            printf(", max events %u", output.max_events);
        if (duration_seconds)
            printf(", duration %u s", duration_seconds);
        if (report_path)
            printf(", HTML report %s", report_path);
        printf(". Press Ctrl+C to stop.\n");
    }

    if (duration_seconds)
        stop_time_ns = monotonic_time_ns() +
                       (uint64_t)duration_seconds * 1000000000ULL;
    output.diagnostic_last_ns = monotonic_time_ns();
    while (!exiting) {
        error = ring_buffer__poll(ring_buffer, 250);
        if (error == -EINTR) {
            error = 0;
            if (exiting)
                break;
            continue;
        }
        if (target_process_exited(&output)) {
            error = 0;
            fprintf(output.json_output ? stderr : stdout,
                    "Target PID %d exited; stopping trace.\n",
                    target_pid);
            break;
        }
        if (error < 0) {
            fprintf(stderr, "ring buffer polling failed: %s\n",
                    strerror(-error));
            break;
        }
        error = 0;
        if (output.show_async && output.diagnostic_interval_ms) {
            uint64_t now = monotonic_time_ns();

            if (now - output.diagnostic_last_ns >=
                (uint64_t)output.diagnostic_interval_ms * 1000000ULL)
                print_queue_diagnostics(&output, false);
        }
        if (stop_time_ns && monotonic_time_ns() >= stop_time_ns)
            break;
    }
    if (ring_buffer && output.io_uring_callback_name && !force_exit) {
        int consume_error = ring_buffer__consume(ring_buffer);

        if (consume_error < 0 && !error)
            error = consume_error;
    }

cleanup:
    if (output.io_uring_mode)
        detach_io_uring_links(skeleton);
    if (interrupt_count == 1 && !force_exit &&
        output.io_uring_mode && output.io_uring_top)
        fprintf(output.json_output ? stderr : stdout,
                "Capture stopped; resolving unique top stacks. "
                "Press Ctrl+C again to exit immediately.\n");
    if (output.show_async && output.diagnostic_last_ns &&
        output.async_hop_stats_map_fd >= 0)
        print_queue_diagnostics(&output, true);
    if (output.io_uring_mode && output.diagnostic_last_ns &&
        output.io_uring_counters_map_fd >= 0 && !force_exit)
        print_io_uring_summary(&output);
    if (output.report_stream) {
        struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS];
        struct async_hop_stats raw[MAX_ASYNC_HOPS];
        size_t diagnostic_count =
            read_queue_diagnostics(&output, diagnostics, raw);

        if ((cw_html_report_end(output.report_stream, diagnostics,
                                diagnostic_count) ||
             fflush(output.report_stream)) && !error) {
            error = -(errno ? errno : EIO);
            fprintf(stderr, "failed to finalize HTML report: %s\n",
                    strerror(-error));
        }
        if (fclose(output.report_stream) && !error)
            error = -errno;
    }
    if (output.json_stream) {
        if (output.io_uring_mode && !force_exit) {
            if (write_io_uring_summary_json(&output) && !error)
                error = -(errno ? errno : EIO);
        } else if (!output.io_uring_mode) {
            struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS];
            struct async_hop_stats raw[MAX_ASYNC_HOPS];
            size_t diagnostic_count =
                read_queue_diagnostics(&output, diagnostics, raw);

            if ((cw_write_queue_diagnostics_json(
                     output.json_stream, diagnostics, diagnostic_count) ||
                 fputc('\n', output.json_stream) == EOF) && !error)
                error = -(errno ? errno : EIO);
        }
        if (fflush(output.json_stream) && !error)
            error = -errno;
        if (output.json_stream != stdout &&
            fclose(output.json_stream) && !error)
            error = -errno;
    }
    if (output.export_failed && !error)
        error = -EIO;
    while (async_link_count)
        bpf_link__destroy(async_links[--async_link_count]);
    if (ring_buffer)
        ring_buffer__free(ring_buffer);
    if (skeleton)
        callweave_bpf__destroy(skeleton);
    if (output.target_pidfd >= 0)
        close(output.target_pidfd);
    if (output.io_uring_maps) {
        map_list_free(output.io_uring_maps);
        free(output.io_uring_maps);
    }
    free(output.io_uring_resources);
    free_async_hops(async_hops, async_hop_count);
    free(configured_function);
    return error ? 1 : 0;
}
