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
#include <pwd.h>
#include <grp.h>
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

#include "core/core_config.h"
#include "async/async_config.h"
#include "epoll/epoll_config.h"
#include "io_uring/io_uring_config.h"
#include "callweave.skel.h"
#include "async/async_events.h"
#include "async/async_output.h"
#include "callweave_internal.h"
#include "config.h"
#include "epoll/epoll.h"
#include "io_uring/io_uring.h"
#include "report.h"
#include "symbols.h"

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

    skeleton->rodata->cw_target_cfg.pidns_dev = (uint64_t)namespace_status.st_dev;
    skeleton->rodata->cw_target_cfg.pidns_ino = (uint64_t)namespace_status.st_ino;
    return 0;
}

static void add_epoll_io_syscall(
    struct cw_epoll_config *config, int syscall_nr,
    enum cw_epoll_io_operation operation)
{
    uint32_t index = config->io_syscall_count;

    if (index >= CW_EPOLL_MAX_IO_SYSCALLS)
        return;
    config->io_syscalls[index].syscall_nr = syscall_nr;
    config->io_syscalls[index].operation = operation;
    config->io_syscall_count++;
}

static void configure_epoll_io_syscalls(
    struct cw_epoll_config *config)
{
#ifdef SYS_read
    add_epoll_io_syscall(config, SYS_read, CW_EPOLL_IO_READ);
#endif
#ifdef SYS_readv
    add_epoll_io_syscall(config, SYS_readv, CW_EPOLL_IO_READV);
#endif
#ifdef SYS_recvfrom
    add_epoll_io_syscall(config, SYS_recvfrom, CW_EPOLL_IO_RECVFROM);
#endif
#ifdef SYS_recvmsg
    add_epoll_io_syscall(config, SYS_recvmsg, CW_EPOLL_IO_RECVMSG);
#endif
#ifdef SYS_recvmmsg
    add_epoll_io_syscall(config, SYS_recvmmsg, CW_EPOLL_IO_RECVMMSG);
#endif
#ifdef SYS_write
    add_epoll_io_syscall(config, SYS_write, CW_EPOLL_IO_WRITE);
#endif
#ifdef SYS_writev
    add_epoll_io_syscall(config, SYS_writev, CW_EPOLL_IO_WRITEV);
#endif
#ifdef SYS_sendto
    add_epoll_io_syscall(config, SYS_sendto, CW_EPOLL_IO_SENDTO);
#endif
#ifdef SYS_sendmsg
    add_epoll_io_syscall(config, SYS_sendmsg, CW_EPOLL_IO_SENDMSG);
#endif
#ifdef SYS_sendmmsg
    add_epoll_io_syscall(config, SYS_sendmmsg, CW_EPOLL_IO_SENDMMSG);
#endif
#ifdef SYS_accept
    add_epoll_io_syscall(config, SYS_accept, CW_EPOLL_IO_ACCEPT);
#endif
#ifdef SYS_accept4
    add_epoll_io_syscall(config, SYS_accept4, CW_EPOLL_IO_ACCEPT4);
#endif
#ifdef SYS_connect
    add_epoll_io_syscall(config, SYS_connect, CW_EPOLL_IO_CONNECT);
#endif
#ifdef SYS_close
    add_epoll_io_syscall(config, SYS_close, CW_EPOLL_IO_CLOSE);
#endif
#ifdef SYS_dup
    add_epoll_io_syscall(config, SYS_dup, CW_EPOLL_IO_DUP);
#endif
#ifdef SYS_dup2
    add_epoll_io_syscall(config, SYS_dup2, CW_EPOLL_IO_DUP2);
#endif
#ifdef SYS_dup3
    add_epoll_io_syscall(config, SYS_dup3, CW_EPOLL_IO_DUP3);
#endif
#ifdef SYS_fcntl
    add_epoll_io_syscall(config, SYS_fcntl, CW_EPOLL_IO_FCNTL_DUP);
#endif
#ifdef SYS_splice
    add_epoll_io_syscall(config, SYS_splice, CW_EPOLL_IO_SPLICE);
#endif
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
            "warning: optional tracepoint %s unavailable: %s\n",
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

static void detach_epoll_links(struct callweave_bpf *skeleton)
{
    if (!skeleton)
        return;
    detach_link(&skeleton->links.trace_epoll_sys_enter);
    detach_link(&skeleton->links.trace_epoll_sys_exit);
    detach_link(&skeleton->links.trace_epoll_wake_sys_enter);
    detach_link(&skeleton->links.trace_epoll_wake_sys_exit);
    detach_link(&skeleton->links.trace_epoll_signal_generate);
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
            "  %s -p PID --epoll\n"
            "  %s --epoll --exec PROGRAM -- [ARGS...]\n"
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
            "      --epoll               trace epoll waits, dispatch, and "
            "resources\n"
            "      --exec PROGRAM         launch PROGRAM after epoll tracing "
            "is ready;\n"
            "                             put its arguments after `--`\n"
            "      --min-epoll-wait-us US only emit waits at least US\n"
            "      --min-epoll-dispatch-us US\n"
            "                             only emit ready-to-I/O dispatches "
            "at least US\n"
            "      --epoll-top N          show N busiest event-loop "
            "call sites (default 5)\n"
            "  -h, --help                show this help\n"
            "\n"
            "When -p is used without --binary or --module, /proc/PID/exe is used.\n"
            "Without -p, an explicit BINARY is required except for "
            "--epoll --exec.\n",
            program, program, program, program, program, program, program,
            program, program, program);
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

int parse_u32_range(const char *text, uint32_t minimum,
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

struct launched_target {
    pid_t pid;
    int exec_status_fd;
    bool resumed;
};

static int parse_identity(const char *text, unsigned long *identity)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !text[0])
        return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end)
        return -1;
    *identity = value;
    return 0;
}

static int restore_sudo_identity(void)
{
    const char *uid_text = getenv("SUDO_UID");
    const char *gid_text = getenv("SUDO_GID");
    unsigned long uid_value;
    unsigned long gid_value;
    struct passwd *account;
    uid_t uid;
    gid_t gid;

    if (geteuid() || !uid_text || !gid_text)
        return 0;
    if (parse_identity(uid_text, &uid_value) ||
        parse_identity(gid_text, &gid_value) ||
        (uid_t)uid_value != uid_value ||
        (gid_t)gid_value != gid_value)
        return -EINVAL;
    uid = (uid_t)uid_value;
    gid = (gid_t)gid_value;
    account = getpwuid(uid);
    if (account) {
        if (initgroups(account->pw_name, gid))
            return -errno;
    } else if (setgroups(0, NULL)) {
        return -errno;
    }
    if (setgid(gid) || setuid(uid))
        return -errno;
    return 0;
}

static int launch_target_suspended(
    const char *path, char *const child_argv[],
    struct launched_target *target)
{
    int status_pipe[2] = {-1, -1};
    int status;
    pid_t pid;

    if (pipe2(status_pipe, O_CLOEXEC))
        return -errno;
    pid = fork();
    if (pid < 0) {
        int error = -errno;

        close(status_pipe[0]);
        close(status_pipe[1]);
        return error;
    }
    if (!pid) {
        int child_error;
        ssize_t written;

        close(status_pipe[0]);
        if (raise(SIGSTOP))
            _exit(127);
        child_error = restore_sudo_identity();
        if (!child_error) {
            execvp(path, child_argv);
            child_error = -errno;
        }
        child_error = -child_error;
        written = write(status_pipe[1], &child_error,
                        sizeof(child_error));
        (void)written;
        _exit(127);
    }
    close(status_pipe[1]);
    do {
        status = 0;
        if (waitpid(pid, &status, WUNTRACED) >= 0)
            break;
    } while (errno == EINTR);
    if (!WIFSTOPPED(status)) {
        close(status_pipe[0]);
        (void)waitpid(pid, NULL, WNOHANG);
        return -ECHILD;
    }
    target->pid = pid;
    target->exec_status_fd = status_pipe[0];
    target->resumed = false;
    return 0;
}

static int resume_launched_target(struct launched_target *target)
{
    int child_error = 0;
    ssize_t length;

    if (!target || target->pid <= 0 || target->exec_status_fd < 0)
        return -EINVAL;
    if (kill(target->pid, SIGCONT))
        return -errno;
    target->resumed = true;
    do {
        length = read(target->exec_status_fd, &child_error,
                      sizeof(child_error));
    } while (length < 0 && errno == EINTR);
    close(target->exec_status_fd);
    target->exec_status_fd = -1;
    if (!length)
        return 0;
    if (length == (ssize_t)sizeof(child_error) && child_error > 0)
        return -child_error;
    return length < 0 ? -errno : -EIO;
}

static void stop_launched_target(struct launched_target *target)
{
    struct timespec pause = {
        .tv_nsec = 25000000,
    };
    unsigned attempt;
    pid_t result;

    if (!target)
        return;
    if (target->exec_status_fd >= 0) {
        close(target->exec_status_fd);
        target->exec_status_fd = -1;
    }
    if (target->pid <= 0)
        return;
    result = waitpid(target->pid, NULL, WNOHANG);
    if (result == target->pid) {
        target->pid = -1;
        return;
    }
    kill(target->pid, target->resumed ? SIGTERM : SIGKILL);
    for (attempt = 0; attempt < 20; attempt++) {
        result = waitpid(target->pid, NULL, WNOHANG);
        if (result == target->pid)
            break;
        nanosleep(&pause, NULL);
    }
    if (result != target->pid) {
        kill(target->pid, SIGKILL);
        do {
            result = waitpid(target->pid, NULL, 0);
        } while (result < 0 && errno == EINTR);
    }
    target->pid = -1;
}

static uint64_t timespec_nanoseconds(const struct timespec *time)
{
    return (uint64_t)time->tv_sec * 1000000000ULL +
           (uint64_t)time->tv_nsec;
}

uint64_t event_realtime_nanoseconds(uint64_t timestamp_ns)
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

void print_event_time(uint64_t timestamp_ns)
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

uint64_t monotonic_time_ns(void)
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

void print_interval(const char *label, uint64_t nanoseconds)
{
    fprint_interval(stdout, label, nanoseconds);
}

void format_interval(char *buffer, size_t size, uint64_t nanoseconds)
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
    OPT_EPOLL,
    OPT_MIN_EPOLL_WAIT_US,
    OPT_MIN_EPOLL_DISPATCH_US,
    OPT_EPOLL_TOP,
    OPT_EXEC,
};

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
        {"epoll", no_argument, NULL, OPT_EPOLL},
        {"min-epoll-wait-us", required_argument, NULL,
         OPT_MIN_EPOLL_WAIT_US},
        {"min-epoll-dispatch-us", required_argument, NULL,
         OPT_MIN_EPOLL_DISPATCH_US},
        {"epoll-top", required_argument, NULL, OPT_EPOLL_TOP},
        {"exec", required_argument, NULL, OPT_EXEC},
        {0, 0, 0, 0},
    };
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
    };
    struct bpf_uprobe_opts return_options = {
        .sz = sizeof(return_options),
        .retprobe = true,
    };
    struct cw_capture_control control =
        CW_CAPTURE_CONTROL_INITIALIZER;
    struct output_options output = {
        .control = &control,
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
        .epoll_stack_map_fd = -1,
        .epoll_counters_map_fd = -1,
        .epoll_loop_stats_map_fd = -1,
        .epoll_resource_stats_map_fd = -1,
        .epoll_registration_map_fd = -1,
        .epoll_token_map_fd = -1,
        .epoll_fd_generation_map_fd = -1,
        .epoll_instance_stats_map_fd = -1,
        .epoll_fd_metadata_map_fd = -1,
        .target_pidfd = -1,
        .diagnostic_interval_ms = 1000,
        .epoll_top = 5,
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
    const char *exec_path = NULL;
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
    struct launched_target launched = {
        .pid = -1,
        .exec_status_fd = -1,
    };
    char **exec_argv = NULL;
    bool async_option_seen = false;
    bool io_callback_option_seen = false;
    bool epoll_top_option_seen = false;
    bool check_config = false;
    bool json_output = false;
    bool finalize_outputs = true;
    int remaining_arguments;
    int option;
    int error = 0;
    int argument_index;

    for (argument_index = 1; argument_index < argc; argument_index++) {
        const char *argument = argv[argument_index];

        if (!strcmp(argument, "--")) {
            break;
        } else if (!strcmp(argument, "--config")) {
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
        case OPT_EPOLL:
            output.epoll_mode = true;
            break;
        case OPT_MIN_EPOLL_WAIT_US:
            if (parse_cli_us("--min-epoll-wait-us", optarg,
                             &output.epoll_min_wait_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MIN_EPOLL_DISPATCH_US:
            if (parse_cli_us("--min-epoll-dispatch-us", optarg,
                             &output.epoll_min_dispatch_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_EPOLL_TOP:
            epoll_top_option_seen = true;
            if (parse_u32_range(optarg, 1, 1000,
                                &output.epoll_top)) {
                fprintf(stderr, "invalid --epoll-top value: %s\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_EXEC:
            if (exec_path) {
                fprintf(stderr, "--exec may appear only once\n");
                error = 2;
                goto cleanup;
            }
            exec_path = optarg;
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
    if (json_output && !output.show_async && !output.io_uring_mode &&
        !output.epoll_mode) {
        fprintf(stderr,
                "--format json requires async tracing, --io-uring, "
                "or --epoll\n");
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
         !output.io_uring_mode && !output.epoll_mode)) {
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

    if (exec_path) {
        if (!exec_path[0]) {
            fprintf(stderr, "--exec PROGRAM must not be empty\n");
            error = 2;
            goto cleanup;
        }
        if (!output.epoll_mode) {
            fprintf(stderr,
                    "--exec is currently supported with standalone "
                    "--epoll mode\n");
            error = 2;
            goto cleanup;
        }
        if (target_pid > 0) {
            fprintf(stderr, "--exec and --pid are mutually exclusive\n");
            error = 2;
            goto cleanup;
        }
    } else {
        error = validate_target_pid(target_pid);
        if (error)
            return 1;
    }

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
    if (!output.epoll_mode &&
        (output.epoll_min_wait_ns ||
         output.epoll_min_dispatch_ns ||
         epoll_top_option_seen)) {
        fprintf(stderr,
                "epoll filters require --epoll\n");
        error = 2;
        goto cleanup;
    }
    if (output.epoll_mode && output.io_uring_mode) {
        fprintf(stderr,
                "--epoll and --io-uring are mutually exclusive "
                "standalone modes\n");
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
    if (output.epoll_mode) {
        if (target_pid <= 0 && !exec_path) {
            fprintf(stderr, "--epoll requires --pid or --exec\n");
            error = 2;
            goto cleanup;
        }
        if ((!exec_path && remaining_arguments) ||
            binary_argument || module_name ||
            find_symbol_name || offset_text || configured_function ||
            output.show_return_value || output.show_duration ||
            output.show_attribution || output.show_async ||
            output.show_discovery || async_source_name ||
            async_source_binary || async_option_seen || async_hop_count ||
            report_path || io_callback_option_seen ||
            output.io_uring_min_latency_ns ||
            output.io_uring_errors_only || output.io_uring_top) {
            fprintf(stderr,
                    "--epoll is a standalone mode; combine it only with "
                    "--pid or --exec, --min-epoll-wait-us, "
                    "--min-epoll-dispatch-us, --epoll-top, "
                    "--duration, --max-events, --format, and --output\n");
            error = 2;
            goto cleanup;
        }
        if (exec_path) {
            size_t index;

            exec_argv = calloc(
                (size_t)remaining_arguments + 2,
                sizeof(*exec_argv));
            if (!exec_argv) {
                error = -ENOMEM;
                goto cleanup;
            }
            exec_argv[0] = (char *)exec_path;
            for (index = 0;
                 index < (size_t)remaining_arguments; index++)
                exec_argv[index + 1] = argv[optind + index];
            error = launch_target_suspended(
                exec_path, exec_argv, &launched);
            if (error) {
                fprintf(stderr, "cannot prepare target %s: %s\n",
                        exec_path, strerror(-error));
                goto cleanup;
            }
            target_pid = launched.pid;
            output.epoll_started_target = true;
            remaining_arguments = 0;
            error = validate_target_pid(target_pid);
            if (error)
                goto cleanup;
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
    if ((output.io_uring_mode || output.epoll_mode) &&
        target_pid > 0 && !output.epoll_started_target) {
        cw_fd_cache_all(&output.fd_resources, target_pid);
        output.target_maps = calloc(1, sizeof(*output.target_maps));
        if (output.target_maps &&
            !read_process_maps((uint32_t)target_pid,
                               output.target_maps)) {
            output.target_maps_pid = (uint32_t)target_pid;
        } else {
            if (output.target_maps) {
                map_list_free(output.target_maps);
                free(output.target_maps);
                output.target_maps = NULL;
            }
        }
    }
    error = cw_capture_control_init(&control);
    if (error) {
        fprintf(stderr, "failed to initialize capture control: %s\n",
                strerror(-error));
        goto cleanup;
    }

    skeleton = callweave_bpf__open();
    if (!skeleton) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        error = -ENOMEM;
        goto cleanup;
    }
    error = configure_pid_namespace(skeleton);
    if (error)
        goto cleanup;
    skeleton->rodata->cw_target_cfg.target_pid =
        target_pid > 0 ? (uint32_t)target_pid : 0;
    skeleton->rodata->cw_trace_cfg.returns_enabled =
        output.show_return_value || output.show_duration;
    skeleton->rodata->cw_trace_cfg.attribution_enabled = output.show_attribution;
    skeleton->rodata->cw_async_cfg.enabled = output.show_async;
    skeleton->rodata->cw_async_cfg.discovery_enabled = output.show_discovery;
    skeleton->rodata->cw_io_uring_cfg.enabled = output.io_uring_mode;
    skeleton->rodata->cw_io_uring_cfg.callback_enabled =
        output.io_uring_callback_name != NULL;
    skeleton->rodata->cw_io_uring_cfg.callback_arg = io_callback_arg;
    skeleton->rodata->cw_io_uring_cfg.min_latency_ns =
        output.io_uring_min_latency_ns;
    skeleton->rodata->cw_io_uring_cfg.errors_only =
        output.io_uring_errors_only;
    skeleton->rodata->cw_epoll_cfg.enabled = output.epoll_mode;
    skeleton->rodata->cw_epoll_cfg.min_wait_ns =
        output.epoll_min_wait_ns;
    skeleton->rodata->cw_epoll_cfg.min_dispatch_ns =
        output.epoll_min_dispatch_ns;
    skeleton->rodata->cw_epoll_cfg.wait_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.pwait_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.pwait2_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.ctl_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.eventfd_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.eventfd2_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.timerfd_create_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.timerfd_settime_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.signalfd_syscall_nr = -1;
    skeleton->rodata->cw_epoll_cfg.signalfd4_syscall_nr = -1;
#ifdef SYS_epoll_wait
    skeleton->rodata->cw_epoll_cfg.wait_syscall_nr = SYS_epoll_wait;
#endif
#ifdef SYS_epoll_pwait
    skeleton->rodata->cw_epoll_cfg.pwait_syscall_nr = SYS_epoll_pwait;
#endif
#ifdef SYS_epoll_pwait2
    skeleton->rodata->cw_epoll_cfg.pwait2_syscall_nr = SYS_epoll_pwait2;
#endif
#ifdef SYS_epoll_ctl
    skeleton->rodata->cw_epoll_cfg.ctl_syscall_nr = SYS_epoll_ctl;
#endif
#ifdef SYS_eventfd
    skeleton->rodata->cw_epoll_cfg.eventfd_syscall_nr = SYS_eventfd;
#endif
#ifdef SYS_eventfd2
    skeleton->rodata->cw_epoll_cfg.eventfd2_syscall_nr = SYS_eventfd2;
#endif
#ifdef SYS_timerfd_create
    skeleton->rodata->cw_epoll_cfg.timerfd_create_syscall_nr =
        SYS_timerfd_create;
#endif
#ifdef SYS_timerfd_settime
    skeleton->rodata->cw_epoll_cfg.timerfd_settime_syscall_nr =
        SYS_timerfd_settime;
#endif
#ifdef SYS_signalfd
    skeleton->rodata->cw_epoll_cfg.signalfd_syscall_nr = SYS_signalfd;
#endif
#ifdef SYS_signalfd4
    skeleton->rodata->cw_epoll_cfg.signalfd4_syscall_nr = SYS_signalfd4;
#endif
    configure_epoll_io_syscalls(
        &skeleton->rodata->cw_epoll_cfg);
    skeleton->rodata->cw_async_cfg.source_arg = async_source_arg;
    skeleton->rodata->cw_async_cfg.target_arg = async_target_arg;
    skeleton->rodata->cw_async_cfg.max_age_ns =
        (uint64_t)async_max_age_ms * 1000000ULL;
    skeleton->rodata->cw_async_cfg.final_hop_id =
        output.show_async ?
            (uint32_t)(async_hop_count ? async_hop_count : 1) : 0;
    skeleton->rodata->cw_trace_cfg.futex_syscall_nr = SYS_futex;
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
    }
    if (!output.epoll_mode) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_epoll_sys_enter, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_epoll_sys_exit, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_epoll_wake_sys_enter, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_epoll_wake_sys_exit, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_epoll_signal_generate, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable epoll programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (output.io_uring_mode || output.epoll_mode) {
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
    if (!output.show_attribution && !output.epoll_mode) {
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
    } else if (output.epoll_mode) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_sys_enter, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_sys_exit, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable function wait attribution programs: %s\n",
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
    output.epoll_stack_map_fd =
        bpf_map__fd(skeleton->maps.epoll_stacks);
    output.epoll_counters_map_fd =
        bpf_map__fd(skeleton->maps.epoll_counters);
    output.epoll_loop_stats_map_fd =
        bpf_map__fd(skeleton->maps.epoll_loop_stats);
    output.epoll_resource_stats_map_fd =
        bpf_map__fd(skeleton->maps.epoll_resource_stats);
    output.epoll_registration_map_fd =
        bpf_map__fd(skeleton->maps.epoll_registrations);
    output.epoll_token_map_fd =
        bpf_map__fd(skeleton->maps.epoll_tokens);
    output.epoll_fd_generation_map_fd =
        bpf_map__fd(skeleton->maps.epoll_fd_generations);
    output.epoll_instance_stats_map_fd =
        bpf_map__fd(skeleton->maps.epoll_instance_stats);
    output.epoll_fd_metadata_map_fd =
        bpf_map__fd(skeleton->maps.epoll_fd_metadata);

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
    } else if (output.epoll_mode) {
        error = attach_raw_tracepoint(
            skeleton->progs.trace_epoll_sys_enter,
            &skeleton->links.trace_epoll_sys_enter, "sys_enter");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_epoll_sys_exit,
                &skeleton->links.trace_epoll_sys_exit, "sys_exit");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_epoll_wake_sys_enter,
                &skeleton->links.trace_epoll_wake_sys_enter,
                "sys_enter");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_epoll_wake_sys_exit,
                &skeleton->links.trace_epoll_wake_sys_exit,
                "sys_exit");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_sched_switch,
                &skeleton->links.trace_sched_switch, "sched_switch");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_sched_wakeup,
                &skeleton->links.trace_sched_wakeup, "sched_wakeup");
        if (error)
            goto cleanup;
        attach_optional_raw_tracepoint(
            skeleton->progs.trace_epoll_signal_generate,
            &skeleton->links.trace_epoll_signal_generate,
            "signal_generate");
        cw_epoll_seed_existing(&output);
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

    if (!output.io_uring_mode && !output.epoll_mode) {
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

    {
        int event_map_fd;
        ring_buffer_sample_fn event_handler;

        if (output.io_uring_mode) {
            event_map_fd =
                bpf_map__fd(skeleton->maps.io_uring_events);
            event_handler = cw_io_uring_handle_event;
        } else if (output.epoll_mode) {
            event_map_fd =
                bpf_map__fd(skeleton->maps.epoll_events);
            event_handler = cw_epoll_handle_event;
        } else {
            event_map_fd = bpf_map__fd(skeleton->maps.events);
            event_handler = handle_event;
        }
        ring_buffer = ring_buffer__new(
            event_map_fd, event_handler, &output, NULL);
    }
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
            cw_io_uring_handle_callback_event, &output);
        if (error) {
            fprintf(stderr,
                    "failed to add io_uring callback ring buffer: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (output.epoll_mode) {
        error = ring_buffer__add(
            ring_buffer,
            bpf_map__fd(skeleton->maps.epoll_dispatch_events),
            cw_epoll_handle_dispatch_event, &output);
        if (error) {
            fprintf(stderr,
                    "failed to add epoll dispatch ring buffer: %s\n",
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
        else if (output.epoll_mode)
            fprintf(stderr, "Tracing epoll");
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
        if (output.epoll_min_wait_ns)
            fprintf(stderr, ", minimum epoll wait %.3f us",
                    (double)output.epoll_min_wait_ns / 1000.0);
        if (output.epoll_min_dispatch_ns)
            fprintf(stderr, ", minimum epoll dispatch %.3f us",
                    (double)output.epoll_min_dispatch_ns / 1000.0);
        if (output.epoll_mode)
            fprintf(stderr, ", top %u event loops",
                    output.epoll_top);
        if (output.epoll_started_target)
            fprintf(stderr, ", target launched after tracer readiness");
        else if (output.epoll_mode)
            fprintf(stderr,
                    ", bootstrapped %u registration%s from %u epoll FD%s",
                    output.epoll_bootstrap_registrations,
                    output.epoll_bootstrap_registrations == 1 ? "" : "s",
                    output.epoll_bootstrap_fds,
                    output.epoll_bootstrap_fds == 1 ? "" : "s");
        if (report_path)
            fprintf(stderr, ", HTML report %s", report_path);
        fprintf(stderr, ". Press Ctrl+C to stop.\n");
    } else {
        if (output.io_uring_mode)
            printf("Tracing io_uring");
        else if (output.epoll_mode)
            printf("Tracing epoll");
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
        if (output.epoll_mode)
            printf(", wait-batch and FD resource diagnostics enabled");
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
        if (output.epoll_min_wait_ns) {
            printf(",");
            print_interval("min-epoll-wait",
                           output.epoll_min_wait_ns);
        }
        if (output.epoll_min_dispatch_ns) {
            printf(",");
            print_interval("min-epoll-dispatch",
                           output.epoll_min_dispatch_ns);
        }
        if (output.epoll_mode)
            printf(", top %u event loops", output.epoll_top);
        if (output.epoll_started_target)
            printf(", target launched after tracer readiness");
        else if (output.epoll_mode)
            printf(", bootstrapped %u registration%s from %u epoll FD%s",
                   output.epoll_bootstrap_registrations,
                   output.epoll_bootstrap_registrations == 1 ? "" : "s",
                   output.epoll_bootstrap_fds,
                   output.epoll_bootstrap_fds == 1 ? "" : "s");
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

    if (launched.pid > 0) {
        fflush(output.json_output ? stderr : stdout);
        error = resume_launched_target(&launched);
        if (error) {
            fprintf(stderr, "cannot execute target %s: %s\n",
                    exec_path, strerror(-error));
            goto cleanup;
        }
        /*
         * BPF links and ring buffers are live before SIGCONT. Give the
         * dynamic loader a brief opportunity to establish mappings used for
         * later user-stack symbolization; tracing is already active here.
         */
        usleep(10000);
        cw_fd_cache_all(&output.fd_resources, target_pid);
        output.target_maps = calloc(
            1, sizeof(*output.target_maps));
        if (output.target_maps &&
            !read_process_maps((uint32_t)target_pid,
                               output.target_maps)) {
            output.target_maps_pid = (uint32_t)target_pid;
        } else {
            if (output.target_maps) {
                map_list_free(output.target_maps);
                free(output.target_maps);
                output.target_maps = NULL;
            }
        }
    }

    if (duration_seconds)
        stop_time_ns = monotonic_time_ns() +
                       (uint64_t)duration_seconds * 1000000000ULL;
    output.diagnostic_last_ns = monotonic_time_ns();
    while (cw_capture_running(&control)) {
        int signal_error;

        error = ring_buffer__poll(ring_buffer, 250);
        signal_error = cw_capture_drain_signals(&control);
        if (signal_error) {
            error = signal_error;
            fprintf(stderr, "failed to read capture signal: %s\n",
                    strerror(-error));
            break;
        }
        if (!cw_capture_running(&control)) {
            error = 0;
            break;
        }
        if (error == -EINTR) {
            error = 0;
            continue;
        }
        if (target_process_exited(&output)) {
            error = 0;
            fprintf(output.json_output ? stderr : stdout,
                    "Target PID %d exited; stopping trace.\n",
                    target_pid);
            cw_capture_request_stop(
                &control, CW_STOP_TARGET_EXIT);
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
        } else if (output.epoll_mode &&
                   output.diagnostic_interval_ms) {
            uint64_t now = monotonic_time_ns();

            if (now - output.diagnostic_last_ns >=
                (uint64_t)output.diagnostic_interval_ms * 1000000ULL) {
                cw_fd_cache_all(
                    &output.fd_resources, output.target_pid);
                output.diagnostic_last_ns = now;
            }
        }
        if (stop_time_ns && monotonic_time_ns() >= stop_time_ns) {
            cw_capture_request_stop(&control, CW_STOP_DURATION);
            break;
        }
    }
    if (ring_buffer && output.io_uring_callback_name &&
        cw_capture_should_finalize(&control)) {
        int consume_error = ring_buffer__consume(ring_buffer);

        if (consume_error < 0 && !error)
            error = consume_error;
    }

cleanup:
    cw_capture_drain_signals(&control);
    stop_launched_target(&launched);
    finalize_outputs = cw_capture_should_finalize(&control);
    if (output.io_uring_mode)
        detach_io_uring_links(skeleton);
    if (output.epoll_mode)
        detach_epoll_links(skeleton);
    if (cw_capture_stopped_by_signal(&control) &&
        ((output.io_uring_mode && output.io_uring_top) ||
         (output.epoll_mode && output.epoll_top)))
        fprintf(output.json_output ? stderr : stdout,
                "Capture stopped; resolving unique top stacks. "
                "Press Ctrl+C again to exit immediately.\n");
    if (finalize_outputs && output.show_async &&
        output.diagnostic_last_ns &&
        output.async_hop_stats_map_fd >= 0)
        print_queue_diagnostics(&output, true);
    if (finalize_outputs && output.io_uring_mode &&
        output.diagnostic_last_ns &&
        output.io_uring_counters_map_fd >= 0)
        cw_io_uring_print_summary(&output);
    if (finalize_outputs && output.epoll_mode &&
        output.epoll_counters_map_fd >= 0)
        cw_epoll_print_summary(&output);
    finalize_outputs = !cw_capture_cancelled(&control);
    if (output.report_stream) {
        if (finalize_outputs) {
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
        }
        if (fclose(output.report_stream) && !error)
            error = -errno;
    }
    if (output.json_stream) {
        finalize_outputs = !cw_capture_cancelled(&control);
        if (output.io_uring_mode && finalize_outputs) {
            if (cw_io_uring_write_summary_json(&output) && !error)
                error = -(errno ? errno : EIO);
        } else if (output.epoll_mode && finalize_outputs) {
            if (cw_epoll_write_summary_json(&output) && !error)
                error = -(errno ? errno : EIO);
        } else if (!output.io_uring_mode && finalize_outputs) {
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
    cw_capture_control_destroy(&control);
    if (output.target_maps) {
        map_list_free(output.target_maps);
        free(output.target_maps);
    }
    cw_fd_cache_destroy(&output.fd_resources);
    free_async_hops(async_hops, async_hop_count);
    free(configured_function);
    free(exec_argv);
    return error ? 1 : 0;
}
