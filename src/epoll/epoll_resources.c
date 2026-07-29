// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include <bpf/bpf.h>

#include "callweave_internal.h"
#include "core/fd_resources.h"
#include "epoll/epoll.h"

static uint32_t seed_fd_generation(
    struct output_options *output, uint32_t pid, int fd)
{
    struct cw_epoll_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    uint32_t generation = 1;

    if (output->epoll_fd_generation_map_fd < 0)
        return generation;
    if (!bpf_map_lookup_elem(
            output->epoll_fd_generation_map_fd,
            &key, &generation))
        return generation;
    generation = 1;
    bpf_map_update_elem(
        output->epoll_fd_generation_map_fd,
        &key, &generation, BPF_NOEXIST);
    return generation;
}

struct seed_pass_result {
    uint32_t epoll_fds;
    uint32_t registrations;
    uint32_t conflicts;
    uint32_t failures;
};

static void seed_wake_fd(
    struct output_options *output, uint32_t pid,
    int fd, const char *target)
{
    struct cw_epoll_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    struct cw_epoll_fd_metadata metadata = {
        .clock_id = -1,
    };
    char path[80];
    char line[256];
    FILE *file;

    if (output->epoll_fd_metadata_map_fd < 0)
        return;
    if (!strcmp(target, "anon_inode:[eventfd]")) {
        metadata.kind = CW_EPOLL_WAKE_EVENTFD;
    } else if (!strcmp(target, "anon_inode:[timerfd]")) {
        metadata.kind = CW_EPOLL_WAKE_TIMERFD;
    } else if (!strcmp(target, "anon_inode:[signalfd]")) {
        metadata.kind = CW_EPOLL_WAKE_SIGNALFD;
    } else {
        return;
    }
    snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d",
             (int)output->target_pid, fd);
    file = fopen(path, "r");
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            if (metadata.kind == CW_EPOLL_WAKE_SIGNALFD) {
                unsigned long long mask;

                if (sscanf(line, "sigmask: %llx", &mask) == 1)
                    metadata.signal_mask = (uint64_t)mask;
            } else if (metadata.kind == CW_EPOLL_WAKE_TIMERFD) {
                int clock_id;

                if (sscanf(line, "clockid: %d", &clock_id) == 1)
                    metadata.clock_id = clock_id;
            }
        }
        fclose(file);
    }
    bpf_map_update_elem(
        output->epoll_fd_metadata_map_fd,
        &key, &metadata, BPF_NOEXIST);
}

static int seed_registration(
    struct output_options *output, uint32_t pid,
    int epoll_fd, int fd, uint32_t events, uint64_t data,
    bool *conflict)
{
    uint32_t epoll_generation =
        seed_fd_generation(output, pid, epoll_fd);
    uint32_t fd_generation =
        seed_fd_generation(output, pid, fd);
    struct cw_epoll_resource_key resource_key = {
        .pid = pid,
        .epoll_fd = epoll_fd,
        .epoll_generation = epoll_generation,
        .fd = fd,
        .fd_generation = fd_generation,
    };
    struct cw_epoll_registration registration = {
        .data = data,
        .events = events,
    };
    struct cw_epoll_token_key token_key = {
        .data = data,
        .pid = pid,
        .epoll_fd = epoll_fd,
        .epoll_generation = epoll_generation,
    };
    struct cw_epoll_token_value token = {
        .fd = fd,
        .fd_generation = fd_generation,
    };
    struct cw_epoll_token_value existing_token;
    struct cw_epoll_registration current_registration;
    struct cw_epoll_resource_stats current_stats;
    struct cw_epoll_resource_stats stats = {
        .data = data,
        .interest_events = events,
        .registrations = 1,
        .active = 1,
        .dispatch_stack_id = -1,
    };

    *conflict = false;
    /*
     * A BPF-observed ADD/MOD/DEL wins over this fdinfo snapshot. The resource
     * stats entry acts as the arbitration marker because the BPF path creates
     * one even for a previously unseen DEL.
     */
    if (bpf_map_update_elem(
            output->epoll_resource_stats_map_fd,
            &resource_key, &stats, BPF_NOEXIST)) {
        if (errno == EEXIST)
            return 0;
        return -1;
    }
#ifdef EPOLLEXCLUSIVE
    if ((events & EPOLLEXCLUSIVE) &&
        output->epoll_instance_stats_map_fd >= 0) {
        struct cw_epoll_instance_key instance_key = {
            .pid = pid,
            .epoll_fd = epoll_fd,
            .epoll_generation = epoll_generation,
        };
        struct cw_epoll_instance_stats instance = {
            .exclusive_resources = 1,
        };

        bpf_map_update_elem(
            output->epoll_instance_stats_map_fd,
            &instance_key, &instance, BPF_NOEXIST);
    }
#endif
    if (bpf_map_update_elem(
            output->epoll_token_map_fd, &token_key,
            &token, BPF_NOEXIST)) {
        if (errno != EEXIST ||
            bpf_map_lookup_elem(
                output->epoll_token_map_fd,
                &token_key, &existing_token))
            return -1;
        if (existing_token.fd != fd) {
            token.fd = -1;
            token.ambiguous = 1;
            if (bpf_map_update_elem(
                    output->epoll_token_map_fd,
                    &token_key, &token, BPF_ANY))
                return -1;
            *conflict = true;
        }
    }
    if (bpf_map_update_elem(
            output->epoll_registration_map_fd,
            &resource_key, &registration, BPF_NOEXIST) &&
        errno != EEXIST)
        return -1;

    /*
     * Recheck after seeding. A concurrent MOD/DEL may have changed the marker
     * after fdinfo was read but before the token and registration were added.
     */
    if (!bpf_map_lookup_elem(
            output->epoll_resource_stats_map_fd,
            &resource_key, &current_stats) &&
        (!current_stats.active || current_stats.data != data)) {
        if (!bpf_map_lookup_elem(
                output->epoll_token_map_fd,
                &token_key, &existing_token) &&
            existing_token.fd == fd &&
            existing_token.fd_generation == fd_generation)
            bpf_map_delete_elem(
                output->epoll_token_map_fd, &token_key);
        if (!bpf_map_lookup_elem(
                output->epoll_registration_map_fd,
                &resource_key, &current_registration) &&
            current_registration.data == data)
            bpf_map_delete_elem(
                output->epoll_registration_map_fd, &resource_key);
    }
    cw_fd_cache_one(&output->fd_resources, output->target_pid, fd);
    return 1;
}

static void seed_epoll_fd(
    struct output_options *output, uint32_t pid, int epoll_fd,
    struct seed_pass_result *result)
{
    char path[80];
    char line[512];
    FILE *file;

    snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d",
             (int)output->target_pid, epoll_fd);
    file = fopen(path, "r");
    if (!file) {
        result->failures++;
        return;
    }
    result->epoll_fds++;
    while (fgets(line, sizeof(line), file)) {
        unsigned long long raw_events;
        unsigned long long data;
        bool conflict;
        int fd;
        int seeded;

        if (sscanf(line,
                   "tfd: %d events: %llx data: %llx",
                   &fd, &raw_events, &data) != 3)
            continue;
        seeded = seed_registration(
            output, pid, epoll_fd, fd,
            (uint32_t)raw_events, (uint64_t)data, &conflict);
        if (seeded > 0)
            result->registrations++;
        else if (seeded < 0)
            result->failures++;
        if (conflict)
            result->conflicts++;
    }
    if (ferror(file))
        result->failures++;
    fclose(file);
}

static bool seed_existing_pass(
    struct output_options *output, struct seed_pass_result *result)
{
    char directory_path[64];
    struct dirent *entry;
    DIR *directory;

    snprintf(directory_path, sizeof(directory_path), "/proc/%d/fd",
             (int)output->target_pid);
    directory = opendir(directory_path);
    if (!directory)
        return false;
    while ((entry = readdir(directory)) != NULL) {
        char link_path[96];
        char target[PATH_MAX];
        char *end = NULL;
        ssize_t length;
        long fd;

        errno = 0;
        fd = strtol(entry->d_name, &end, 10);
        if (errno || end == entry->d_name || *end ||
            fd < 0 || fd > INT_MAX)
            continue;
        snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%ld",
                 (int)output->target_pid, fd);
        length = readlink(link_path, target, sizeof(target) - 1);
        if (length < 0)
            continue;
        target[length] = '\0';
        seed_wake_fd(
            output, (uint32_t)output->target_pid,
            (int)fd, target);
        if (!strcmp(target, "anon_inode:[eventpoll]"))
            seed_epoll_fd(
                output, (uint32_t)output->target_pid, (int)fd,
                result);
    }
    closedir(directory);
    return true;
}

void cw_epoll_seed_existing(struct output_options *output)
{
    unsigned pass;

    if (!output || output->target_pid <= 0 ||
        output->epoll_registration_map_fd < 0 ||
        output->epoll_token_map_fd < 0 ||
        output->epoll_resource_stats_map_fd < 0 ||
        output->epoll_fd_generation_map_fd < 0 ||
        output->epoll_fd_metadata_map_fd < 0)
        return;
    output->epoll_bootstrap_scans = 0;
    output->epoll_bootstrap_fds = 0;
    output->epoll_bootstrap_registrations = 0;
    output->epoll_bootstrap_conflicts = 0;
    output->epoll_bootstrap_failures = 0;
    /*
     * Programs are attached before this function runs. Two snapshots catch
     * registrations created while the first /proc walk is in progress; live
     * BPF updates remain authoritative through BPF_NOEXIST arbitration.
     */
    for (pass = 0; pass < 2; pass++) {
        struct seed_pass_result result = {0};

        if (!seed_existing_pass(output, &result)) {
            output->epoll_bootstrap_failures++;
            continue;
        }
        output->epoll_bootstrap_scans++;
        if (result.epoll_fds > output->epoll_bootstrap_fds)
            output->epoll_bootstrap_fds = result.epoll_fds;
        output->epoll_bootstrap_registrations +=
            result.registrations;
        output->epoll_bootstrap_conflicts += result.conflicts;
        output->epoll_bootstrap_failures += result.failures;
    }
}
