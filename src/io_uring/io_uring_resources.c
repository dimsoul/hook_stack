// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "callweave_internal.h"
#include "io_uring.h"
#include "io_uring_internal.h"
struct map_list *cw_io_uring_get_maps(
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

void cw_io_uring_resolve_fd_resource(
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

void cw_io_uring_cache_fd_resource(
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
    cw_io_uring_resolve_fd_resource(
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

void cw_io_uring_cache_resources(
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
        cw_io_uring_cache_fd_resource(output, (int)fd);
    }
    closedir(directory);
}

void cw_io_uring_cleanup(struct output_options *output)
{
    if (output->io_uring_maps) {
        map_list_free(output->io_uring_maps);
        free(output->io_uring_maps);
        output->io_uring_maps = NULL;
    }
    free(output->io_uring_resources);
    output->io_uring_resources = NULL;
    output->io_uring_resource_count = 0;
    output->io_uring_resource_capacity = 0;
}
