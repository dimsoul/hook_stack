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

#include "core/fd_resources.h"

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

static bool resolve_live_fd(
    pid_t pid, int fd, char *buffer, size_t size)
{
    char path[64];
    ssize_t length;

    if (fd < 0 || pid <= 0)
        return false;
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", (int)pid, fd);
    length = readlink(path, buffer, size - 1);
    if (length < 0)
        return false;
    buffer[length] = '\0';
    enrich_socket_resource(pid, buffer, size);
    return true;
}

void cw_fd_resolve(const struct cw_fd_cache *cache, pid_t pid, int fd,
                   char *buffer, size_t size)
{
    size_t index;

    if (!buffer || !size)
        return;
    buffer[0] = '\0';
    for (index = 0; cache && index < cache->count; index++) {
        if (cache->items[index].fd == fd) {
            snprintf(buffer, size, "%s", cache->items[index].path);
            return;
        }
    }
    resolve_live_fd(pid, fd, buffer, size);
}

void cw_fd_cache_one(struct cw_fd_cache *cache, pid_t pid, int fd)
{
    struct cw_fd_resource *resized;
    char resource[PATH_MAX];
    size_t next_capacity;
    size_t index;

    if (!cache || fd < 0)
        return;
    if (!resolve_live_fd(pid, fd, resource, sizeof(resource)))
        return;
    for (index = 0; index < cache->count; index++) {
        if (cache->items[index].fd == fd) {
            snprintf(cache->items[index].path, PATH_MAX,
                     "%s", resource);
            return;
        }
    }
    if (cache->count == cache->capacity) {
        next_capacity = cache->capacity ? cache->capacity * 2 : 16;
        resized = realloc(
            cache->items, next_capacity * sizeof(*resized));
        if (!resized)
            return;
        cache->items = resized;
        cache->capacity = next_capacity;
    }
    cache->items[cache->count].fd = fd;
    snprintf(cache->items[cache->count].path, PATH_MAX, "%s", resource);
    cache->count++;
}

void cw_fd_cache_all(struct cw_fd_cache *cache, pid_t pid)
{
    char directory_path[64];
    struct dirent *entry;
    DIR *directory;

    if (!cache || pid <= 0)
        return;
    snprintf(directory_path, sizeof(directory_path), "/proc/%d/fd",
             (int)pid);
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
        cw_fd_cache_one(cache, pid, (int)fd);
    }
    closedir(directory);
}

void cw_fd_cache_destroy(struct cw_fd_cache *cache)
{
    if (!cache)
        return;
    free(cache->items);
    cache->items = NULL;
    cache->count = 0;
    cache->capacity = 0;
}
