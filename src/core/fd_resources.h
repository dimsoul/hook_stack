// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_FD_RESOURCES_H
#define CALLWEAVE_FD_RESOURCES_H

#include <limits.h>
#include <stddef.h>
#include <sys/types.h>

struct cw_fd_resource {
    int fd;
    char path[PATH_MAX];
};

struct cw_fd_cache {
    struct cw_fd_resource *items;
    size_t count;
    size_t capacity;
};

void cw_fd_cache_all(struct cw_fd_cache *cache, pid_t pid);
void cw_fd_cache_one(struct cw_fd_cache *cache, pid_t pid, int fd);
void cw_fd_resolve(const struct cw_fd_cache *cache, pid_t pid, int fd,
                   char *buffer, size_t size);
void cw_fd_cache_destroy(struct cw_fd_cache *cache);

#endif
