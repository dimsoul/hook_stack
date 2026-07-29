// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include "callweave_internal.h"
#include "core/fd_resources.h"
#include "io_uring.h"
#include "io_uring_internal.h"

struct map_list *cw_io_uring_get_maps(
    struct output_options *output,
    const struct io_uring_event *event)
{
    struct map_list *maps;
    uint32_t maps_pid = event->submit_pid;

    if (output->target_maps &&
        output->target_maps_pid == maps_pid)
        return output->target_maps;

    if (output->target_maps) {
        map_list_free(output->target_maps);
        free(output->target_maps);
        output->target_maps = NULL;
        output->target_maps_pid = 0;
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
    output->target_maps = maps;
    output->target_maps_pid = maps_pid;
    return maps;
}

void cw_io_uring_resolve_fd_resource(
    const struct output_options *output, int fd,
    char *buffer, size_t size)
{
    cw_fd_resolve(&output->fd_resources, output->target_pid,
                  fd, buffer, size);
}

void cw_io_uring_cache_fd_resource(
    struct output_options *output, int fd)
{
    cw_fd_cache_one(&output->fd_resources, output->target_pid, fd);
}

void cw_io_uring_cache_resources(
    struct output_options *output)
{
    cw_fd_cache_all(&output->fd_resources, output->target_pid);
}
