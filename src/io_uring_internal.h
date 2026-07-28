// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_IO_URING_INTERNAL_H
#define CALLWEAVE_IO_URING_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "callweave_internal.h"

const char *cw_io_uring_opcode_name(uint8_t opcode);
int cw_io_uring_write_json_string(
    FILE *stream, const char *text, size_t size);
struct map_list *cw_io_uring_get_maps(
    struct output_options *output,
    const struct io_uring_event *event);
void cw_io_uring_cache_fd_resource(
    struct output_options *output, int fd);
void cw_io_uring_resolve_fd_resource(
    const struct output_options *output, int fd,
    char *buffer, size_t size);

#endif
