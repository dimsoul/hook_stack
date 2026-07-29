// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_IO_URING_H
#define CALLWEAVE_IO_URING_H

#include <stdbool.h>
#include <stddef.h>

struct output_options;

int cw_io_uring_handle_event(void *context, void *data, size_t data_size);
int cw_io_uring_handle_callback_event(
    void *context, void *data, size_t data_size);
void cw_io_uring_cache_resources(struct output_options *output);
bool cw_io_uring_print_summary(struct output_options *output);
int cw_io_uring_write_summary_json(struct output_options *output);

#endif
