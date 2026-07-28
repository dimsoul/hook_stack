// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_ASYNC_OUTPUT_H
#define CALLWEAVE_ASYNC_OUTPUT_H

#include <stdbool.h>
#include <stddef.h>

#include "callweave_internal.h"
#include "report.h"

size_t read_queue_diagnostics(
    const struct output_options *output,
    struct cw_queue_diagnostic diagnostics[MAX_ASYNC_HOPS],
    struct async_hop_stats raw[MAX_ASYNC_HOPS]);
bool print_queue_diagnostics(struct output_options *output, bool final);
int handle_event(void *context, void *data, size_t data_size);

#endif
