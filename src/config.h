// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_CONFIG_H
#define CALLWEAVE_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "callweave_internal.h"

int parse_u32_range(const char *text, uint32_t minimum,
                    uint32_t maximum, uint32_t *result);
void free_async_hops(struct async_hop_config *hops, size_t count);
int parse_async_hop(const char *text, struct async_hop_config *hop);
int parse_cli_ms(const char *option, const char *value,
                 uint64_t *nanoseconds);
int parse_cli_us(const char *option, const char *value,
                 uint64_t *nanoseconds);
int parse_trace_config(const char *path,
                       struct async_hop_config *hops,
                       size_t *hop_count,
                       char **configured_function,
                       struct output_options *output,
                       uint32_t *duration_seconds);

#endif
