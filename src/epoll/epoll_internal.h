// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_EPOLL_INTERNAL_H
#define CALLWEAVE_EPOLL_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

const char *cw_epoll_wait_kind_name(uint32_t kind);
const char *cw_epoll_io_operation_name(uint32_t operation);
const char *cw_epoll_wake_kind_name(uint32_t kind);
const char *cw_epoll_wake_action_name(uint32_t action);
bool cw_epoll_resource_single_read(const char *resource);
void cw_epoll_format_events(uint32_t events, char *buffer, size_t size);
int cw_epoll_write_json_string(
    FILE *stream, const char *text, size_t size);

#endif
