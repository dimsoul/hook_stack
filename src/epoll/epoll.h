// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_EPOLL_H
#define CALLWEAVE_EPOLL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct output_options;

int cw_epoll_handle_event(void *context, void *data, size_t data_size);
int cw_epoll_handle_dispatch_event(
    void *context, void *data, size_t data_size);
int cw_epoll_handle_callback_event(
    void *context, void *data, size_t data_size);
const char *cw_epoll_output_mode_name(uint32_t mode);
const char *cw_epoll_callback_match_name(uint32_t match);
void cw_epoll_seed_existing(struct output_options *output);
bool cw_epoll_seed_runtime_fd(
    struct output_options *output, uint32_t pid, int fd);
bool cw_epoll_print_summary(struct output_options *output);
int cw_epoll_write_summary_json(struct output_options *output);

#endif
