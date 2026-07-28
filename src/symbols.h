// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_SYMBOLS_H
#define CALLWEAVE_SYMBOLS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int resolve_process_executable(pid_t pid, char *path, size_t path_size);
int resolve_loaded_module(pid_t pid, const char *module,
                          char *resolved, size_t resolved_size);
int print_symbol_result(const char *path, const char *symbol_name);
int find_symbol_in_process(pid_t pid, const char *module,
                           const char *symbol_name);

#endif
