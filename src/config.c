// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

void free_async_hops(struct async_hop_config *hops, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free(hops[i].source);
        free(hops[i].target);
    }
}

int parse_async_hop(const char *text, struct async_hop_config *hop)
{
    char *copy = strdup(text);
    char *parts[4] = {0};
    char *save = NULL;
    char *part;
    size_t count = 0;
    int error = -1;

    if (!copy)
        return -1;
    for (part = strtok_r(copy, ",", &save);
         part && count < 4;
         part = strtok_r(NULL, ",", &save))
        parts[count++] = part;
    if (part || count < 3 || count > 4 ||
        !parts[0][0] || !parts[2][0])
        goto cleanup;
    if (parse_u32_range(parts[1], 1, 8, &hop->source_arg))
        goto cleanup;
    hop->target_arg = 0;
    if (count == 4 && strcmp(parts[3], "auto") &&
        parse_u32_range(parts[3], 1, 8, &hop->target_arg))
        goto cleanup;

    hop->source = strdup(parts[0]);
    hop->target = strdup(parts[2]);
    if (!hop->source || !hop->target)
        goto cleanup;
    error = 0;

cleanup:
    if (error) {
        free(hop->source);
        free(hop->target);
        hop->source = NULL;
        hop->target = NULL;
    }
    free(copy);
    return error;
}

static char *trim_config_text(char *text)
{
    char *end;

    while (*text == ' ' || *text == '\t')
        text++;
    end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' ||
            end[-1] == '\n' || end[-1] == '\r'))
        *--end = '\0';
    return text;
}

static char *normalize_config_value(char *value)
{
    size_t length;

    value = trim_config_text(value);
    length = strlen(value);
    if (length >= 2 &&
        ((value[0] == '"' && value[length - 1] == '"') ||
         (value[0] == '\'' && value[length - 1] == '\''))) {
        value[length - 1] = '\0';
        value++;
    }
    return value;
}

static int parse_config_ms(const char *path, size_t line_number,
                           const char *name, const char *value,
                           uint64_t *nanoseconds)
{
    uint32_t milliseconds;

    if (parse_u32_range(value, 0, UINT32_MAX, &milliseconds)) {
        fprintf(stderr, "%s:%zu: invalid %s value '%s'\n",
                path, line_number, name, value);
        return -1;
    }
    *nanoseconds = (uint64_t)milliseconds * 1000000ULL;
    return 0;
}

int parse_cli_ms(const char *option, const char *value,
                        uint64_t *nanoseconds)
{
    uint32_t milliseconds;

    if (parse_u32_range(value, 0, UINT32_MAX, &milliseconds)) {
        fprintf(stderr, "invalid %s value: %s\n", option, value);
        return -1;
    }
    *nanoseconds = (uint64_t)milliseconds * 1000000ULL;
    return 0;
}

int parse_cli_us(const char *option, const char *value,
                        uint64_t *nanoseconds)
{
    uint32_t microseconds;

    if (parse_u32_range(value, 1, UINT32_MAX, &microseconds)) {
        fprintf(stderr, "invalid %s value: %s\n", option, value);
        return -1;
    }
    *nanoseconds = (uint64_t)microseconds * 1000ULL;
    return 0;
}

int parse_trace_config(const char *path,
                              struct async_hop_config *hops,
                              size_t *hop_count,
                              char **configured_function,
                              struct output_options *output,
                              uint32_t *duration_seconds)
{
    enum config_section {
        CONFIG_NONE,
        CONFIG_TARGET,
        CONFIG_HOPS,
        CONFIG_FILTERS,
    } section = CONFIG_NONE;
    bool source_arg_seen[MAX_ASYNC_HOPS] = {0};
    bool target_arg_seen[MAX_ASYNC_HOPS] = {0};
    FILE *file;
    char *line = NULL;
    size_t capacity = 0;
    size_t line_number = 0;
    int result = -1;

    file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "cannot open config %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    while (getline(&line, &capacity, file) >= 0) {
        struct async_hop_config *hop = NULL;
        char *key;
        char *value;
        char *separator;
        bool new_hop = false;

        line_number++;
        key = trim_config_text(line);
        if (!key[0] || key[0] == '#')
            continue;
        if (!strcmp(key, "target:")) {
            section = CONFIG_TARGET;
            continue;
        }
        if (!strcmp(key, "hops:")) {
            section = CONFIG_HOPS;
            continue;
        }
        if (!strcmp(key, "filters:")) {
            section = CONFIG_FILTERS;
            continue;
        }

        if (section == CONFIG_HOPS && key[0] == '-') {
            key = trim_config_text(key + 1);
            if (*hop_count >= MAX_ASYNC_HOPS) {
                fprintf(stderr, "%s:%zu: at most %d hops are supported\n",
                        path, line_number, MAX_ASYNC_HOPS);
                goto cleanup;
            }
            hop = &hops[*hop_count];
            (*hop_count)++;
            new_hop = true;
        } else if (section == CONFIG_HOPS && *hop_count) {
            hop = &hops[*hop_count - 1];
        }

        separator = strchr(key, ':');
        if (!separator) {
            fprintf(stderr, "%s:%zu: expected KEY: VALUE\n",
                    path, line_number);
            goto cleanup;
        }
        *separator = '\0';
        value = normalize_config_value(separator + 1);
        key = trim_config_text(key);
        if (!value[0]) {
            fprintf(stderr, "%s:%zu: %s must not be empty\n",
                    path, line_number, key);
            goto cleanup;
        }

        if (section == CONFIG_TARGET) {
            if (strcmp(key, "function")) {
                fprintf(stderr, "%s:%zu: unknown target key '%s'\n",
                        path, line_number, key);
                goto cleanup;
            }
            if (*configured_function) {
                fprintf(stderr, "%s:%zu: duplicate target function\n",
                        path, line_number);
                goto cleanup;
            }
            *configured_function = strdup(value);
            if (!*configured_function)
                goto cleanup;
        } else if (section == CONFIG_HOPS && hop) {
            size_t index = *hop_count - 1;

            if (new_hop && strcmp(key, "source")) {
                fprintf(stderr,
                        "%s:%zu: each hop must begin with '- source:'\n",
                        path, line_number);
                goto cleanup;
            }
            if (!strcmp(key, "source")) {
                if (hop->source) {
                    fprintf(stderr, "%s:%zu: duplicate hop source\n",
                            path, line_number);
                    goto cleanup;
                }
                hop->source = strdup(value);
                if (!hop->source)
                    goto cleanup;
            } else if (!strcmp(key, "source_arg")) {
                if (parse_u32_range(value, 1, 8, &hop->source_arg)) {
                    fprintf(stderr, "%s:%zu: invalid source_arg '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
                source_arg_seen[index] = true;
            } else if (!strcmp(key, "target")) {
                if (hop->target) {
                    fprintf(stderr, "%s:%zu: duplicate hop target\n",
                            path, line_number);
                    goto cleanup;
                }
                hop->target = strdup(value);
                if (!hop->target)
                    goto cleanup;
            } else if (!strcmp(key, "target_arg")) {
                if (target_arg_seen[index]) {
                    fprintf(stderr, "%s:%zu: duplicate target_arg\n",
                            path, line_number);
                    goto cleanup;
                }
                if (!strcmp(value, "auto")) {
                    hop->target_arg = 0;
                } else if (parse_u32_range(value, 1, 8,
                                           &hop->target_arg)) {
                    fprintf(stderr, "%s:%zu: invalid target_arg '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
                target_arg_seen[index] = true;
            } else {
                fprintf(stderr, "%s:%zu: unknown hop key '%s'\n",
                        path, line_number, key);
                goto cleanup;
            }
        } else if (section == CONFIG_FILTERS) {
            if (!strcmp(key, "min_total_ms")) {
                if (parse_config_ms(path, line_number, key, value,
                                    &output->min_total_ns))
                    goto cleanup;
            } else if (!strcmp(key, "min_queue_ms")) {
                if (parse_config_ms(path, line_number, key, value,
                                    &output->min_queue_ns))
                    goto cleanup;
            } else if (!strcmp(key, "min_work_ms")) {
                if (parse_config_ms(path, line_number, key, value,
                                    &output->min_work_ns))
                    goto cleanup;
            } else if (!strcmp(key, "max_events")) {
                if (parse_u32_range(value, 1, UINT32_MAX,
                                    &output->max_events)) {
                    fprintf(stderr, "%s:%zu: invalid max_events '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
            } else if (!strcmp(key, "duration")) {
                if (parse_u32_range(value, 1, UINT32_MAX,
                                    duration_seconds)) {
                    fprintf(stderr, "%s:%zu: invalid duration '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
            } else if (!strcmp(key, "diagnostic_interval_ms")) {
                if (parse_u32_range(
                        value, 0, UINT32_MAX,
                        &output->diagnostic_interval_ms)) {
                    fprintf(stderr,
                            "%s:%zu: invalid diagnostic_interval_ms '%s'\n",
                            path, line_number, value);
                    goto cleanup;
                }
            } else {
                fprintf(stderr, "%s:%zu: unknown filter key '%s'\n",
                        path, line_number, key);
                goto cleanup;
            }
        } else {
            fprintf(stderr, "%s:%zu: value appears outside a known section\n",
                    path, line_number);
            goto cleanup;
        }
    }
    if (ferror(file)) {
        fprintf(stderr, "cannot read config %s: %s\n",
                path, strerror(errno));
        goto cleanup;
    }
    if (!*configured_function) {
        fprintf(stderr, "%s: target.function is required\n", path);
        goto cleanup;
    }
    if (!*hop_count) {
        fprintf(stderr, "%s: at least one hop is required\n", path);
        goto cleanup;
    }
    for (size_t index = 0; index < *hop_count; index++) {
        if (!hops[index].source || !hops[index].target ||
            !source_arg_seen[index]) {
            fprintf(stderr,
                    "%s: hop %zu requires source, source_arg, and target; "
                    "target_arg is optional\n",
                    path, index);
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    free(line);
    fclose(file);
    return result;
}
