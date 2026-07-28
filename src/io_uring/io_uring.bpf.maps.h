// SPDX-License-Identifier: GPL-2.0-only

#ifndef CALLWEAVE_IO_URING_BPF_MAPS_H
#define CALLWEAVE_IO_URING_BPF_MAPS_H

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, u64);
    __type(value, struct io_uring_request_state);
} io_uring_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u8);
} io_uring_contexts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct io_uring_counters);
} io_uring_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct io_uring_aggregate_key);
    __type(value, struct io_uring_aggregate);
} io_uring_aggregates SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct io_uring_result_key);
    __type(value, u64);
} io_uring_results SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct io_uring_ring_stats);
} io_uring_ring_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct io_uring_failure_key);
    __type(value, struct io_uring_failure_stats);
} io_uring_failures SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct io_uring_link_key);
    __type(value, struct io_uring_link_stats);
} io_uring_links SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct io_uring_completion_key);
    __type(value, struct io_uring_completion_context);
} io_uring_completions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} io_uring_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} io_uring_callback_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64[MAX_ASYNC_STACK_DEPTH]);
} io_uring_stacks SEC(".maps");

#endif
