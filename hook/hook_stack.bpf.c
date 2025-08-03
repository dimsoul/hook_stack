#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_STACK_DEPTH 128
#define MAX_PATH_LEN 256

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_PATH_LEN]);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct stack_trace_event {
    u32 pid;
    char comm[16];
    char target_path[MAX_PATH_LEN];
    u64 stack[MAX_STACK_DEPTH];
    u32 stack_len;
    u64 timestamp;
};

SEC("uprobe")
int trace_switch(struct pt_regs *ctx) {
    u32 key = 0;
    char *target_path = bpf_map_lookup_elem(&config_map, &key);
    if (!target_path) {
        bpf_printk("Error: target path not configured");
        return 0;
    }

    char comm[16];

    struct stack_trace_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_printk("Error: failed to reserve event in ringbuf");
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    __builtin_memcpy(event->target_path, target_path, MAX_PATH_LEN);
    event->timestamp = bpf_ktime_get_ns();
    event->stack_len = bpf_get_stack(ctx, event->stack, sizeof(event->stack), BPF_F_USER_STACK);
    bpf_printk("the bpf: PID %d, comm %s, stack_len %u", event->pid, event->comm, event->stack_len);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";