#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "hook_stack.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

#define MAX_STACK_DEPTH 128
#define MAX_PATH_LEN 256

struct stack_trace_event {
    unsigned int pid;
    char comm[16];
    char target_path[MAX_PATH_LEN];
    unsigned long long  stack[MAX_STACK_DEPTH];
    unsigned int stack_len;
    unsigned long long timestamp;
};

#define MAX_PATH_LEN 256

char target_path[MAX_PATH_LEN];
char func_name[128];

struct bpf_uprobe_opts opts = {
    .sz = sizeof(struct bpf_uprobe_opts),
    .func_name = func_name,
};

unsigned long long get_module_base(pid_t pid, const char *module_name) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return 0;
    }

    unsigned long long base = 0;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, module_name)) {
            sscanf(line, "%llx-", &base);
            break;
        }
    }
    fclose(maps);
    return base;
}

unsigned long long calc_real_address(unsigned long long raw_addr, unsigned long long base) {
    return (base > 0) ? (raw_addr - base) : raw_addr;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {

    const struct stack_trace_event *e = data;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("[%s] PID %d (%s) stack_len(%d) Stack trace:\n", time_str, e->pid, e->comm, e->stack_len);

    char binary_path[256] = {0};
    const char *last_slash = strrchr(target_path, '/');
    if (last_slash) {
        const char *filename = last_slash + 1;
        const char *colon = strchr(filename, ':');
        size_t len = colon ? (size_t)(colon - filename) : strlen(filename);
        strncpy(binary_path, filename, len);
        binary_path[len] = '\0';
    } else {
        const char *filename = target_path;
        const char *colon = strchr(filename, ':');
        size_t len = colon ? (size_t)(colon - filename) : strlen(filename);
        strncpy(binary_path, filename, len);
        binary_path[len] = '\0';
    }

    unsigned long long base = get_module_base(e->pid, binary_path);
    int frame_count = e->stack_len / sizeof(unsigned long long);

    for (int i = 0; i < frame_count -1; i++) {
        char cmd[256];

        unsigned long long real_addr = calc_real_address(e->stack[i], base);

        snprintf(cmd, sizeof(cmd), "addr2line 0x%016llx -e %s -f -p", real_addr, target_path);
        printf("#%-2d ", i);
        fflush(stdout);
        system(cmd);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct hook_stack_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    if (argc < 3) {
        printf("Usage: %s /path/to/binary\n", argv[0]);
        return 1;
    }

    skel = hook_stack_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = hook_stack_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    unsigned int key = 0;

    strncpy(target_path, argv[1], sizeof(target_path) - 1);
    target_path[sizeof(target_path) - 1] = '\0';
    strncpy(func_name, argv[2], sizeof(func_name) - 1);
    func_name[sizeof(func_name) - 1] = '\0';
    printf("Target path: %s, Function name: %s\n", target_path, func_name);

    skel->links.trace_switch = bpf_program__attach_uprobe_opts(
        skel->progs.trace_switch,
        -1,     
        target_path,
        0,
        &opts
    );
    if (!skel->links.trace_switch) {
        fprintf(stderr, "Failed to attach uprobe\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Monitoring uprobe. Press Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Ring buffer error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    hook_stack_bpf__destroy(skel);
    return err ? 1 : 0;
}