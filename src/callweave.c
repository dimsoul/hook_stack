// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <libelf.h>
#include <gelf.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "callweave.skel.h"
#include "report.h"

#define MAX_STACK_DEPTH 128
#define MAX_ASYNC_STACK_DEPTH 127
#define MAX_ASYNC_HOPS 8
#define ASYNC_HOP_ID_MASK 0xffffU
#define ASYNC_TARGET_ARG_SHIFT 16

enum event_type {
    EVENT_ENTRY,
    EVENT_RETURN,
};

struct async_hop_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_id;
    uint32_t reserved;
    uint64_t key;
    uint64_t queue_ns;
    uint64_t target_ns;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
};

struct discovery_wakeup {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_id;
    int32_t pidns_error;
    uint64_t wake_ns;
};

struct stack_trace_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t global_pid;
    uint32_t global_tid;
    char comm[16];
    int32_t stack_size;
    int32_t pidns_error;
    uint32_t event_type;
    uint32_t reserved;
    uint64_t duration_ns;
    int64_t return_value;
    uint64_t offcpu_ns;
    uint64_t blocked_ns;
    uint64_t runqueue_ns;
    uint32_t async_hop_count;
    uint32_t async_truncated;
    struct async_hop_event async_hops[MAX_ASYNC_HOPS];
    uint32_t discovery_valid;
    uint32_t discovery_reserved;
    struct discovery_wakeup discovery_waker;
    uint64_t discovery_wakeup_ns;
    uint64_t stack[MAX_STACK_DEPTH];
};

struct async_hop_config {
    char *source;
    uint32_t source_arg;
    char *target;
    uint32_t target_arg;
};

struct output_options {
    bool show_return_value;
    bool show_duration;
    bool show_attribution;
    bool show_async;
    bool show_discovery;
    int async_stack_map_fd;
    int discovery_stack_map_fd;
    const struct async_hop_config *async_hops;
    size_t async_hop_count;
    const char *async_source_name;
    const char *final_target_name;
    const char *target_path;
    uint32_t discovery_target_arg;
    uint64_t min_total_ns;
    uint64_t min_queue_ns;
    uint64_t min_work_ns;
    uint32_t max_events;
    uint32_t emitted_events;
    bool json_output;
    FILE *json_stream;
    FILE *report_stream;
    bool report_first;
    bool export_failed;
};

_Static_assert(offsetof(struct stack_trace_event, stack) == 864,
               "userspace and BPF event layouts differ");
_Static_assert(sizeof(struct stack_trace_event) == 1888,
               "userspace and BPF event sizes differ");

struct proc_map {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char perms[5];
    char path[PATH_MAX];
    bool bias_checked;
    uint64_t load_bias;
};

struct map_list {
    struct proc_map *items;
    size_t count;
    size_t capacity;
};

struct frame_info {
    uint64_t ip;
    uint64_t object_address;
    struct proc_map *map;
    char address_text[19];
    char *symbol;
};

struct elf_symbol_info {
    uint64_t value;
    uint64_t file_offset;
    bool has_file_offset;
};

static volatile sig_atomic_t exiting;

static const char *path_basename(const char *path);

static void handle_signal(int signo)
{
    (void)signo;
    exiting = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action = {
        .sa_handler = handle_signal,
    };

    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
        fprintf(stderr, "failed to install signal handlers: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int configure_pid_namespace(struct callweave_bpf *skeleton)
{
    struct stat namespace_status;
    int saved_error;

    if (stat("/proc/self/ns/pid", &namespace_status)) {
        saved_error = errno;
        fprintf(stderr, "cannot inspect /proc/self/ns/pid: %s\n",
                strerror(saved_error));
        return -saved_error;
    }

    skeleton->rodata->pidns_dev = (uint64_t)namespace_status.st_dev;
    skeleton->rodata->pidns_ino = (uint64_t)namespace_status.st_ino;
    return 0;
}

static int attach_raw_tracepoint(struct bpf_program *program,
                                 struct bpf_link **link,
                                 const char *tracepoint)
{
    int error;

    *link = bpf_program__attach_raw_tracepoint(program, tracepoint);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return 0;

    *link = NULL;
    fprintf(stderr, "failed to attach raw tracepoint %s: %s\n",
            tracepoint, strerror(-error));
    return error;
}

static int attach_named_uprobe(struct bpf_program *program,
                               struct bpf_link **link,
                               const char *path, const char *function,
                               uint64_t cookie, bool return_probe)
{
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
        .func_name = function,
        .bpf_cookie = cookie,
        .retprobe = return_probe,
    };
    int error;

    *link = bpf_program__attach_uprobe_opts(program, -1, path, 0, &options);
    error = *link ? libbpf_get_error(*link) :
                    (errno ? -errno : -EINVAL);
    if (!error)
        return 0;

    *link = NULL;
    fprintf(stderr, "failed to attach async %suprobe to %s:%s: %s\n",
            return_probe ? "return " : "", path, function,
            strerror(-error));
    return error;
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage:\n"
            "  %s [OPTIONS] BINARY FUNCTION\n"
            "  %s -p PID [--module MODULE] FUNCTION\n"
            "  %s -p PID [--module MODULE] --find-symbol SYMBOL\n"
            "  %s --binary BINARY --offset OFFSET\n"
            "  %s -p PID --discover-async FUNCTION\n"
            "  %s -p PID --config PATH\n"
            "  %s --check-config PATH\n"
            "\n"
            "Options:\n"
            "  -p, --pid PID             only emit events from PID\n"
            "  -b, --binary PATH         executable or shared-library path\n"
            "  -m, --module MODULE       mapped module basename or absolute path\n"
            "  -s, --find-symbol SYMBOL  find SYMBOL in mapped ELF modules and exit\n"
            "  -o, --offset OFFSET       attach at an ELF file offset\n"
            "  -r, --ret                 print the raw function return value\n"
            "  -t, --time                print function execution time\n"
            "  -a, --attribution         break time down by scheduler state\n"
            "      --async-source FUNC    capture the producer stack at FUNC\n"
            "      --async-source-binary PATH\n"
            "                             ELF containing the producer function\n"
            "      --async-source-arg N   producer key argument, 1-8 (default 1)\n"
            "      --async-target-arg N   target key argument, 1-8 or auto\n"
            "                             (default auto)\n"
            "      --async-max-age-ms MS  discard older contexts (default 30000)\n"
            "      --async-hop S,SA,T[,TA]\n"
            "                             add one async hop (repeat up to 8);\n"
            "                             omitted TA scans target arg1-arg8\n"
            "                             async tracing implies --time and\n"
            "                             --attribution\n"
            "      --discover-async FUNC  show the latest waker stack and a\n"
            "                             candidate async-hop for FUNC\n"
            "      --config PATH          load target, hops, and filters from\n"
            "                             a callweave YAML config\n"
            "      --check-config PATH    validate a config and exit\n"
            "      --min-total-ms MS      only print chains at least MS total\n"
            "      --min-queue-ms MS      require one hop with MS queue time\n"
            "      --min-work-ms MS       require one hop with MS work time\n"
            "      --max-events N         stop after N matching chains\n"
            "      --duration SEC         stop tracing after SEC seconds\n"
            "      --format FORMAT        text or json (default text)\n"
            "      --output PATH          write JSON Lines to PATH\n"
            "      --report PATH          write a self-contained HTML report\n"
            "  -h, --help                show this help\n"
            "\n"
            "When -p is used without --binary or --module, /proc/PID/exe is used.\n"
            "Without -p, an explicit BINARY is required.\n",
            program, program, program, program, program, program, program);
}

static int parse_pid(const char *text, pid_t *pid)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || !end || *end != '\0' || value <= 0 || value > INT_MAX)
        return -1;
    *pid = (pid_t)value;
    return 0;
}

static int parse_offset(const char *text, size_t *offset)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno || !end || *end != '\0')
        return -1;
#if SIZE_MAX < ULLONG_MAX
    if (value > SIZE_MAX)
        return -1;
#endif
    *offset = (size_t)value;
    return 0;
}

static int parse_u32_range(const char *text, uint32_t minimum,
                           uint32_t maximum, uint32_t *result)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end != '\0' ||
        value < minimum || value > maximum)
        return -1;
    *result = (uint32_t)value;
    return 0;
}

static int validate_target_pid(pid_t pid)
{
    char process_path[64];
    struct stat process_status;
    int saved_error;

    if (pid <= 0)
        return 0;

    snprintf(process_path, sizeof(process_path), "/proc/%d", (int)pid);
    if (!stat(process_path, &process_status))
        return 0;

    saved_error = errno;
    fprintf(stderr,
            "target PID %d is not visible in this PID namespace: %s\n"
            "verify it with `ps -p %d` while the target is still running\n",
            (int)pid, strerror(saved_error), (int)pid);
    return -saved_error;
}

static void map_list_free(struct map_list *maps)
{
    free(maps->items);
    maps->items = NULL;
    maps->count = 0;
    maps->capacity = 0;
}

static int map_list_append(struct map_list *maps, const struct proc_map *map)
{
    struct proc_map *new_items;
    size_t new_capacity;

    if (maps->count == maps->capacity) {
        new_capacity = maps->capacity ? maps->capacity * 2 : 32;
        new_items = realloc(maps->items, new_capacity * sizeof(*new_items));
        if (!new_items)
            return -1;
        maps->items = new_items;
        maps->capacity = new_capacity;
    }

    maps->items[maps->count++] = *map;
    return 0;
}

static void trim_deleted_suffix(char *path)
{
    static const char suffix[] = " (deleted)";
    size_t path_length = strlen(path);
    size_t suffix_length = sizeof(suffix) - 1;

    if (path_length >= suffix_length &&
        !strcmp(path + path_length - suffix_length, suffix))
        path[path_length - suffix_length] = '\0';
}

static int read_process_maps(uint32_t pid, struct map_list *maps)
{
    char maps_path[64];
    char *line = NULL;
    size_t line_capacity = 0;
    FILE *file;
    int result = -1;

    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    file = fopen(maps_path, "re");
    if (!file)
        return -1;

    while (getline(&line, &line_capacity, file) >= 0) {
        struct proc_map map = {0};
        unsigned long long start, end, offset;
        char device[32];
        unsigned long inode;
        int path_offset = 0;
        char *path;

        if (sscanf(line, "%llx-%llx %4s %llx %31s %lu %n",
                   &start, &end, map.perms, &offset, device, &inode,
                   &path_offset) < 6)
            continue;

        map.start = start;
        map.end = end;
        map.offset = offset;
        path = line + path_offset;
        path[strcspn(path, "\r\n")] = '\0';
        while (*path == ' ' || *path == '\t')
            path++;

        if (*path == '/') {
            snprintf(map.path, sizeof(map.path), "%s", path);
            trim_deleted_suffix(map.path);
        }

        if (map_list_append(maps, &map))
            goto out;
    }

    result = 0;
out:
    free(line);
    fclose(file);
    return result;
}

static bool is_first_path_occurrence(const struct map_list *maps, size_t index)
{
    size_t i;

    if (!maps->items[index].path[0])
        return false;
    for (i = 0; i < index; i++) {
        if (!strcmp(maps->items[i].path, maps->items[index].path))
            return false;
    }
    return true;
}

static bool module_name_matches(const char *path, const char *module)
{
    if (strchr(module, '/'))
        return !strcmp(path, module);
    return !strcmp(path_basename(path), module);
}

static int resolve_process_executable(pid_t pid, char *path, size_t path_size)
{
    char proc_exe[64];
    char resolved[PATH_MAX];
    ssize_t length;

    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", (int)pid);
    length = readlink(proc_exe, resolved, sizeof(resolved) - 1);
    if (length < 0) {
        fprintf(stderr, "cannot read %s: %s\n", proc_exe, strerror(errno));
        return -errno;
    }
    if ((size_t)length >= sizeof(resolved) - 1) {
        fprintf(stderr, "executable path for PID %d is too long\n", (int)pid);
        return -ENAMETOOLONG;
    }
    resolved[length] = '\0';

    if (!strstr(resolved, " (deleted)") && !access(resolved, R_OK)) {
        if (snprintf(path, path_size, "%s", resolved) >= (int)path_size)
            return -ENAMETOOLONG;
    } else if (snprintf(path, path_size, "%s", proc_exe) >= (int)path_size) {
        return -ENAMETOOLONG;
    }
    return 0;
}

static int resolve_loaded_module(pid_t pid, const char *module,
                                 char *path, size_t path_size)
{
    struct map_list maps = {0};
    size_t match_count = 0;
    size_t i;
    int error = 0;

    if (read_process_maps((uint32_t)pid, &maps)) {
        error = -errno;
        fprintf(stderr, "cannot read /proc/%d/maps: %s\n",
                (int)pid, strerror(errno));
        goto out;
    }

    for (i = 0; i < maps.count; i++) {
        if (!is_first_path_occurrence(&maps, i) ||
            !module_name_matches(maps.items[i].path, module))
            continue;
        match_count++;
        if (match_count == 1 &&
            snprintf(path, path_size, "%s", maps.items[i].path) >=
                (int)path_size) {
            error = -ENAMETOOLONG;
            goto out;
        }
    }

    if (!match_count) {
        fprintf(stderr, "module '%s' is not mapped in PID %d\n",
                module, (int)pid);
        error = -ENOENT;
    } else if (match_count > 1) {
        fprintf(stderr, "module '%s' is ambiguous in PID %d:\n",
                module, (int)pid);
        for (i = 0; i < maps.count; i++) {
            if (is_first_path_occurrence(&maps, i) &&
                module_name_matches(maps.items[i].path, module))
                fprintf(stderr, "  %s\n", maps.items[i].path);
        }
        fprintf(stderr, "use an absolute module path to select one\n");
        error = -ENOTUNIQ;
    }

out:
    map_list_free(&maps);
    return error;
}

static void symbol_file_offset(Elf *elf, uint64_t value,
                               struct elf_symbol_info *info)
{
    size_t program_header_count;
    size_t i;

    if (elf_getphdrnum(elf, &program_header_count))
        return;

    for (i = 0; i < program_header_count; i++) {
        GElf_Phdr program_header;

        if (!gelf_getphdr(elf, (int)i, &program_header) ||
            program_header.p_type != PT_LOAD ||
            value < program_header.p_vaddr ||
            value - program_header.p_vaddr >= program_header.p_filesz)
            continue;

        info->file_offset = program_header.p_offset +
                            (value - program_header.p_vaddr);
        info->has_file_offset = true;
        return;
    }
}

static int find_elf_symbol(const char *path, const char *symbol_name,
                           struct elf_symbol_info *info)
{
    Elf_Scn *section = NULL;
    Elf *elf = NULL;
    int file_descriptor = -1;
    int result = -1;

    memset(info, 0, sizeof(*info));
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
        errno = ENOTSUP;
        return -1;
    }

    file_descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (file_descriptor < 0)
        return -1;
    elf = elf_begin(file_descriptor, ELF_C_READ, NULL);
    if (!elf) {
        errno = ENOEXEC;
        goto out;
    }

    result = 0;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr section_header;
        Elf_Data *data = NULL;

        if (!gelf_getshdr(section, &section_header) ||
            (section_header.sh_type != SHT_SYMTAB &&
             section_header.sh_type != SHT_DYNSYM) ||
            !section_header.sh_entsize)
            continue;

        while ((data = elf_getdata(section, data)) != NULL) {
            size_t symbol_count = data->d_size / section_header.sh_entsize;
            size_t i;

            for (i = 0; i < symbol_count; i++) {
                GElf_Sym symbol;
                const char *name;
                unsigned int type;

                if (!gelf_getsym(data, (int)i, &symbol) ||
                    symbol.st_shndx == SHN_UNDEF)
                    continue;
                type = GELF_ST_TYPE(symbol.st_info);
                if (type != STT_FUNC
#ifdef STT_GNU_IFUNC
                    && type != STT_GNU_IFUNC
#endif
                )
                    continue;
                name = elf_strptr(elf, section_header.sh_link, symbol.st_name);
                if (!name || strcmp(name, symbol_name))
                    continue;

                info->value = symbol.st_value;
                symbol_file_offset(elf, info->value, info);
                result = 1;
                goto out;
            }
        }
    }

out:
    if (elf)
        elf_end(elf);
    if (file_descriptor >= 0)
        close(file_descriptor);
    return result;
}

static int print_symbol_result(const char *path, const char *symbol_name)
{
    struct elf_symbol_info info;
    int result = find_elf_symbol(path, symbol_name, &info);

    if (result <= 0)
        return result;

    printf("%s\n", path);
    printf("  symbol=%s value=0x%llx", symbol_name,
           (unsigned long long)info.value);
    if (info.has_file_offset)
        printf(" offset=0x%llx",
               (unsigned long long)info.file_offset);
    else
        printf(" offset=unavailable");
    putchar('\n');
    return 1;
}

static int find_symbol_in_process(pid_t pid, const char *module,
                                  const char *symbol_name)
{
    struct map_list maps = {0};
    size_t searched = 0;
    size_t matches = 0;
    size_t i;
    int error = 0;

    if (read_process_maps((uint32_t)pid, &maps)) {
        fprintf(stderr, "cannot read /proc/%d/maps: %s\n",
                (int)pid, strerror(errno));
        return -errno;
    }

    for (i = 0; i < maps.count; i++) {
        int result;

        if (!is_first_path_occurrence(&maps, i) ||
            (module && !module_name_matches(maps.items[i].path, module)))
            continue;
        searched++;
        result = print_symbol_result(maps.items[i].path, symbol_name);
        if (result > 0)
            matches++;
    }

    if (!matches) {
        fprintf(stderr,
                "symbol '%s' was not found in %zu mapped ELF module%s\n",
                symbol_name, searched, searched == 1 ? "" : "s");
        error = -ENOENT;
    } else {
        printf("Found %zu matching module%s.\n",
               matches, matches == 1 ? "" : "s");
    }

    map_list_free(&maps);
    return error;
}

static struct proc_map *find_map(struct map_list *maps, uint64_t address)
{
    size_t i;

    for (i = 0; i < maps->count; i++) {
        if (address >= maps->items[i].start && address < maps->items[i].end)
            return &maps->items[i];
    }
    return NULL;
}

static uint64_t align_down(uint64_t value, uint64_t alignment)
{
    return alignment ? value - value % alignment : value;
}

static int load_bias_from_elf64(FILE *file, const Elf64_Ehdr *header,
                                const struct proc_map *map, uint64_t page_size,
                                uint64_t *load_bias)
{
    size_t i;

    if (header->e_phentsize != sizeof(Elf64_Phdr) ||
        fseeko(file, (off_t)header->e_phoff, SEEK_SET))
        return -1;

    for (i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr program_header;

        if (fread(&program_header, sizeof(program_header), 1, file) != 1)
            return -1;
        if (program_header.p_type != PT_LOAD)
            continue;
        if (align_down(program_header.p_offset, page_size) != map->offset)
            continue;

        *load_bias = map->start -
                     align_down(program_header.p_vaddr, page_size);
        return 0;
    }
    return -1;
}

static int load_bias_from_elf32(FILE *file, const Elf32_Ehdr *header,
                                const struct proc_map *map, uint64_t page_size,
                                uint64_t *load_bias)
{
    size_t i;

    if (header->e_phentsize != sizeof(Elf32_Phdr) ||
        fseeko(file, (off_t)header->e_phoff, SEEK_SET))
        return -1;

    for (i = 0; i < header->e_phnum; i++) {
        Elf32_Phdr program_header;

        if (fread(&program_header, sizeof(program_header), 1, file) != 1)
            return -1;
        if (program_header.p_type != PT_LOAD)
            continue;
        if (align_down(program_header.p_offset, page_size) != map->offset)
            continue;

        *load_bias = map->start -
                     align_down(program_header.p_vaddr, page_size);
        return 0;
    }
    return -1;
}

static uint64_t get_load_bias(struct proc_map *map)
{
    unsigned char identity[EI_NIDENT];
    long system_page_size = sysconf(_SC_PAGESIZE);
    uint64_t page_size = system_page_size > 0 ? (uint64_t)system_page_size : 4096;
    FILE *file;

    if (map->bias_checked)
        return map->load_bias;
    map->bias_checked = true;

    file = fopen(map->path, "re");
    if (!file)
        goto fallback;
    if (fread(identity, sizeof(identity), 1, file) != 1 ||
        memcmp(identity, ELFMAG, SELFMAG))
        goto close_and_fallback;
    rewind(file);

    if (identity[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr header;

        if (fread(&header, sizeof(header), 1, file) == 1 &&
            !load_bias_from_elf64(file, &header, map, page_size,
                                  &map->load_bias)) {
            fclose(file);
            return map->load_bias;
        }
    } else if (identity[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr header;

        if (fread(&header, sizeof(header), 1, file) == 1 &&
            !load_bias_from_elf32(file, &header, map, page_size,
                                  &map->load_bias)) {
            fclose(file);
            return map->load_bias;
        }
    }

close_and_fallback:
    fclose(file);
fallback:
    map->load_bias = map->start - map->offset;
    return map->load_bias;
}

static int wait_for_child(pid_t child, int *status)
{
    pid_t result;

    do {
        result = waitpid(child, status, 0);
    } while (result < 0 && errno == EINTR);
    return result < 0 ? -1 : 0;
}

static int symbolize_group(struct frame_info *frames, const size_t *indices,
                           size_t count, const char *module_path)
{
    char *arguments[MAX_STACK_DEPTH + 8];
    char *line = NULL;
    size_t line_capacity = 0;
    int pipe_fds[2];
    pid_t child;
    FILE *output;
    size_t i;
    int status;

    if (!count)
        return 0;
    if (pipe(pipe_fds))
        return -1;

    arguments[0] = (char *)"addr2line";
    arguments[1] = (char *)"-C";
    arguments[2] = (char *)"-f";
    arguments[3] = (char *)"-p";
    arguments[4] = (char *)"-e";
    arguments[5] = (char *)module_path;
    for (i = 0; i < count; i++)
        arguments[6 + i] = frames[indices[i]].address_text;
    arguments[6 + count] = NULL;

    child = fork();
    if (child < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    if (child == 0) {
        close(pipe_fds[0]);
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(pipe_fds[1]);
        execvp(arguments[0], arguments);
        _exit(127);
    }

    close(pipe_fds[1]);
    output = fdopen(pipe_fds[0], "r");
    if (!output) {
        close(pipe_fds[0]);
        wait_for_child(child, &status);
        return -1;
    }

    for (i = 0; i < count && getline(&line, &line_capacity, output) >= 0; i++) {
        line[strcspn(line, "\r\n")] = '\0';
        frames[indices[i]].symbol = strdup(line);
    }

    free(line);
    fclose(output);
    if (wait_for_child(child, &status))
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void resolve_frames(struct frame_info *frames, size_t frame_count)
{
    bool grouped[MAX_STACK_DEPTH] = {0};
    size_t indices[MAX_STACK_DEPTH];
    size_t i, j;

    for (i = 0; i < frame_count; i++) {
        size_t group_count = 0;

        if (grouped[i] || !frames[i].map || !frames[i].map->path[0])
            continue;
        for (j = i; j < frame_count; j++) {
            if (!grouped[j] && frames[j].map &&
                !strcmp(frames[i].map->path, frames[j].map->path)) {
                grouped[j] = true;
                indices[group_count++] = j;
            }
        }
        symbolize_group(frames, indices, group_count, frames[i].map->path);
    }
}

static void print_event_time(void)
{
    char buffer[32];
    struct tm local_time;
    time_t now = time(NULL);

    if (localtime_r(&now, &local_time) &&
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time))
        printf("[%s] ", buffer);
}

static uint64_t monotonic_time_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL +
           (uint64_t)now.tv_nsec;
}

static void print_interval(const char *label, uint64_t nanoseconds)
{
    if (nanoseconds >= 1000000000ULL)
        printf(" %s=%.6f s", label,
               (double)nanoseconds / 1000000000.0);
    else if (nanoseconds >= 1000000ULL)
        printf(" %s=%.3f ms", label,
               (double)nanoseconds / 1000000.0);
    else if (nanoseconds >= 1000ULL)
        printf(" %s=%.3f us", label,
               (double)nanoseconds / 1000.0);
    else
        printf(" %s=%llu ns", label,
               (unsigned long long)nanoseconds);
}

static void calculate_attribution(uint64_t duration_ns, uint64_t offcpu_ns,
                                  uint64_t blocked_ns, uint64_t runqueue_ns,
                                  uint64_t *oncpu_ns, uint64_t *unknown_ns)
{
    uint64_t classified_ns;

    if (offcpu_ns > duration_ns)
        offcpu_ns = duration_ns;
    classified_ns = blocked_ns + runqueue_ns;
    *unknown_ns = offcpu_ns > classified_ns ?
                  offcpu_ns - classified_ns : 0;
    *oncpu_ns = duration_ns - offcpu_ns;
}

static const char *dominant_attribution(uint64_t oncpu_ns,
                                        uint64_t blocked_ns,
                                        uint64_t runqueue_ns,
                                        uint64_t unknown_ns)
{
    const char *dominant = "on-CPU";
    uint64_t maximum = oncpu_ns;

    if (blocked_ns > maximum) {
        dominant = "blocked";
        maximum = blocked_ns;
    }
    if (runqueue_ns > maximum) {
        dominant = "run-queue";
        maximum = runqueue_ns;
    }
    if (unknown_ns > maximum)
        dominant = "preempt/unknown";
    return dominant;
}

static void print_attribution(uint64_t duration_ns, uint64_t offcpu_ns,
                              uint64_t blocked_ns, uint64_t runqueue_ns,
                              bool include_dominant)
{
    uint64_t oncpu_ns;
    uint64_t unknown_ns;

    calculate_attribution(duration_ns, offcpu_ns, blocked_ns, runqueue_ns,
                          &oncpu_ns, &unknown_ns);
    print_interval("oncpu", oncpu_ns);
    print_interval("offcpu", offcpu_ns > duration_ns ?
                   duration_ns : offcpu_ns);
    print_interval("blocked", blocked_ns);
    print_interval("runq", runqueue_ns);
    print_interval("preempt/unknown", unknown_ns);
    if (include_dominant)
        printf(" dominant=%s",
               dominant_attribution(oncpu_ns, blocked_ns, runqueue_ns,
                                    unknown_ns));
}

static void print_stack_frames(const uint64_t *stack, int32_t stack_size,
                               struct map_list *maps, const char *prefix,
                               const char *candidate_path,
                               char *candidate, size_t candidate_size)
{
    struct frame_info frames[MAX_STACK_DEPTH] = {0};
    size_t frame_count;
    size_t i;

    if (stack_size < 0) {
        printf("  %sunable to collect user stack: %s (%d)\n",
               prefix, strerror(-stack_size), stack_size);
        return;
    }
    if (!stack_size) {
        printf("  %sempty user stack\n", prefix);
        return;
    }

    frame_count = (size_t)stack_size / sizeof(stack[0]);
    if (frame_count > MAX_STACK_DEPTH)
        frame_count = MAX_STACK_DEPTH;
    while (frame_count && !stack[frame_count - 1])
        frame_count--;
    if (!frame_count) {
        printf("  %sempty user stack\n", prefix);
        return;
    }

    for (i = 0; i < frame_count; i++) {
        frames[i].ip = stack[i];
        frames[i].map = find_map(maps, frames[i].ip);
        if (frames[i].map && frames[i].map->path[0]) {
            uint64_t load_bias = get_load_bias(frames[i].map);

            frames[i].object_address = frames[i].ip - load_bias;
            snprintf(frames[i].address_text, sizeof(frames[i].address_text),
                     "0x%016llx",
                     (unsigned long long)frames[i].object_address);
        }
    }

    resolve_frames(frames, frame_count);
    for (i = 0; i < frame_count; i++) {
        if (candidate && candidate_size && !candidate[0] &&
            candidate_path && frames[i].map &&
            !strcmp(frames[i].map->path, candidate_path) &&
            frames[i].symbol && strncmp(frames[i].symbol, "??", 2)) {
            const char *separator = strstr(frames[i].symbol, " at ");
            size_t length = separator ?
                            (size_t)(separator - frames[i].symbol) :
                            strlen(frames[i].symbol);

            if (length >= candidate_size)
                length = candidate_size - 1;
            memcpy(candidate, frames[i].symbol, length);
            candidate[length] = '\0';
        }
        if (!frames[i].map) {
            printf("  %s#%-3zu 0x%016llx [unmapped]\n", prefix, i,
                   (unsigned long long)frames[i].ip);
        } else if (!frames[i].map->path[0]) {
            printf("  %s#%-3zu 0x%016llx [anonymous]\n", prefix, i,
                   (unsigned long long)frames[i].ip);
        } else {
            printf("  %s#%-3zu 0x%016llx %-24s %s\n", prefix, i,
                   (unsigned long long)frames[i].ip,
                   path_basename(frames[i].map->path),
                   frames[i].symbol ? frames[i].symbol : "?? at ??:0");
        }
        free(frames[i].symbol);
    }
}

static bool has_async_chain_filters(const struct output_options *output)
{
    return output->min_total_ns || output->min_queue_ns ||
           output->min_work_ns || output->max_events;
}

static bool async_chain_matches(const struct stack_trace_event *event,
                                const struct output_options *output)
{
    uint64_t total_ns = 0;
    uint64_t maximum_queue_ns = 0;
    uint64_t maximum_work_ns = 0;
    uint32_t count = event->async_hop_count;
    uint32_t index;

    if (!count)
        return false;
    if (count > MAX_ASYNC_HOPS)
        count = MAX_ASYNC_HOPS;
    for (index = 0; index < count; index++) {
        const struct async_hop_event *hop = &event->async_hops[index];

        if (UINT64_MAX - total_ns < hop->queue_ns)
            total_ns = UINT64_MAX;
        else
            total_ns += hop->queue_ns;
        if (UINT64_MAX - total_ns < hop->target_ns)
            total_ns = UINT64_MAX;
        else
            total_ns += hop->target_ns;
        if (hop->queue_ns > maximum_queue_ns)
            maximum_queue_ns = hop->queue_ns;
        if (hop->target_ns > maximum_work_ns)
            maximum_work_ns = hop->target_ns;
    }

    return total_ns >= output->min_total_ns &&
           maximum_queue_ns >= output->min_queue_ns &&
           maximum_work_ns >= output->min_work_ns;
}

static uint64_t realtime_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now))
        return 0;
    return (uint64_t)now.tv_sec * 1000ULL +
           (uint64_t)now.tv_nsec / 1000000ULL;
}

static void copy_report_comm(char destination[17],
                             const char source[16])
{
    memcpy(destination, source, 16);
    destination[16] = '\0';
}

static void build_report_chain(const struct stack_trace_event *event,
                               const struct output_options *output,
                               struct cw_report_chain *chain)
{
    uint32_t hop_count = event->async_hop_count;
    uint32_t hop_index;

    memset(chain, 0, sizeof(*chain));
    chain->timestamp_ms = realtime_milliseconds();
    chain->pid = event->pid;
    chain->tid = event->tid;
    copy_report_comm(chain->comm, event->comm);
    chain->duration_ns = event->duration_ns;
    chain->offcpu_ns = event->offcpu_ns;
    chain->blocked_ns = event->blocked_ns;
    chain->runqueue_ns = event->runqueue_ns;
    chain->truncated = event->async_truncated;
    if (hop_count > CW_REPORT_MAX_HOPS)
        hop_count = CW_REPORT_MAX_HOPS;
    chain->hop_count = hop_count;

    for (hop_index = 0; hop_index < hop_count; hop_index++) {
        const struct async_hop_event *source =
            &event->async_hops[hop_index];
        struct cw_report_hop *destination =
            &chain->hops[hop_index];
        uint32_t hop_id = source->reserved & ASYNC_HOP_ID_MASK;
        uint32_t configured_hop =
            hop_id ? hop_id - 1 : hop_index;

        destination->index = configured_hop;
        destination->pid = source->pid;
        destination->tid = source->tid;
        destination->target_tid =
            hop_index + 1 < hop_count ?
                event->async_hops[hop_index + 1].tid : event->tid;
        destination->target_arg =
            source->reserved >> ASYNC_TARGET_ARG_SHIFT;
        copy_report_comm(destination->comm, source->comm);
        if (configured_hop < output->async_hop_count) {
            destination->source =
                output->async_hops[configured_hop].source;
            destination->target =
                output->async_hops[configured_hop].target;
        } else {
            destination->source =
                output->async_source_name ?
                    output->async_source_name : "source";
            destination->target =
                output->final_target_name ?
                    output->final_target_name : "target";
        }
        destination->key = source->key;
        destination->queue_ns = source->queue_ns;
        destination->work_ns = source->target_ns;
        destination->offcpu_ns = source->offcpu_ns;
        destination->blocked_ns = source->blocked_ns;
        destination->runqueue_ns = source->runqueue_ns;
    }
}

static void export_completed_chain(const struct stack_trace_event *event,
                                   struct output_options *output)
{
    struct cw_report_chain chain;
    bool failed = false;

    if ((!output->json_stream && !output->report_stream) ||
        output->export_failed)
        return;
    build_report_chain(event, output, &chain);
    if (output->json_stream) {
        failed = cw_write_chain_json(output->json_stream, &chain) ||
                 fputc('\n', output->json_stream) == EOF ||
                 fflush(output->json_stream);
    }
    if (!failed && output->report_stream) {
        failed = cw_html_report_write(output->report_stream, &chain,
                                      &output->report_first) ||
                 fflush(output->report_stream);
    }
    if (failed) {
        fprintf(stderr, "failed to write trace export: %s\n",
                strerror(errno ? errno : EIO));
        output->export_failed = true;
        exiting = 1;
    }
}

static void count_completed_chain(struct output_options *output)
{
    output->emitted_events++;
    if (output->max_events &&
        output->emitted_events >= output->max_events)
        exiting = 1;
}

static int handle_event(void *context, void *data, size_t data_size)
{
    const struct stack_trace_event *event = data;
    struct output_options *output = context;
    struct map_list maps = {0};
    size_t header_size = offsetof(struct stack_trace_event, stack);
    size_t entry_size = sizeof(*event);
    uint32_t maps_pid;

    if (output->max_events &&
        output->emitted_events >= output->max_events)
        return 0;
    if (data_size < header_size) {
        fprintf(stderr,
                "short event header received: %zu bytes (expected %zu)\n",
                data_size, header_size);
        return 0;
    }
    if (output->show_async && has_async_chain_filters(output)) {
        if (event->event_type == EVENT_ENTRY)
            return 0;
        if (event->event_type == EVENT_RETURN &&
            !async_chain_matches(event, output))
            return 0;
    }
    if (event->event_type == EVENT_RETURN && event->async_hop_count) {
        export_completed_chain(event, output);
        if (output->json_output) {
            count_completed_chain(output);
            return 0;
        }
    } else if (output->json_output) {
        return 0;
    }
    maps_pid = event->pid;

    print_event_time();
    printf("PID %u/TID %u (%.*s)", event->pid, event->tid,
           (int)sizeof(event->comm), event->comm);
    if (event->event_type == EVENT_RETURN) {
        printf(" RETURN");
        if (output->show_return_value)
            printf(" ret=0x%016llx (%lld)",
                   (unsigned long long)(uint64_t)event->return_value,
                   (long long)event->return_value);
        if (output->show_duration)
            print_interval("duration", event->duration_ns);
        if (output->show_attribution)
            print_attribution(event->duration_ns, event->offcpu_ns,
                              event->blocked_ns, event->runqueue_ns, false);
        putchar('\n');
    } else {
        if (output->show_return_value || output->show_duration)
            printf(" ENTRY");
        putchar('\n');
    }
    if (event->pidns_error) {
        fprintf(stderr,
                "warning: PID namespace translation failed: %s (%d); "
                "using global PID %u\n",
                strerror(-event->pidns_error), event->pidns_error,
                event->global_pid);
    } else if (event->pid != event->global_pid ||
               event->tid != event->global_tid) {
        printf("  global PID %u/TID %u\n",
               event->global_pid, event->global_tid);
    }
    fflush(stdout);

    if (event->event_type != EVENT_ENTRY) {
        if (event->event_type != EVENT_RETURN) {
            fprintf(stderr, "unknown event type: %u\n", event->event_type);
            return 0;
        }
    }
    if (event->event_type == EVENT_ENTRY && data_size < entry_size) {
        fprintf(stderr, "short entry event received: %zu bytes (expected %zu)\n",
                data_size, entry_size);
        return 0;
    }
    if ((event->event_type == EVENT_ENTRY ||
         (output->show_async && event->async_hop_count)) &&
        read_process_maps(maps_pid, &maps)) {
        int maps_error = errno;

        if (event->global_pid != maps_pid) {
            map_list_free(&maps);
            if (!read_process_maps(event->global_pid, &maps)) {
                maps_pid = event->global_pid;
                printf("  using global /proc/%u/maps\n", maps_pid);
                maps_error = 0;
            }
        }
        if (maps_error) {
            fflush(stdout);
            fprintf(stderr, "warning: cannot read /proc/%u/maps: %s\n",
                    maps_pid, strerror(maps_error));
        }
    }

    if (output->show_async && event->async_hop_count) {
        uint32_t hop_count = event->async_hop_count;
        uint32_t hop_index;

        if (hop_count > MAX_ASYNC_HOPS)
            hop_count = MAX_ASYNC_HOPS;
        if (event->async_truncated)
            printf("  ... %u earlier async hop(s) truncated ...\n",
                   event->async_truncated);
        for (hop_index = 0; hop_index < hop_count; hop_index++) {
            const struct async_hop_event *hop =
                &event->async_hops[hop_index];
            uint64_t async_stack[MAX_ASYNC_STACK_DEPTH] = {0};
            uint32_t hop_id = hop->reserved & ASYNC_HOP_ID_MASK;
            uint32_t configured_hop =
                hop_id ? hop_id - 1 : hop_index;
            uint32_t matched_target_arg =
                hop->reserved >> ASYNC_TARGET_ARG_SHIFT;

            const char *source_name = output->async_source_name;
            const char *target_name = output->final_target_name;

            if (configured_hop < output->async_hop_count) {
                source_name = output->async_hops[configured_hop].source;
                target_name = output->async_hops[configured_hop].target;
            }
            printf("  async hop %u %s -> %s PID %u/TID %u (%.*s) "
                   "key=0x%016llx target-arg=%u\n",
                   configured_hop,
                   source_name ? source_name : "source",
                   target_name ? target_name : "target",
                   hop->pid, hop->tid,
                   (int)sizeof(hop->comm), hop->comm,
                   (unsigned long long)hop->key,
                   matched_target_arg);
            printf("    ");
            print_interval("queue", hop->queue_ns);
            if (hop->target_ns) {
                print_interval("work", hop->target_ns);
                print_attribution(hop->target_ns, hop->offcpu_ns,
                                  hop->blocked_ns, hop->runqueue_ns, true);
            } else {
                printf(" work=unavailable");
            }
            putchar('\n');
            if (hop->pid != hop->global_pid ||
                hop->tid != hop->global_tid)
                printf("  async global PID %u/TID %u\n",
                       hop->global_pid, hop->global_tid);
            if (hop->stack_id < 0) {
                printf("  async unable to collect user stack: %s (%d)\n",
                       strerror(-hop->stack_id), hop->stack_id);
            } else if (output->async_stack_map_fd < 0) {
                printf("  async stack map is unavailable\n");
            } else if (bpf_map_lookup_elem(output->async_stack_map_fd,
                                           &hop->stack_id,
                                           async_stack)) {
                printf("  async stack id %d is unavailable: %s\n",
                       hop->stack_id, strerror(errno));
            } else {
                print_stack_frames(async_stack, sizeof(async_stack),
                                   &maps, "async ", NULL, NULL, 0);
            }
        }
    }
    if (output->show_discovery && event->discovery_valid) {
        const struct discovery_wakeup *waker = &event->discovery_waker;
        struct map_list waker_maps = {0};
        uint64_t waker_stack[MAX_ASYNC_STACK_DEPTH] = {0};
        char candidate[256] = {0};
        uint32_t waker_maps_pid = waker->pid;

        printf("  async discovery: latest waker PID %u/TID %u (%.*s)",
               waker->pid, waker->tid, (int)sizeof(waker->comm),
               waker->comm);
        print_interval("wake-to-target", event->discovery_wakeup_ns);
        putchar('\n');
        if (waker->pid != waker->global_pid ||
            waker->tid != waker->global_tid)
            printf("  waker global PID %u/TID %u\n",
                   waker->global_pid, waker->global_tid);
        if (waker->pidns_error)
            printf("  waker PID namespace translation failed: %s (%d)\n",
                   strerror(-waker->pidns_error), waker->pidns_error);

        if (read_process_maps(waker_maps_pid, &waker_maps) &&
            waker->global_pid != waker_maps_pid) {
            map_list_free(&waker_maps);
            waker_maps_pid = waker->global_pid;
            read_process_maps(waker_maps_pid, &waker_maps);
        }

        if (waker->stack_id < 0) {
            printf("  unable to collect waker user stack: %s (%d)\n",
                   strerror(-waker->stack_id), waker->stack_id);
        } else if (output->discovery_stack_map_fd < 0) {
            printf("  discovery stack map is unavailable\n");
        } else if (bpf_map_lookup_elem(output->discovery_stack_map_fd,
                                       &waker->stack_id, waker_stack)) {
            printf("  discovery stack id %d is unavailable: %s\n",
                   waker->stack_id, strerror(errno));
        } else {
            print_stack_frames(waker_stack, sizeof(waker_stack),
                               &waker_maps, "waker ",
                               output->target_path, candidate,
                               sizeof(candidate));
        }

        if (candidate[0]) {
            printf("  candidate source function: %s\n", candidate);
            if (output->discovery_target_arg) {
                printf("  suggested template:\n"
                       "    --async-hop %s,?,%s,%u %s\n",
                       candidate,
                       output->final_target_name ?
                           output->final_target_name : "TARGET",
                       output->discovery_target_arg,
                       output->final_target_name ?
                           output->final_target_name : "TARGET");
            } else {
                printf("  suggested template:\n"
                       "    --async-hop %s,?,%s %s\n",
                       candidate,
                       output->final_target_name ?
                           output->final_target_name : "TARGET",
                       output->final_target_name ?
                           output->final_target_name : "TARGET");
            }
        } else {
            printf("  no source symbol was inferred; inspect the waker "
                   "stack and choose the enqueue/submit frame\n");
        }
        map_list_free(&waker_maps);
    }
    if (event->event_type == EVENT_RETURN) {
        if (output->show_async && event->async_hop_count)
            count_completed_chain(output);
        putchar('\n');
        map_list_free(&maps);
        return 0;
    }
    print_stack_frames(event->stack, event->stack_size, &maps, "",
                       NULL, NULL, 0);
    putchar('\n');

    map_list_free(&maps);
    return 0;
}

enum long_option_id {
    OPT_ASYNC_SOURCE = 1000,
    OPT_ASYNC_SOURCE_BINARY,
    OPT_ASYNC_SOURCE_ARG,
    OPT_ASYNC_TARGET_ARG,
    OPT_ASYNC_MAX_AGE_MS,
    OPT_ASYNC_HOP,
    OPT_DISCOVER_ASYNC,
    OPT_CONFIG,
    OPT_CHECK_CONFIG,
    OPT_MIN_TOTAL_MS,
    OPT_MIN_QUEUE_MS,
    OPT_MIN_WORK_MS,
    OPT_MAX_EVENTS,
    OPT_DURATION,
    OPT_FORMAT,
    OPT_OUTPUT,
    OPT_REPORT,
};

static void free_async_hops(struct async_hop_config *hops, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free(hops[i].source);
        free(hops[i].target);
    }
}

static int parse_async_hop(const char *text, struct async_hop_config *hop)
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

static int parse_cli_ms(const char *option, const char *value,
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

static int parse_trace_config(const char *path,
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

int main(int argc, char **argv)
{
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"pid", required_argument, NULL, 'p'},
        {"binary", required_argument, NULL, 'b'},
        {"module", required_argument, NULL, 'm'},
        {"find-symbol", required_argument, NULL, 's'},
        {"offset", required_argument, NULL, 'o'},
        {"ret", no_argument, NULL, 'r'},
        {"return-value", no_argument, NULL, 'r'},
        {"time", no_argument, NULL, 't'},
        {"latency", no_argument, NULL, 't'},
        {"attribution", no_argument, NULL, 'a'},
        {"breakdown", no_argument, NULL, 'a'},
        {"async-source", required_argument, NULL, OPT_ASYNC_SOURCE},
        {"async-source-binary", required_argument, NULL,
         OPT_ASYNC_SOURCE_BINARY},
        {"async-source-arg", required_argument, NULL, OPT_ASYNC_SOURCE_ARG},
        {"async-target-arg", required_argument, NULL, OPT_ASYNC_TARGET_ARG},
        {"async-max-age-ms", required_argument, NULL, OPT_ASYNC_MAX_AGE_MS},
        {"async-hop", required_argument, NULL, OPT_ASYNC_HOP},
        {"discover-async", required_argument, NULL, OPT_DISCOVER_ASYNC},
        {"config", required_argument, NULL, OPT_CONFIG},
        {"check-config", required_argument, NULL, OPT_CHECK_CONFIG},
        {"min-total-ms", required_argument, NULL, OPT_MIN_TOTAL_MS},
        {"min-queue-ms", required_argument, NULL, OPT_MIN_QUEUE_MS},
        {"min-work-ms", required_argument, NULL, OPT_MIN_WORK_MS},
        {"max-events", required_argument, NULL, OPT_MAX_EVENTS},
        {"duration", required_argument, NULL, OPT_DURATION},
        {"format", required_argument, NULL, OPT_FORMAT},
        {"output", required_argument, NULL, OPT_OUTPUT},
        {"report", required_argument, NULL, OPT_REPORT},
        {0, 0, 0, 0},
    };
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
    };
    struct bpf_uprobe_opts return_options = {
        .sz = sizeof(return_options),
        .retprobe = true,
    };
    struct output_options output = {
        .async_stack_map_fd = -1,
        .discovery_stack_map_fd = -1,
    };
    struct callweave_bpf *skeleton = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct async_hop_config async_hops[MAX_ASYNC_HOPS] = {0};
    struct bpf_link *async_links[MAX_ASYNC_HOPS * 3] = {0};
    char target_path[PATH_MAX] = {0};
    char async_source_path[PATH_MAX] = {0};
    const char *binary_argument = NULL;
    const char *module_name = NULL;
    const char *find_symbol_name = NULL;
    const char *offset_text = NULL;
    const char *function_name = NULL;
    const char *async_source_name = NULL;
    const char *async_source_binary = NULL;
    const char *discover_function = NULL;
    const char *config_path = NULL;
    const char *output_path = NULL;
    const char *report_path = NULL;
    char *configured_function = NULL;
    size_t function_offset = 0;
    uint32_t async_source_arg = 1;
    uint32_t async_target_arg = 0;
    uint32_t async_max_age_ms = 30000;
    uint32_t duration_seconds = 0;
    uint64_t stop_time_ns = 0;
    size_t async_hop_count = 0;
    size_t async_link_count = 0;
    pid_t target_pid = -1;
    bool async_option_seen = false;
    bool check_config = false;
    bool json_output = false;
    int remaining_arguments;
    int option;
    int error = 0;
    int argument_index;

    for (argument_index = 1; argument_index < argc; argument_index++) {
        const char *argument = argv[argument_index];

        if (!strcmp(argument, "--config")) {
            if (++argument_index >= argc || config_path) {
                fprintf(stderr,
                        "--config requires one path and may appear once\n");
                return 2;
            }
            config_path = argv[argument_index];
        } else if (!strcmp(argument, "--check-config")) {
            if (++argument_index >= argc || config_path) {
                fprintf(stderr,
                        "--check-config requires one path and cannot be "
                        "combined with --config\n");
                return 2;
            }
            config_path = argv[argument_index];
            check_config = true;
        } else if (!strncmp(argument, "--config=", 9)) {
            if (config_path || !argument[9]) {
                fprintf(stderr,
                        "--config requires one path and may appear once\n");
                return 2;
            }
            config_path = argument + 9;
        } else if (!strncmp(argument, "--check-config=", 15)) {
            if (config_path || !argument[15]) {
                fprintf(stderr,
                        "--check-config requires one path and cannot be "
                        "combined with --config\n");
                return 2;
            }
            config_path = argument + 15;
            check_config = true;
        }
    }
    if (config_path) {
        if (parse_trace_config(config_path, async_hops, &async_hop_count,
                               &configured_function, &output,
                               &duration_seconds)) {
            error = 2;
            goto cleanup;
        }
        output.show_async = true;
    }

    while ((option = getopt_long(argc, argv, "hp:b:m:s:o:rta",
                                 long_options, NULL)) != -1) {
        switch (option) {
        case 'h':
            usage(stdout, argv[0]);
            return 0;
        case 'p':
            if (parse_pid(optarg, &target_pid)) {
                fprintf(stderr, "invalid PID: %s\n", optarg);
                return 2;
            }
            break;
        case 'b':
            binary_argument = optarg;
            break;
        case 'm':
            module_name = optarg;
            break;
        case 's':
            find_symbol_name = optarg;
            break;
        case 'o':
            offset_text = optarg;
            break;
        case 'r':
            output.show_return_value = true;
            break;
        case 't':
            output.show_duration = true;
            break;
        case 'a':
            output.show_attribution = true;
            output.show_duration = true;
            break;
        case OPT_ASYNC_SOURCE:
            async_source_name = optarg;
            output.show_async = true;
            break;
        case OPT_ASYNC_SOURCE_BINARY:
            async_source_binary = optarg;
            async_option_seen = true;
            break;
        case OPT_ASYNC_SOURCE_ARG:
            async_option_seen = true;
            if (parse_u32_range(optarg, 1, 8, &async_source_arg)) {
                fprintf(stderr, "invalid async source argument: %s\n",
                        optarg);
                return 2;
            }
            break;
        case OPT_ASYNC_TARGET_ARG:
            async_option_seen = true;
            if (!strcmp(optarg, "auto")) {
                async_target_arg = 0;
            } else if (parse_u32_range(optarg, 1, 8,
                                       &async_target_arg)) {
                fprintf(stderr, "invalid async target argument: %s\n",
                        optarg);
                return 2;
            }
            break;
        case OPT_ASYNC_MAX_AGE_MS:
            if (parse_u32_range(optarg, 1, UINT32_MAX,
                                &async_max_age_ms)) {
                fprintf(stderr, "invalid async maximum age: %s\n", optarg);
                return 2;
            }
            break;
        case OPT_ASYNC_HOP:
            if (config_path) {
                fprintf(stderr,
                        "--async-hop cannot be combined with --config\n");
                error = 2;
                goto cleanup;
            }
            if (async_hop_count >= MAX_ASYNC_HOPS) {
                fprintf(stderr, "at most %d async hops are supported\n",
                        MAX_ASYNC_HOPS);
                error = 2;
                goto cleanup;
            }
            if (parse_async_hop(optarg, &async_hops[async_hop_count])) {
                fprintf(stderr,
                        "invalid async hop '%s'; expected "
                        "SOURCE,SOURCE_ARG,TARGET[,TARGET_ARG]\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            async_hop_count++;
            output.show_async = true;
            break;
        case OPT_DISCOVER_ASYNC:
            discover_function = optarg;
            output.show_discovery = true;
            break;
        case OPT_CONFIG:
            break;
        case OPT_CHECK_CONFIG:
            break;
        case OPT_MIN_TOTAL_MS:
            if (parse_cli_ms("--min-total-ms", optarg,
                             &output.min_total_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MIN_QUEUE_MS:
            if (parse_cli_ms("--min-queue-ms", optarg,
                             &output.min_queue_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MIN_WORK_MS:
            if (parse_cli_ms("--min-work-ms", optarg,
                             &output.min_work_ns)) {
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_MAX_EVENTS:
            if (parse_u32_range(optarg, 1, UINT32_MAX,
                                &output.max_events)) {
                fprintf(stderr, "invalid maximum event count: %s\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_DURATION:
            if (parse_u32_range(optarg, 1, UINT32_MAX,
                                &duration_seconds)) {
                fprintf(stderr, "invalid duration: %s\n", optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_FORMAT:
            if (!strcmp(optarg, "json")) {
                json_output = true;
            } else if (!strcmp(optarg, "text")) {
                json_output = false;
            } else {
                fprintf(stderr,
                        "invalid output format '%s'; expected text or json\n",
                        optarg);
                error = 2;
                goto cleanup;
            }
            break;
        case OPT_OUTPUT:
            output_path = optarg;
            break;
        case OPT_REPORT:
            report_path = optarg;
            break;
        default:
            usage(stderr, argv[0]);
            return 2;
        }
    }

    remaining_arguments = argc - optind;
    if (check_config) {
        if (remaining_arguments) {
            fprintf(stderr,
                    "--check-config does not accept positional arguments\n");
            error = 2;
            goto cleanup;
        }
        printf("%s: valid (%zu async hop%s)\n",
               config_path, async_hop_count,
               async_hop_count == 1 ? "" : "s");
        goto cleanup;
    }
    if (output.show_async) {
        output.show_duration = true;
        output.show_attribution = true;
    }
    if (output_path && !json_output) {
        fprintf(stderr, "--output requires --format json\n");
        error = 2;
        goto cleanup;
    }
    if ((json_output || report_path) && !output.show_async) {
        fprintf(stderr,
                "--format json and --report require async tracing via "
                "--config, --async-hop, or --async-source\n");
        error = 2;
        goto cleanup;
    }
    if (output_path && report_path && !strcmp(output_path, report_path)) {
        fprintf(stderr,
                "--output and --report must use different paths\n");
        error = 2;
        goto cleanup;
    }
    output.json_output = json_output;
    if (module_name && target_pid <= 0) {
        fprintf(stderr, "--module requires --pid\n");
        return 2;
    }
    if (module_name && binary_argument) {
        fprintf(stderr, "--module and --binary are mutually exclusive\n");
        return 2;
    }
    if (output.show_discovery &&
        (output.show_async || async_source_name || async_hop_count)) {
        fprintf(stderr,
                "--discover-async cannot be combined with async tracing\n");
        error = 2;
        goto cleanup;
    }
    if ((output.min_total_ns || output.min_queue_ns ||
         output.min_work_ns || output.max_events) &&
        !output.show_async) {
        fprintf(stderr,
                "chain filters require --config, --async-hop, or "
                "--async-source\n");
        error = 2;
        goto cleanup;
    }
    if (output.show_discovery && target_pid <= 0) {
        fprintf(stderr, "--discover-async requires --pid\n");
        error = 2;
        goto cleanup;
    }
    if (async_hop_count && (async_source_name || async_option_seen)) {
        fprintf(stderr,
                "--async-hop cannot be combined with the legacy "
                "--async-source options\n");
        error = 2;
        goto cleanup;
    }
    if (!async_hop_count && async_option_seen && !async_source_name &&
        !output.show_discovery) {
        fprintf(stderr,
                "async tuning options require --async-source FUNCTION\n");
        error = 2;
        goto cleanup;
    }
    if (async_source_name && !async_source_name[0]) {
        fprintf(stderr, "async source function must not be empty\n");
        return 2;
    }

    error = validate_target_pid(target_pid);
    if (error)
        return 1;

    if (find_symbol_name) {
        int result;

        if (offset_text || remaining_arguments ||
            output.show_return_value || output.show_duration ||
            output.show_async || output.show_discovery) {
            fprintf(stderr,
                    "--find-symbol cannot be combined with --offset, "
                    "--ret, --time, --attribution, --async-source, or a "
                    "positional FUNCTION\n");
            return 2;
        }
        if (!find_symbol_name[0]) {
            fprintf(stderr, "symbol name must not be empty\n");
            return 2;
        }
        if (binary_argument) {
            if (!realpath(binary_argument, target_path)) {
                fprintf(stderr, "cannot resolve %s: %s\n",
                        binary_argument, strerror(errno));
                return 1;
            }
            result = print_symbol_result(target_path, find_symbol_name);
            if (result < 0)
                fprintf(stderr, "cannot inspect %s: %s\n",
                        target_path, strerror(errno));
            else if (!result)
                fprintf(stderr, "symbol '%s' was not found in %s\n",
                        find_symbol_name, target_path);
            return result > 0 ? 0 : 1;
        }
        if (target_pid <= 0) {
            fprintf(stderr,
                    "--find-symbol requires --pid or --binary\n");
            return 2;
        }
        if (module_name) {
            error = resolve_loaded_module(target_pid, module_name,
                                          target_path,
                                          sizeof(target_path));
            if (error)
                return 1;
            result = print_symbol_result(target_path, find_symbol_name);
            if (result < 0)
                fprintf(stderr, "cannot inspect %s: %s\n",
                        target_path, strerror(errno));
            else if (!result)
                fprintf(stderr, "symbol '%s' was not found in %s\n",
                        find_symbol_name, target_path);
            return result > 0 ? 0 : 1;
        }
        return find_symbol_in_process(target_pid, module_name,
                                      find_symbol_name) ? 1 : 0;
    }

    if (configured_function) {
        if (discover_function || offset_text || remaining_arguments) {
            fprintf(stderr,
                    "--config supplies target.function and cannot be "
                    "combined with another target function\n");
            error = 2;
            goto cleanup;
        }
        function_name = configured_function;
    } else if (discover_function) {
        if (offset_text || remaining_arguments || !discover_function[0]) {
            fprintf(stderr,
                    "--discover-async accepts its target as the option "
                    "argument and cannot be combined with --offset or a "
                    "positional FUNCTION\n");
            return 2;
        }
        function_name = discover_function;
    } else if (offset_text) {
        if (remaining_arguments || !binary_argument || module_name) {
            fprintf(stderr,
                    "--offset requires --binary and no positional FUNCTION\n");
            return 2;
        }
        if (parse_offset(offset_text, &function_offset)) {
            fprintf(stderr, "invalid ELF file offset: %s\n", offset_text);
            return 2;
        }
    } else if (remaining_arguments == 2 &&
               !binary_argument && !module_name) {
        binary_argument = argv[optind];
        function_name = argv[optind + 1];
    } else if (remaining_arguments == 1) {
        function_name = argv[optind];
    } else {
        usage(stderr, argv[0]);
        return 2;
    }

    if (!offset_text && (!function_name || !function_name[0])) {
        fprintf(stderr, "function name must not be empty\n");
        return 2;
    }
    output.async_hops = async_hops;
    output.async_hop_count = async_hop_count;
    output.async_source_name = async_source_name;
    output.final_target_name = function_name;
    output.discovery_target_arg = async_target_arg;

    if (module_name) {
        error = resolve_loaded_module(target_pid, module_name,
                                      target_path, sizeof(target_path));
        if (error)
            return 1;
    } else if (binary_argument) {
        if (!realpath(binary_argument, target_path)) {
            fprintf(stderr, "cannot resolve %s: %s\n",
                    binary_argument, strerror(errno));
            return 1;
        }
    } else if (target_pid > 0) {
        error = resolve_process_executable(target_pid, target_path,
                                           sizeof(target_path));
        if (error)
            return 1;
    } else {
        fprintf(stderr,
                "BINARY is required when --pid is not specified\n");
        return 2;
    }
    output.target_path = target_path;

    if (async_hop_count) {
        const struct async_hop_config *last =
            &async_hops[async_hop_count - 1];

        if (offset_text) {
            fprintf(stderr,
                    "--async-hop requires a named final target function\n");
            error = 2;
            goto cleanup;
        }
        if (strcmp(last->target, function_name)) {
            fprintf(stderr,
                    "the last async-hop target '%s' must match the traced "
                    "function '%s'\n",
                    last->target, function_name);
            error = 2;
            goto cleanup;
        }
        async_target_arg = last->target_arg;
    }

    if (output.show_async) {
        if (async_source_binary) {
            if (!realpath(async_source_binary, async_source_path)) {
                fprintf(stderr, "cannot resolve async source %s: %s\n",
                        async_source_binary, strerror(errno));
                return 1;
            }
        } else {
            snprintf(async_source_path, sizeof(async_source_path), "%s",
                     target_path);
        }
    }

    if (install_signal_handlers())
        return 1;

    skeleton = callweave_bpf__open();
    if (!skeleton) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }
    error = configure_pid_namespace(skeleton);
    if (error)
        goto cleanup;
    skeleton->rodata->target_pid =
        target_pid > 0 ? (uint32_t)target_pid : 0;
    skeleton->rodata->trace_returns =
        output.show_return_value || output.show_duration;
    skeleton->rodata->trace_attribution = output.show_attribution;
    skeleton->rodata->trace_async = output.show_async;
    skeleton->rodata->trace_discovery = output.show_discovery;
    skeleton->rodata->async_source_arg = async_source_arg;
    skeleton->rodata->async_target_arg = async_target_arg;
    skeleton->rodata->async_max_age_ns =
        (uint64_t)async_max_age_ms * 1000000ULL;
    if (!output.show_attribution) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_sched_switch, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_sched_wakeup, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable scheduler attribution programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (!output.show_discovery) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_sched_waking, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable async discovery program: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (!output.show_async) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_async_source, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable async source program: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }
    if (async_hop_count <= 1) {
        error = bpf_program__set_autoload(
            skeleton->progs.trace_async_target, false);
        if (!error)
            error = bpf_program__set_autoload(
                skeleton->progs.trace_async_target_return, false);
        if (error) {
            fprintf(stderr,
                    "failed to disable multi-hop target programs: %s\n",
                    strerror(-error));
            goto cleanup;
        }
    }

    error = callweave_bpf__load(skeleton);
    if (error) {
        fprintf(stderr, "failed to load BPF program: %s\n", strerror(-error));
        goto cleanup;
    }
    output.async_stack_map_fd = bpf_map__fd(skeleton->maps.async_stacks);
    output.discovery_stack_map_fd =
        bpf_map__fd(skeleton->maps.discovery_stacks);

    if (output.show_attribution) {
        error = attach_raw_tracepoint(
            skeleton->progs.trace_sched_switch,
            &skeleton->links.trace_sched_switch, "sched_switch");
        if (!error)
            error = attach_raw_tracepoint(
                skeleton->progs.trace_sched_wakeup,
                &skeleton->links.trace_sched_wakeup, "sched_wakeup");
        if (error)
            goto cleanup;
    } else if (output.show_discovery) {
        error = attach_raw_tracepoint(
            skeleton->progs.trace_sched_waking,
            &skeleton->links.trace_sched_waking, "sched_waking");
        if (error)
            goto cleanup;
    }

    if (output.show_return_value || output.show_duration) {
        return_options.func_name = offset_text ? NULL : function_name;
        skeleton->links.trace_function_return =
            bpf_program__attach_uprobe_opts(
                skeleton->progs.trace_function_return, -1, target_path,
                function_offset, &return_options);
        error = skeleton->links.trace_function_return ?
                libbpf_get_error(skeleton->links.trace_function_return) :
                (errno ? -errno : -EINVAL);
        if (error) {
            skeleton->links.trace_function_return = NULL;
            if (offset_text)
                fprintf(stderr,
                        "failed to attach uretprobe to %s+0x%zx: %s\n",
                        target_path, function_offset, strerror(-error));
            else
                fprintf(stderr,
                        "failed to attach uretprobe to %s:%s: %s\n",
                        target_path, function_name, strerror(-error));
            goto cleanup;
        }
    }

    if (async_hop_count) {
        size_t i;

        for (i = 0; i + 1 < async_hop_count; i++) {
            uint64_t target_cookie =
                (1ULL << 32) | async_hops[i].target_arg;

            error = attach_named_uprobe(
                skeleton->progs.trace_async_target_return,
                &async_links[async_link_count], target_path,
                async_hops[i].target, 0, true);
            if (error)
                goto cleanup;
            async_link_count++;
            error = attach_named_uprobe(
                skeleton->progs.trace_async_target,
                &async_links[async_link_count], target_path,
                async_hops[i].target, target_cookie, false);
            if (error)
                goto cleanup;
            async_link_count++;
        }
        for (i = 0; i < async_hop_count; i++) {
            uint64_t source_cookie =
                ((uint64_t)(i + 1) << 32) |
                async_hops[i].source_arg;

            error = attach_named_uprobe(
                skeleton->progs.trace_async_source,
                &async_links[async_link_count], target_path,
                async_hops[i].source, source_cookie, false);
            if (error)
                goto cleanup;
            async_link_count++;
        }
    } else if (output.show_async) {
        error = attach_named_uprobe(
            skeleton->progs.trace_async_source,
            &skeleton->links.trace_async_source, async_source_path,
            async_source_name, 0, false);
        if (error)
            goto cleanup;
    }

    options.func_name = offset_text ? NULL : function_name;
    skeleton->links.trace_function = bpf_program__attach_uprobe_opts(
        skeleton->progs.trace_function, -1, target_path,
        function_offset, &options);
    error = skeleton->links.trace_function ?
            libbpf_get_error(skeleton->links.trace_function) :
            (errno ? -errno : -EINVAL);
    if (error) {
        skeleton->links.trace_function = NULL;
        if (offset_text)
            fprintf(stderr,
                    "failed to attach uprobe to %s+0x%zx: %s\n",
                    target_path, function_offset, strerror(-error));
        else
            fprintf(stderr, "failed to attach uprobe to %s:%s: %s\n",
                    target_path, function_name, strerror(-error));
        goto cleanup;
    }

    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                                   handle_event, &output, NULL);
    if (!ring_buffer) {
        error = errno ? -errno : -ENOMEM;
        fprintf(stderr, "failed to create ring buffer: %s\n",
                strerror(-error));
        goto cleanup;
    }

    if (json_output) {
        if (output_path) {
            output.json_stream = fopen(output_path, "w");
            if (!output.json_stream) {
                error = -errno;
                fprintf(stderr, "cannot create JSON output %s: %s\n",
                        output_path, strerror(errno));
                goto cleanup;
            }
        } else {
            output.json_stream = stdout;
        }
    }
    if (report_path) {
        FILE *report_stream = fopen(report_path, "w");

        if (!report_stream) {
            error = -errno;
            fprintf(stderr, "cannot create HTML report %s: %s\n",
                    report_path, strerror(errno));
            goto cleanup;
        }
        output.report_first = true;
        if (cw_html_report_begin(report_stream)) {
            error = -(errno ? errno : EIO);
            fprintf(stderr, "cannot initialize HTML report %s: %s\n",
                    report_path, strerror(-error));
            fclose(report_stream);
            goto cleanup;
        }
        output.report_stream = report_stream;
    }

    if (json_output) {
        if (offset_text)
            fprintf(stderr, "Tracing %s+0x%zx", target_path,
                    function_offset);
        else
            fprintf(stderr, "Tracing %s:%s", target_path, function_name);
        if (target_pid > 0)
            fprintf(stderr, " in PID %d", target_pid);
        else
            fprintf(stderr, " in all processes");
        fprintf(stderr, ", JSON Lines output");
        if (output_path)
            fprintf(stderr, " to %s", output_path);
        if (report_path)
            fprintf(stderr, ", HTML report %s", report_path);
        fprintf(stderr, ". Press Ctrl+C to stop.\n");
    } else {
        if (offset_text)
            printf("Tracing %s+0x%zx", target_path, function_offset);
        else
            printf("Tracing %s:%s", target_path, function_name);
        if (target_pid > 0)
            printf(" in PID %d", target_pid);
        else
            printf(" in all processes");
        if (output.show_return_value)
            printf(", return values enabled");
        if (output.show_duration)
            printf(", timing enabled");
        if (output.show_attribution)
            printf(", scheduler attribution enabled");
        if (async_hop_count)
            printf(", %zu async hop%s enabled", async_hop_count,
                   async_hop_count == 1 ? "" : "s");
        else if (output.show_async) {
            if (async_target_arg)
                printf(", async source %s:%s arg%u -> target arg%u",
                       async_source_path, async_source_name,
                       async_source_arg, async_target_arg);
            else
                printf(", async source %s:%s arg%u -> target auto",
                       async_source_path, async_source_name,
                       async_source_arg);
        }
        if (output.show_discovery) {
            if (async_target_arg)
                printf(", async discovery enabled for target arg%u",
                       async_target_arg);
            else
                printf(", async discovery enabled for target auto");
        }
        if (output.min_total_ns) {
            printf(",");
            print_interval("min-total", output.min_total_ns);
        }
        if (output.min_queue_ns) {
            printf(",");
            print_interval("min-queue", output.min_queue_ns);
        }
        if (output.min_work_ns) {
            printf(",");
            print_interval("min-work", output.min_work_ns);
        }
        if (output.max_events)
            printf(", max events %u", output.max_events);
        if (duration_seconds)
            printf(", duration %u s", duration_seconds);
        if (report_path)
            printf(", HTML report %s", report_path);
        printf(". Press Ctrl+C to stop.\n");
    }

    if (duration_seconds)
        stop_time_ns = monotonic_time_ns() +
                       (uint64_t)duration_seconds * 1000000000ULL;
    while (!exiting) {
        error = ring_buffer__poll(ring_buffer, 250);
        if (error == -EINTR) {
            error = 0;
            if (exiting)
                break;
            continue;
        }
        if (error < 0) {
            fprintf(stderr, "ring buffer polling failed: %s\n",
                    strerror(-error));
            break;
        }
        error = 0;
        if (stop_time_ns && monotonic_time_ns() >= stop_time_ns)
            break;
    }

cleanup:
    if (output.report_stream) {
        if ((cw_html_report_end(output.report_stream) ||
             fflush(output.report_stream)) && !error) {
            error = -(errno ? errno : EIO);
            fprintf(stderr, "failed to finalize HTML report: %s\n",
                    strerror(-error));
        }
        if (fclose(output.report_stream) && !error)
            error = -errno;
    }
    if (output.json_stream) {
        if (fflush(output.json_stream) && !error)
            error = -errno;
        if (output.json_stream != stdout &&
            fclose(output.json_stream) && !error)
            error = -errno;
    }
    if (output.export_failed && !error)
        error = -EIO;
    while (async_link_count)
        bpf_link__destroy(async_links[--async_link_count]);
    if (ring_buffer)
        ring_buffer__free(ring_buffer);
    if (skeleton)
        callweave_bpf__destroy(skeleton);
    free_async_hops(async_hops, async_hop_count);
    free(configured_function);
    return error ? 1 : 0;
}
