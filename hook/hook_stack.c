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

#include "hook_stack.skel.h"

#define MAX_STACK_DEPTH 128

enum event_type {
    EVENT_ENTRY,
    EVENT_RETURN,
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
    uint64_t stack[MAX_STACK_DEPTH];
};

struct output_options {
    bool show_return_value;
    bool show_duration;
};

_Static_assert(offsetof(struct stack_trace_event, stack) == 64,
               "userspace and BPF event layouts differ");
_Static_assert(sizeof(struct stack_trace_event) == 1088,
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

static int configure_pid_namespace(struct hook_stack_bpf *skeleton)
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

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage:\n"
            "  %s [OPTIONS] BINARY FUNCTION\n"
            "  %s -p PID [--module MODULE] FUNCTION\n"
            "  %s -p PID [--module MODULE] --find-symbol SYMBOL\n"
            "  %s --binary BINARY --offset OFFSET\n"
            "\n"
            "Options:\n"
            "  -p, --pid PID             only emit events from PID\n"
            "  -b, --binary PATH         executable or shared-library path\n"
            "  -m, --module MODULE       mapped module basename or absolute path\n"
            "  -s, --find-symbol SYMBOL  find SYMBOL in mapped ELF modules and exit\n"
            "  -o, --offset OFFSET       attach at an ELF file offset\n"
            "  -r, --ret                 print the raw function return value\n"
            "  -t, --time                print function execution time\n"
            "  -h, --help                show this help\n"
            "\n"
            "When -p is used without --binary or --module, /proc/PID/exe is used.\n"
            "Without -p, an explicit BINARY is required.\n",
            program, program, program, program);
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

static int handle_event(void *context, void *data, size_t data_size)
{
    const struct stack_trace_event *event = data;
    const struct output_options *output = context;
    struct frame_info frames[MAX_STACK_DEPTH] = {0};
    struct map_list maps = {0};
    size_t header_size = offsetof(struct stack_trace_event, stack);
    size_t frame_count;
    uint32_t maps_pid = event->pid;
    size_t i;

    if (data_size < header_size) {
        fprintf(stderr,
                "short event header received: %zu bytes (expected %zu)\n",
                data_size, header_size);
        return 0;
    }

    print_event_time();
    printf("PID %u/TID %u (%.*s)", event->pid, event->tid,
           (int)sizeof(event->comm), event->comm);
    if (event->event_type == EVENT_RETURN) {
        printf(" RETURN");
        if (output->show_return_value)
            printf(" ret=0x%016llx (%lld)",
                   (unsigned long long)(uint64_t)event->return_value,
                   (long long)event->return_value);
        if (output->show_duration) {
            if (event->duration_ns >= 1000000000ULL)
                printf(" duration=%.6f s",
                       (double)event->duration_ns / 1000000000.0);
            else if (event->duration_ns >= 1000000ULL)
                printf(" duration=%.3f ms",
                       (double)event->duration_ns / 1000000.0);
            else if (event->duration_ns >= 1000ULL)
                printf(" duration=%.3f us",
                       (double)event->duration_ns / 1000.0);
            else
                printf(" duration=%llu ns",
                       (unsigned long long)event->duration_ns);
        }
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

    if (event->event_type == EVENT_RETURN) {
        putchar('\n');
        return 0;
    }
    if (event->event_type != EVENT_ENTRY) {
        fprintf(stderr, "unknown event type: %u\n", event->event_type);
        return 0;
    }
    if (data_size < sizeof(*event)) {
        fprintf(stderr, "short entry event received: %zu bytes (expected %zu)\n",
                data_size, sizeof(*event));
        return 0;
    }

    if (event->stack_size < 0) {
        printf("  unable to collect user stack: %s (%d)\n\n",
               strerror(-event->stack_size), event->stack_size);
        return 0;
    }
    if (event->stack_size == 0) {
        printf("  empty user stack\n\n");
        return 0;
    }

    frame_count = (size_t)event->stack_size / sizeof(event->stack[0]);
    if (frame_count > MAX_STACK_DEPTH)
        frame_count = MAX_STACK_DEPTH;

    if (read_process_maps(maps_pid, &maps)) {
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

    for (i = 0; i < frame_count; i++) {
        frames[i].ip = event->stack[i];
        frames[i].map = find_map(&maps, frames[i].ip);
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
        if (!frames[i].map) {
            printf("  #%-3zu 0x%016llx [unmapped]\n", i,
                   (unsigned long long)frames[i].ip);
        } else if (!frames[i].map->path[0]) {
            printf("  #%-3zu 0x%016llx [anonymous]\n", i,
                   (unsigned long long)frames[i].ip);
        } else {
            printf("  #%-3zu 0x%016llx %-24s %s\n", i,
                   (unsigned long long)frames[i].ip,
                   path_basename(frames[i].map->path),
                   frames[i].symbol ? frames[i].symbol : "?? at ??:0");
        }
        free(frames[i].symbol);
    }
    putchar('\n');

    map_list_free(&maps);
    return 0;
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
        {0, 0, 0, 0},
    };
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options),
    };
    struct bpf_uprobe_opts return_options = {
        .sz = sizeof(return_options),
        .retprobe = true,
    };
    struct output_options output = {0};
    struct hook_stack_bpf *skeleton = NULL;
    struct ring_buffer *ring_buffer = NULL;
    char target_path[PATH_MAX] = {0};
    const char *binary_argument = NULL;
    const char *module_name = NULL;
    const char *find_symbol_name = NULL;
    const char *offset_text = NULL;
    const char *function_name = NULL;
    size_t function_offset = 0;
    pid_t target_pid = -1;
    int remaining_arguments;
    int option;
    int error = 0;

    while ((option = getopt_long(argc, argv, "hp:b:m:s:o:rt",
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
        default:
            usage(stderr, argv[0]);
            return 2;
        }
    }

    remaining_arguments = argc - optind;
    if (module_name && target_pid <= 0) {
        fprintf(stderr, "--module requires --pid\n");
        return 2;
    }
    if (module_name && binary_argument) {
        fprintf(stderr, "--module and --binary are mutually exclusive\n");
        return 2;
    }

    error = validate_target_pid(target_pid);
    if (error)
        return 1;

    if (find_symbol_name) {
        int result;

        if (offset_text || remaining_arguments ||
            output.show_return_value || output.show_duration) {
            fprintf(stderr,
                    "--find-symbol cannot be combined with --offset, "
                    "--ret, --time, or a positional FUNCTION\n");
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

    if (offset_text) {
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

    if (install_signal_handlers())
        return 1;

    skeleton = hook_stack_bpf__open();
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

    error = hook_stack_bpf__load(skeleton);
    if (error) {
        fprintf(stderr, "failed to load BPF program: %s\n", strerror(-error));
        goto cleanup;
    }

    options.func_name = offset_text ? NULL : function_name;
    skeleton->links.trace_function = bpf_program__attach_uprobe_opts(
        skeleton->progs.trace_function, -1, target_path,
        function_offset, &options);
    if (!skeleton->links.trace_function) {
        error = errno ? -errno : -EINVAL;
        if (offset_text)
            fprintf(stderr,
                    "failed to attach uprobe to %s+0x%zx: %s\n",
                    target_path, function_offset, strerror(-error));
        else
            fprintf(stderr, "failed to attach uprobe to %s:%s: %s\n",
                    target_path, function_name, strerror(-error));
        goto cleanup;
    }

    if (output.show_return_value || output.show_duration) {
        return_options.func_name = offset_text ? NULL : function_name;
        skeleton->links.trace_function_return =
            bpf_program__attach_uprobe_opts(
                skeleton->progs.trace_function_return, -1, target_path,
                function_offset, &return_options);
        if (!skeleton->links.trace_function_return) {
            error = errno ? -errno : -EINVAL;
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

    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                                   handle_event, &output, NULL);
    if (!ring_buffer) {
        error = errno ? -errno : -ENOMEM;
        fprintf(stderr, "failed to create ring buffer: %s\n",
                strerror(-error));
        goto cleanup;
    }

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
    printf(". Press Ctrl+C to stop.\n");

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
    }

cleanup:
    if (ring_buffer)
        ring_buffer__free(ring_buffer);
    if (skeleton)
        hook_stack_bpf__destroy(skeleton);
    return error ? 1 : 0;
}
