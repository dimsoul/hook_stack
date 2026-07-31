// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "callweave_internal.h"
#include "symbols.h"

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

static const char *path_basename(const char *path);
static struct proc_map *find_map(
    struct map_list *maps, uint64_t address);
void map_list_free(struct map_list *maps)
{
    free(maps->items);
    maps->items = NULL;
    maps->count = 0;
    maps->capacity = 0;
}

int read_process_maps(uint32_t pid, struct map_list *maps);

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

int read_process_maps(uint32_t pid, struct map_list *maps)
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

int resolve_process_executable(pid_t pid, char *path, size_t path_size)
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

int resolve_loaded_module(pid_t pid, const char *module,
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

int resolve_process_symbol_module(pid_t pid, const char *symbol_name,
                                  char *path, size_t path_size)
{
    struct map_list maps = {0};
    size_t matches = 0;
    size_t i;
    int error = 0;

    if (read_process_maps((uint32_t)pid, &maps))
        return -(errno ? errno : EIO);
    for (i = 0; i < maps.count; i++) {
        struct elf_symbol_info info;
        int result;

        if (!is_first_path_occurrence(&maps, i) ||
            access(maps.items[i].path, R_OK))
            continue;
        result = find_elf_symbol(
            maps.items[i].path, symbol_name, &info);
        if (result < 0)
            continue;
        if (!result)
            continue;
        matches++;
        if (matches == 1 &&
            snprintf(path, path_size, "%s",
                     maps.items[i].path) >= (int)path_size) {
            error = -ENAMETOOLONG;
            goto out;
        }
    }
    if (!matches)
        error = -ENOENT;
    else if (matches > 1)
        error = -ENOTUNIQ;
out:
    map_list_free(&maps);
    return error;
}

static int linked_candidate(
    char *line, char *candidate, size_t candidate_size)
{
    char *start = strstr(line, "=>");
    char *end;

    if (start)
        start += 2;
    else
        start = line;
    while (*start == ' ' || *start == '\t')
        start++;
    if (*start != '/')
        return 0;
    end = start;
    while (*end && *end != ' ' && *end != '\t' &&
           *end != '\r' && *end != '\n')
        end++;
    if ((size_t)(end - start) >= candidate_size)
        return -ENAMETOOLONG;
    memcpy(candidate, start, (size_t)(end - start));
    candidate[end - start] = '\0';
    return 1;
}

int resolve_linked_symbol_module(const char *executable,
                                 const char *symbol_name,
                                 char *path, size_t path_size)
{
    struct elf_symbol_info info;
    char candidate[PATH_MAX];
    char resolved[PATH_MAX];
    char *line = NULL;
    size_t line_capacity = 0;
    int pipe_fds[2] = {-1, -1};
    FILE *output = NULL;
    pid_t child = -1;
    int result;
    int status = 0;
    int error = -ENOENT;

    result = find_elf_symbol(executable, symbol_name, &info);
    if (result > 0) {
        if (snprintf(path, path_size, "%s", executable) >=
            (int)path_size)
            return -ENAMETOOLONG;
        return 0;
    }
    if (pipe2(pipe_fds, O_CLOEXEC))
        return -errno;
    child = fork();
    if (child < 0) {
        error = -errno;
        goto out;
    }
    if (!child) {
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        execlp("ldd", "ldd", "--", executable, (char *)NULL);
        _exit(127);
    }
    close(pipe_fds[1]);
    pipe_fds[1] = -1;
    output = fdopen(pipe_fds[0], "r");
    if (!output) {
        error = -errno;
        goto out;
    }
    pipe_fds[0] = -1;
    while (getline(&line, &line_capacity, output) >= 0) {
        result = linked_candidate(
            line, candidate, sizeof(candidate));
        if (result <= 0 || !realpath(candidate, resolved))
            continue;
        result = find_elf_symbol(resolved, symbol_name, &info);
        if (result <= 0)
            continue;
        if (snprintf(path, path_size, "%s", resolved) >=
            (int)path_size)
            error = -ENAMETOOLONG;
        else
            error = 0;
        break;
    }
out:
    free(line);
    if (output)
        fclose(output);
    if (pipe_fds[0] >= 0)
        close(pipe_fds[0]);
    if (pipe_fds[1] >= 0)
        close(pipe_fds[1]);
    if (child > 0) {
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
            ;
    }
    return error;
}

int resolve_process_address(pid_t pid, uint64_t address,
                            char *path, size_t path_size,
                            uint64_t *file_offset)
{
    struct map_list maps = {0};
    struct proc_map *map;
    int error = 0;

    if (!path || !path_size || !file_offset)
        return -EINVAL;
    if (read_process_maps((uint32_t)pid, &maps))
        return -(errno ? errno : EIO);
    map = find_map(&maps, address);
    if (!map || !map->path[0] || !strchr(map->perms, 'x')) {
        error = -ENOENT;
        goto out;
    }
    if (snprintf(path, path_size, "%s", map->path) >=
        (int)path_size) {
        error = -ENAMETOOLONG;
        goto out;
    }
    *file_offset = map->offset + (address - map->start);
out:
    map_list_free(&maps);
    return error;
}

int print_symbol_result(const char *path, const char *symbol_name)
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

int find_symbol_in_process(pid_t pid, const char *module,
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

static int wait_for_child(pid_t child, int *status,
                          struct cw_capture_control *control)
{
    pid_t result;

    if (!control) {
        do {
            result = waitpid(child, status, 0);
        } while (result < 0 && errno == EINTR);
        return result < 0 ? -1 : 0;
    }
    for (;;) {
        if (cw_capture_cancelled(control)) {
            kill(child, SIGKILL);
            do {
                result = waitpid(child, status, 0);
            } while (result < 0 && errno == EINTR);
            return -1;
        }
        result = waitpid(child, status, WNOHANG);
        if (result == child)
            return 0;
        if (result < 0 && errno != EINTR)
            return -1;
        cw_capture_wait(control, 50);
    }
}

static bool wait_for_symbol_output(
    FILE *output, struct cw_capture_control *control)
{
    struct pollfd descriptors[2] = {
        {
            .fd = fileno(output),
            .events = POLLIN,
        },
        {
            .fd = cw_capture_signal_fd(control),
            .events = POLLIN,
        },
    };
    nfds_t count = descriptors[1].fd >= 0 ? 2 : 1;
    int result;

    do {
        result = poll(descriptors, count, -1);
    } while (result < 0 && errno == EINTR);
    if (result <= 0)
        return false;
    if (count == 2 && descriptors[1].revents)
        cw_capture_drain_signals(control);
    if (cw_capture_cancelled(control))
        return false;
    return descriptors[0].revents & (POLLIN | POLLHUP);
}

static int symbolize_group(struct frame_info *frames, const size_t *indices,
                           size_t count, const char *module_path,
                           struct cw_capture_control *control)
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
        cw_capture_prepare_child(control);
        execvp(arguments[0], arguments);
        _exit(127);
    }

    close(pipe_fds[1]);
    output = fdopen(pipe_fds[0], "r");
    if (!output) {
        close(pipe_fds[0]);
        wait_for_child(child, &status, control);
        return -1;
    }
    setvbuf(output, NULL, _IONBF, 0);

    for (i = 0;
         i < count && !cw_capture_cancelled(control) &&
         wait_for_symbol_output(output, control) &&
         getline(&line, &line_capacity, output) >= 0;
         i++) {
        line[strcspn(line, "\r\n")] = '\0';
        frames[indices[i]].symbol = strdup(line);
    }

    free(line);
    fclose(output);
    if (wait_for_child(child, &status, control))
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void resolve_frames(struct frame_info *frames, size_t frame_count,
                           struct cw_capture_control *control)
{
    bool grouped[MAX_STACK_DEPTH] = {0};
    size_t indices[MAX_STACK_DEPTH];
    size_t i, j;

    for (i = 0; i < frame_count; i++) {
        if (cw_capture_cancelled(control))
            break;
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
        symbolize_group(frames, indices, group_count,
                        frames[i].map->path, control);
    }
}

void print_stack_frames(const uint64_t *stack, int32_t stack_size,
                        struct map_list *maps, const char *prefix,
                        const char *candidate_path,
                        char *candidate, size_t candidate_size,
                        struct cw_capture_control *control)
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

    for (i = 0;
         i < frame_count && !cw_capture_cancelled(control);
         i++) {
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

    resolve_frames(frames, frame_count, control);
    if (cw_capture_cancelled(control)) {
        for (i = 0; i < frame_count; i++)
            free(frames[i].symbol);
        return;
    }
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
