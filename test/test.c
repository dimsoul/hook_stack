// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

__attribute__((noinline)) long function_to_trace(void)
{
    struct stat file_status;

    if (stat(".", &file_status) == 0) {
        printf("stat succeeded; inode: %llu\n",
               (unsigned long long)file_status.st_ino);
        return (long)file_status.st_ino;
    }

    perror("stat failed");
    return -1;
}

__attribute__((noinline)) static void call_trace_target(void)
{
    volatile long result = function_to_trace();

    (void)result;
}

int main(void)
{
    for (;;) {
        call_trace_target();
        sleep(1);
    }
}
