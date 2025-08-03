#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

void function_to_trace() {
    struct stat st;

    if (stat(".", &st) == 0) {
        printf("stat syscall succeeded. inode: %lu\n", st.st_ino);
    } else {
        perror("stat syscall failed");
    }

    sleep(10);
}

void loop() {
    while (1) {
        function_to_trace();
    }
}

int main() {
    loop();
    return 0;
}