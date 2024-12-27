/**
 * User program for loading a single generic program and attaching
 * Usage: ./load.user bpf_file bpf_prog_name
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Not enough args\n");
        printf("Expected: ./load.user bpf_file bpf_prog_name\n");
        return -1;
    }

    char * bpf_path = argv[1];
    char * prog_name = argv[2];

    // Open the shared1.kern object
    struct bpf_object * prog = bpf_object__open(bpf_path);
    
    // Try and load this program
    // This should make the map we need
    if (bpf_object__load(prog)) {
        printf("Failed");
        return 0;
    }

    struct bpf_program * program = bpf_object__find_program_by_name(prog, prog_name);

    if (program == NULL) {
        printf("Shared 1 failed\n");
        return 0;
    }

    printf("PID: %d\n", getpid());

    getchar();

    bpf_program__attach(program);

    return 0;
}
