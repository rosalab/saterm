#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Simple user program that loads BPF program and keeps it attached */

static volatile bool keep_running = true;

void signal_handler(int signo) {
    keep_running = false;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_program.o>\n", argv[0]);
        return 1;
    }

    char *bpf_program = argv[1];
    struct bpf_link *link = NULL;
    struct bpf_program *prog;
    struct bpf_object *obj;
    
    /* Setup signal handler for clean exit */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Open BPF object file */
    obj = bpf_object__open_file(bpf_program, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed: %s\n", 
                strerror(libbpf_get_error(obj)));
        return 1;
    }

    /* Find the program by name */
    prog = bpf_object__find_program_by_name(obj, "trace_saterm_exit");
    if (!prog) {
        fprintf(stderr, "ERROR: finding prog in obj file failed\n");
        goto cleanup;
    }
//rm -rf /sys/fs/bpf/throw_prog && bpftool -d prog load termination_latency_test_throw.kern.o /sys/fs/bpf/throw_prog
    // set debug level to print verbose logs in verifier
    // bpf_program__set_log_level(prog, 2);

    // char log_buf[1024];
    // bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));

    /* Load the BPF program into the kernel */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    /* Get map FDs for reporting */
    int control_map_fd = bpf_object__find_map_fd_by_name(obj, "control_map");
    int counter_map_fd = bpf_object__find_map_fd_by_name(obj, "counter_map");
    
    /* Attach the program to the tracepoint */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_program__attach failed: %ld\n", 
                libbpf_get_error(link));
        link = NULL;
        goto cleanup;
    }

    /* Print program and map IDs for the Python script */
    int prog_fd = bpf_program__fd(prog);
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
        printf("PROG_ID=%u\n", info.id);
    }
    
    if (control_map_fd >= 0) {
        struct bpf_map_info map_info = {};
        __u32 map_info_len = sizeof(map_info);
        if (bpf_obj_get_info_by_fd(control_map_fd, &map_info, &map_info_len) == 0) {
            printf("CONTROL_MAP_ID=%u\n", map_info.id);
        }
    }
    
    if (counter_map_fd >= 0) {
        struct bpf_map_info map_info = {};
        __u32 map_info_len = sizeof(map_info);
        if (bpf_obj_get_info_by_fd(counter_map_fd, &map_info, &map_info_len) == 0) {
            printf("COUNTER_MAP_ID=%u\n", map_info.id);
        }
    }
    
    printf("READY\n");
    fflush(stdout);

    /* Keep running until signaled */
    while (keep_running) {
        sleep(1);
    }

    printf("Shutting down...\n");

cleanup:
    // printf("Verifier log: %s\n", log_buf);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}

