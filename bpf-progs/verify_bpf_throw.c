// Test program to verify bpf_throw works correctly
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/syscall.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int prog_fd, control_fd, counter_fd;
    __u32 key = 0;
    __u64 value = 0;
    int err = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_program.o>\n", argv[0]);
        fprintf(stderr, "Example: %s termination_latency_test_throw.kern.o\n", argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    printf("=== BPF_THROW Verification Test ===\n\n");
    printf("Step 1: Loading BPF program: %s\n", argv[1]);
    
    /* Open and load BPF object */
    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: Failed to open BPF object: %s\n", 
                strerror(-libbpf_get_error(obj)));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF object: %s\n", strerror(-err));
        fprintf(stderr, "\n*** This likely means your kernel doesn't support bpf_throw ***\n");
        fprintf(stderr, "    Check if you're running the bpf_throw branch kernel\n");
        goto cleanup;
    }

    printf("✓ BPF program loaded successfully!\n");
    printf("  (This means bpf_throw kfunc was resolved by the kernel)\n\n");

    /* Find the program */
    prog = bpf_object__find_program_by_name(obj, "trace_saterm_exit");
    if (!prog) {
        fprintf(stderr, "ERROR: Could not find program 'trace_saterm_exit'\n");
        goto cleanup;
    }

    prog_fd = bpf_program__fd(prog);
    printf("Step 2: Program FD: %d\n", prog_fd);

    /* Get map FDs */
    control_fd = bpf_object__find_map_fd_by_name(obj, "control_map");
    counter_fd = bpf_object__find_map_fd_by_name(obj, "counter_map");
    
    if (control_fd < 0 || counter_fd < 0) {
        fprintf(stderr, "ERROR: Could not find maps\n");
        goto cleanup;
    }

    printf("✓ Control map FD: %d\n", control_fd);
    printf("✓ Counter map FD: %d\n\n", counter_fd);

    /* Attach the program */
    printf("Step 3: Attaching program to tracepoint...\n");
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Failed to attach program: %ld\n", 
                libbpf_get_error(link));
        link = NULL;
        goto cleanup;
    }

    printf("✓ Program attached successfully\n\n");

    /* Test 1: Run without trigger */
    printf("Step 4: Testing WITHOUT bpf_throw trigger...\n");
    value = 0;
    bpf_map_update_elem(control_fd, &key, &value, BPF_ANY);
    
    /* Trigger the syscall a few times */
    for (int i = 0; i < 5; i++) {
        syscall(470); // saterm_test syscall
        usleep(10000);
    }
    
    /* Read counter */
    __u64 counter_before = 0;
    bpf_map_lookup_elem(counter_fd, &key, &counter_before);
    printf("  Counter value: %llu\n", counter_before);
    
    if (counter_before > 0) {
        printf("✓ Program is executing on syscall\n\n");
    } else {
        printf("⚠ Program might not be triggering (counter=0)\n");
        printf("  This could mean:\n");
        printf("  - The saterm_test syscall (470) is not available\n");
        printf("  - The tracepoint is not being hit\n\n");
    }

    /* Test 2: Run WITH bpf_throw trigger */
    printf("Step 5: Testing WITH bpf_throw trigger...\n");
    value = 1; // Enable bpf_throw
    bpf_map_update_elem(control_fd, &key, &value, BPF_ANY);
    
    printf("  Triggering syscall with bpf_throw enabled...\n");
    for (int i = 0; i < 3; i++) {
        int ret = syscall(470);
        printf("  syscall returned: %d (errno: %d - %s)\n", ret, errno, strerror(errno));
        usleep(10000);
    }
    
    /* Read counter again */
    __u64 counter_after = 0;
    bpf_map_lookup_elem(counter_fd, &key, &counter_after);
    printf("  Counter value: %llu\n", counter_after);
    
    if (counter_after > counter_before) {
        printf("✓ bpf_throw was triggered! Counter increased from %llu to %llu\n", 
               counter_before, counter_after);
        printf("  The program ran and hit bpf_throw(0)\n");
    } else {
        printf("⚠ Counter didn't increase - bpf_throw path may not have executed\n");
    }

    printf("\n=== Verification Complete ===\n");
    printf("\nTo see kernel logs (bpf_printk output):\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("\nTo check bpf_throw in action:\n");
    printf("  sudo bpftool prog tracelog\n");

    err = 0;

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    
    return err;
}

