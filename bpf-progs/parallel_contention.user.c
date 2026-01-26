// Parallel BPF Contention Test
// Spawns threads pinned to each CPU, all triggering the same BPF program
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define __NR_saterm_test 470
#define TEST_DURATION_SEC 5

// Large value to match BPF side
#define VALUE_SIZE 256
struct large_value {
    __u64 counter;
    char padding[VALUE_SIZE - sizeof(__u64)];
};

static volatile int running = 0;
static int counter_map_fd = -1;

typedef struct {
    int cpu_id;
    unsigned long syscall_count;
} thread_data_t;

static void die(const char *msg, int err) {
    fprintf(stderr, "%s: %s (%d)\n", msg, strerror(err > 0 ? err : -err), err);
    exit(1);
}

// Thread function - pinned to specific CPU, calls syscall in tight loop
static void *worker_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    cpu_set_t cpuset;
    
    // Pin to specific CPU
    CPU_ZERO(&cpuset);
    CPU_SET(data->cpu_id, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        fprintf(stderr, "Warning: Failed to pin thread to CPU %d\n", data->cpu_id);
    }
    
    data->syscall_count = 0;
    
    while (running) {
        syscall(__NR_saterm_test);
        data->syscall_count++;
    }
    
    return NULL;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int timing_fd, invocation_fd, failure_fd;
    int num_cpus, num_threads;
    pthread_t *threads = NULL;
    thread_data_t *thread_data = NULL;
    
    printf("=======================================================\n");
    printf("Parallel BPF Contention Test\n");
    printf("=======================================================\n\n");
    
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root\n");
        return 1;
    }
    
    // Get number of CPUs
    num_cpus = get_nprocs();
    printf("Detected %d CPUs\n", num_cpus);
    
    // Use all CPUs or use specified count
    num_threads = num_cpus;
    if (argc > 1) {
        num_threads = atoi(argv[1]);
        if (num_threads <= 0) {
            num_threads = num_cpus;
        }
        // Allow up to 10000 threads (no artificial limit)
        if (num_threads > 10000) {
            num_threads = 10000;
        }
    }
    printf("Will spawn %d threads (on %d CPUs)\n", num_threads, num_cpus);
    
    // Load BPF program
    printf("\nLoading BPF program...\n");
    obj = bpf_object__open_file("contention_lock.kern.o", NULL);
    if (!obj) die("Failed to open BPF object", errno);
    
    if (bpf_object__load(obj)) die("Failed to load BPF object", errno);
    printf("✓ BPF program loaded\n");
    
    // Get maps
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "counter_map");
    if (!map) die("Failed to find counter_map", ENOENT);
    counter_map_fd = bpf_map__fd(map);
    
    map = bpf_object__find_map_by_name(obj, "timing_map");
    if (!map) die("Failed to find timing_map", ENOENT);
    timing_fd = bpf_map__fd(map);
    
    map = bpf_object__find_map_by_name(obj, "invocation_map");
    if (!map) die("Failed to find invocation_map", ENOENT);
    invocation_fd = bpf_map__fd(map);
    
    map = bpf_object__find_map_by_name(obj, "failure_map");
    if (!map) die("Failed to find failure_map", ENOENT);
    failure_fd = bpf_map__fd(map);
    
    // Attach program
    prog = bpf_object__find_program_by_name(obj, "write_counter");
    if (!prog) die("Failed to find program", ENOENT);
    
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) die("Failed to attach", libbpf_get_error(link));
    printf("✓ Attached to tracepoint\n");
    
    // Initialize counter_map with a value
    __u32 key = 0;
    struct large_value init_val = { .counter = 0 };
    bpf_map_update_elem(counter_map_fd, &key, &init_val, BPF_ANY);
    
    // Allocate threads
    threads = calloc(num_threads, sizeof(pthread_t));
    thread_data = calloc(num_threads, sizeof(thread_data_t));
    if (!threads || !thread_data) die("calloc failed", ENOMEM);
    
    // Reset maps
    __u64 zero = 0;
    bpf_map_update_elem(timing_fd, &key, &zero, BPF_ANY);
    bpf_map_update_elem(invocation_fd, &key, &zero, BPF_ANY);
    bpf_map_update_elem(failure_fd, &key, &zero, BPF_ANY);
    
    printf("\n=======================================================\n");
    printf("Starting %d threads for %d seconds...\n", num_threads, TEST_DURATION_SEC);
    printf("=======================================================\n\n");
    
    // Start threads
    running = 1;
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].cpu_id = i % num_cpus;  // Distribute across CPUs
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
        }
    }
    
    // Wait
    sleep(TEST_DURATION_SEC);
    
    // Stop threads
    running = 0;
    printf("Stopping threads...\n");
    
    unsigned long total_syscalls = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        total_syscalls += thread_data[i].syscall_count;
    }
    
    // Read results
    __u64 timing_value = 0, invocation_value = 0, failure_value = 0;
    bpf_map_lookup_elem(timing_fd, &key, &timing_value);
    bpf_map_lookup_elem(invocation_fd, &key, &invocation_value);
    bpf_map_lookup_elem(failure_fd, &key, &failure_value);
    
    // Calculate
    double avg_helper_ns = invocation_value > 0 ? (double)timing_value / invocation_value : 0;
    double avg_helper_ms = avg_helper_ns / 1000000.0;
    
    printf("\n=======================================================\n");
    printf("RESULTS\n");
    printf("=======================================================\n");
    printf("Threads:              %d\n", num_threads);
    printf("Total syscalls:       %lu\n", total_syscalls);
    printf("BPF invocations:      %llu\n", (unsigned long long)invocation_value);
    printf("Lock failures:        %llu\n", (unsigned long long)failure_value);
    printf("Avg helper time:      %.2f ns (%.6f ms)\n", avg_helper_ns, avg_helper_ms);
    printf("=======================================================\n");
    
    if (failure_value > 0) {
        printf("\n*** TIMEOUTS DETECTED! ***\n");
    } else if (avg_helper_ms > 100) {
        printf("\n*** Helper time approaching timeout threshold! ***\n");
    } else {
        printf("\nNo timeouts. Helper time is %.2f ns.\n", avg_helper_ns);
        printf("(Need ~250,000,000 ns = 250ms to trigger timeout)\n");
    }
    
    // Cleanup
    free(threads);
    free(thread_data);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    
    return 0;
}

