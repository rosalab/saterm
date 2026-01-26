// BPF Timeout Demonstration - Userspace
// Demonstrates rqspinlock timeout by increasing lock hold time until waiters timeout
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define __NR_saterm_test 470

struct results {
    __u64 success_count;
    __u64 timeout_count;
    __u64 total_wait_ns;
    __u64 max_wait_ns;
};

static volatile int running = 0;

static void die(const char *msg, int err) {
    fprintf(stderr, "%s: %s (%d)\n", msg, strerror(err > 0 ? err : -err), err);
    exit(1);
}

// Thread that triggers lock_holder (sys_enter_saterm_test)
static void *holder_thread(void *arg) {
    while (running) {
        syscall(__NR_saterm_test);
        usleep(1000); // Small delay between acquisitions
    }
    return NULL;
}

// Thread that triggers lock_waiter (sys_exit_saterm_test) 
// The waiter is triggered by sys_exit, so same syscall triggers both
static void *waiter_thread(void *arg) {
    while (running) {
        syscall(__NR_saterm_test);
        usleep(500); // Try more frequently than holder
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *holder_prog, *waiter_prog;
    struct bpf_link *holder_link = NULL, *waiter_link = NULL;
    int hold_iter_fd, results_fd;
    int err;
    
    printf("=======================================================\n");
    printf("BPF Resilient Spinlock Timeout Demonstration\n");
    printf("=======================================================\n\n");
    
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root\n");
        return 1;
    }
    
    // Load BPF object
    printf("Loading BPF program...\n");
    obj = bpf_object__open_file("timeout_demo.kern.o", NULL);
    if (!obj) {
        die("Failed to open BPF object", errno);
    }
    
    err = bpf_object__load(obj);
    if (err) {
        die("Failed to load BPF object", err);
    }
    printf("✓ BPF program loaded\n");
    
    // Get map FDs
    struct bpf_map *map;
    
    map = bpf_object__find_map_by_name(obj, "hold_iterations_map");
    if (!map) die("Failed to find hold_iterations_map", ENOENT);
    hold_iter_fd = bpf_map__fd(map);
    
    map = bpf_object__find_map_by_name(obj, "results_map");
    if (!map) die("Failed to find results_map", ENOENT);
    results_fd = bpf_map__fd(map);
    
    printf("✓ Found all maps\n");
    
    // Attach programs
    holder_prog = bpf_object__find_program_by_name(obj, "lock_holder");
    if (!holder_prog) die("Failed to find lock_holder program", ENOENT);
    
    waiter_prog = bpf_object__find_program_by_name(obj, "lock_waiter");
    if (!waiter_prog) die("Failed to find lock_waiter program", ENOENT);
    
    holder_link = bpf_program__attach(holder_prog);
    if (libbpf_get_error(holder_link)) {
        die("Failed to attach lock_holder", libbpf_get_error(holder_link));
    }
    
    waiter_link = bpf_program__attach(waiter_prog);
    if (libbpf_get_error(waiter_link)) {
        die("Failed to attach lock_waiter", libbpf_get_error(waiter_link));
    }
    
    printf("✓ Attached both programs\n\n");
    
    // Test with increasing hold iterations
    printf("Testing with increasing lock hold times...\n");
    printf("(Looking for timeouts when hold time exceeds 250ms)\n\n");
    
    // Iteration counts to test (each iteration is ~few nanoseconds)
    // 250ms = 250,000,000 ns
    // At ~5ns per iteration, need ~50,000,000 iterations for 250ms
    __u64 test_iterations[] = {
        1000000,      // ~5ms
        5000000,      // ~25ms  
        10000000,     // ~50ms
        25000000,     // ~125ms
        50000000,     // ~250ms - should start seeing timeouts!
        75000000,     // ~375ms
        100000000,    // ~500ms
    };
    int num_tests = sizeof(test_iterations) / sizeof(test_iterations[0]);
    
    printf("%-15s %-12s %-12s %-15s %-15s\n", 
           "Iterations", "Successes", "Timeouts", "Avg Wait (ms)", "Max Wait (ms)");
    printf("─────────────────────────────────────────────────────────────────────\n");
    
    for (int t = 0; t < num_tests; t++) {
        __u32 key = 0;
        __u64 iterations = test_iterations[t];
        struct results zero_results = {};
        struct results final_results;
        
        // Set hold iterations
        bpf_map_update_elem(hold_iter_fd, &key, &iterations, BPF_ANY);
        
        // Reset results
        bpf_map_update_elem(results_fd, &key, &zero_results, BPF_ANY);
        
        // Start threads
        pthread_t holder, waiter1, waiter2;
        running = 1;
        
        pthread_create(&holder, NULL, holder_thread, NULL);
        pthread_create(&waiter1, NULL, waiter_thread, NULL);
        pthread_create(&waiter2, NULL, waiter_thread, NULL);
        
        // Run for 3 seconds per test
        sleep(3);
        
        running = 0;
        pthread_join(holder, NULL);
        pthread_join(waiter1, NULL);
        pthread_join(waiter2, NULL);
        
        // Read results
        bpf_map_lookup_elem(results_fd, &key, &final_results);
        
        __u64 total_ops = final_results.success_count + final_results.timeout_count;
        double avg_wait_ms = total_ops > 0 ? 
            (double)final_results.total_wait_ns / total_ops / 1000000.0 : 0;
        double max_wait_ms = (double)final_results.max_wait_ns / 1000000.0;
        
        printf("%-15llu %-12llu %-12llu %-15.2f %-15.2f",
               (unsigned long long)iterations,
               (unsigned long long)final_results.success_count,
               (unsigned long long)final_results.timeout_count,
               avg_wait_ms,
               max_wait_ms);
        
        if (final_results.timeout_count > 0) {
            printf(" ← TIMEOUTS DETECTED!");
        }
        printf("\n");
        
        // If we're seeing lots of timeouts, we've demonstrated the behavior
        if (final_results.timeout_count > 10) {
            printf("\n✓ Successfully demonstrated rqspinlock timeout behavior!\n");
            break;
        }
    }
    
    printf("\n=======================================================\n");
    printf("Demonstration complete!\n");
    printf("=======================================================\n");
    
    // Cleanup
    if (holder_link) bpf_link__destroy(holder_link);
    if (waiter_link) bpf_link__destroy(waiter_link);
    if (obj) bpf_object__close(obj);
    
    return 0;
}

