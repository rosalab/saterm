// Map iterator benchmark - measures BPF map iteration performance
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <regex.h>

#define __NR_saterm_test 470
#define MAX_ELEMS 10000
#define NUM_SYSCALLS 1000

typedef struct {
    unsigned long run_time_ns;
    unsigned long run_cnt;
} bpf_stats_t;

typedef struct {
    unsigned long long map_iter_ns;
    unsigned long long fill_loop_ns;
} timing_stats_t;

static void die(const char *msg, int err) {
    fprintf(stderr, "%s: %s (%d)\n", msg, strerror(err > 0 ? err : -err), err);
    exit(1);
}

// Enable BPF statistics collection
static int enable_bpf_stats(void) {
    FILE *f = fopen("/proc/sys/kernel/bpf_stats_enabled", "w");
    if (!f) {
        perror("Failed to open bpf_stats_enabled");
        return -1;
    }
    fprintf(f, "1\n");
    fclose(f);
    printf("✓ BPF stats enabled\n");
    return 0;
}

// Read BPF program statistics (similar to execution_time_benchmark.py)
static int read_bpf_stats(int prog_id, bpf_stats_t *stats) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bpftool prog show id %d", prog_id);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Failed to execute bpftool\n");
        return -1;
    }
    
    // Read entire output into buffer
    char output[4096] = {0};
    size_t total = 0;
    char line[1024];
    
    while (fgets(line, sizeof(line), fp) && total < sizeof(output) - 1) {
        size_t len = strlen(line);
        if (total + len < sizeof(output) - 1) {
            strcat(output, line);
            total += len;
        }
    }
    
    pclose(fp);
    
    // Parse output using regex-like pattern matching
    // Example: "41: tracepoint  name iterate_over_map  tag xxx  run_time_ns 35875602162 run_cnt 160512637"
    int found_run_time = 0, found_run_cnt = 0;
    
    char *run_time_pos = strstr(output, "run_time_ns");
    if (run_time_pos) {
        if (sscanf(run_time_pos, "run_time_ns %lu", &stats->run_time_ns) == 1) {
            found_run_time = 1;
        }
    }
    
    char *run_cnt_pos = strstr(output, "run_cnt");
    if (run_cnt_pos) {
        if (sscanf(run_cnt_pos, "run_cnt %lu", &stats->run_cnt) == 1) {
            found_run_cnt = 1;
        }
    }
    
    if (!found_run_time || !found_run_cnt) {
        // Stats might be 0 if program hasn't run yet - that's okay, just set to 0
        if (!found_run_time) {
            stats->run_time_ns = 0;
        }
        if (!found_run_cnt) {
            stats->run_cnt = 0;
        }
    }
    
    return 0;
}

// Populate array map with n elements
static int populate_array(int map_fd, unsigned int n) {
    if (n > MAX_ELEMS) {
        fprintf(stderr, "n=%u exceeds MAX_ELEMS=%d\n", n, MAX_ELEMS);
        return -1;
    }
    
    for (unsigned int i = 0; i < n; i++) {
        unsigned int key = i;
        unsigned int value = i;  // Just use index as value
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update map at key %u: %s\n", i, strerror(errno));
            return -1;
        }
    }
    
    return 0;
}

// Trigger the syscall multiple times
static void trigger_syscalls(int count) {
    for (int i = 0; i < count; i++) {
        syscall(__NR_saterm_test);
    }
}

// Run benchmark for a specific value of n
static int run_benchmark_for_n(int prog_id, int ar_fd, int timing_fd, int control_fd, 
                                unsigned int n, FILE *csv) {
    unsigned int key = 0;
    timing_stats_t timing_values;
    bpf_stats_t initial_stats, final_stats;
    
    printf("\n[n=%u] Starting benchmark...\n", n);
    
    // Step 1: Populate array map with n elements
    printf("  Populating array with %u elements...\n", n);
    if (populate_array(ar_fd, n) != 0) {
        fprintf(stderr, "Failed to populate array\n");
        return -1;
    }
    
    // Step 2: Write n to control_map
    if (bpf_map_update_elem(control_fd, &key, &n, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update control_map: %s\n", strerror(errno));
        return -1;
    }
    
    // Step 3: Reset timing_map to 0
    memset(&timing_values, 0, sizeof(timing_values));
    if (bpf_map_update_elem(timing_fd, &key, &timing_values, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to reset timing_map: %s\n", strerror(errno));
        return -1;
    }
    
    // Step 4: Read initial bpftool stats
    if (read_bpf_stats(prog_id, &initial_stats) != 0) {
        fprintf(stderr, "Failed to read initial stats\n");
        return -1;
    }
    printf("  Initial: run_cnt=%lu, run_time_ns=%lu\n", 
           initial_stats.run_cnt, initial_stats.run_time_ns);
    
    // Step 5: Trigger syscall NUM_SYSCALLS times
    printf("  Triggering %d syscalls...\n", NUM_SYSCALLS);
    trigger_syscalls(NUM_SYSCALLS);
    
    // Step 6: Read final bpftool stats
    if (read_bpf_stats(prog_id, &final_stats) != 0) {
        fprintf(stderr, "Failed to read final stats\n");
        return -1;
    }
    printf("  Final: run_cnt=%lu, run_time_ns=%lu\n", 
           final_stats.run_cnt, final_stats.run_time_ns);
    
    // Step 7: Read timing_map for cumulative helper time
    if (bpf_map_lookup_elem(timing_fd, &key, &timing_values) != 0) {
        fprintf(stderr, "Failed to read timing_map: %s\n", strerror(errno));
        return -1;
    }
    
    // Step 8: Calculate averages
    unsigned long delta_run_cnt = final_stats.run_cnt - initial_stats.run_cnt;
    unsigned long delta_run_time = final_stats.run_time_ns - initial_stats.run_time_ns;
    
    if (delta_run_cnt == 0) {
        fprintf(stderr, "No BPF invocations detected!\n");
        return -1;
    }
    
    double avg_bpftool_total_ns = (double)delta_run_time / (double)delta_run_cnt;
    double avg_map_iter_ns = (double)timing_values.map_iter_ns / (double)delta_run_cnt;
    double avg_fill_loop_ns = (double)timing_values.fill_loop_ns / (double)delta_run_cnt;
    double avg_component_total_ns = avg_map_iter_ns + avg_fill_loop_ns; // desired total = loop + helper
    double map_iter_pct = (avg_component_total_ns > 0) ? (avg_map_iter_ns / avg_component_total_ns) * 100.0 : 0.0;
    double fill_loop_pct = (avg_component_total_ns > 0) ? (avg_fill_loop_ns / avg_component_total_ns) * 100.0 : 0.0;
    
    printf("  Results:\n");
    printf("    Invocations: %lu\n", delta_run_cnt);
    printf("    Avg component total (map+loop): %.2f ns\n", avg_component_total_ns);
    printf("    Avg map-iterator time: %.2f ns (%.1f%% of component)\n", avg_map_iter_ns, map_iter_pct);
    printf("    Avg fill-loop time: %.2f ns (%.1f%% of component)\n", avg_fill_loop_ns, fill_loop_pct);
    printf("    Avg bpftool total (reference): %.2f ns\n", avg_bpftool_total_ns);
    
    // Step 9: Write to CSV
    fprintf(csv, "%u,%.2f,%.2f,%.2f,%.1f,%.1f,%.2f,%lu\n",
            n, avg_component_total_ns, avg_map_iter_ns, avg_fill_loop_ns,
            map_iter_pct, fill_loop_pct, avg_bpftool_total_ns, delta_run_cnt);
    fflush(csv);
    
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_map *ar_map = NULL, *timing_map = NULL, *control_map = NULL;
    int ar_fd, timing_fd, control_fd, prog_fd, prog_id;
    FILE *csv = NULL;
    int err;

    printf("=======================================================\n");
    printf("BPF Map Iterator Performance Benchmark\n");
    printf("=======================================================\n\n");

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root\n");
        return 1;
    }

    // Enable BPF stats
    if (enable_bpf_stats() != 0) {
        return 1;
    }

    // Load BPF object
    printf("Loading BPF program...\n");
    obj = bpf_object__open_file("map_iterator.kern.o", NULL);
    if (!obj) {
        die("bpf_object__open_file failed", errno);
    }

    err = bpf_object__load(obj);
    if (err) {
        die("bpf_object__load failed", err);
    }
    printf("✓ BPF program loaded\n");

    // Find maps
    ar_map = bpf_object__find_map_by_name(obj, "ar");
    if (!ar_map) die("can't find map 'ar'", ENOENT);
    
    timing_map = bpf_object__find_map_by_name(obj, "timing_map");
    if (!timing_map) die("can't find map 'timing_map'", ENOENT);
    
    control_map = bpf_object__find_map_by_name(obj, "control_map");
    if (!control_map) die("can't find map 'control_map'", ENOENT);
    
    ar_fd = bpf_map__fd(ar_map);
    timing_fd = bpf_map__fd(timing_map);
    control_fd = bpf_map__fd(control_map);
    
    printf("✓ Found maps: ar, timing_map, control_map\n");

    // Find and attach program
    prog = bpf_object__find_program_by_name(obj, "iterate_over_map");
    if (!prog) die("can't find program 'iterate_over_map'", ENOENT);
    
    link = bpf_program__attach(prog);
    err = libbpf_get_error(link);
    if (err) die("attach tracepoint failed", err);
    
    prog_fd = bpf_program__fd(prog);
    
    // Get program ID
    struct bpf_prog_info info = {};
    unsigned int info_len = sizeof(info);
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err) die("bpf_obj_get_info_by_fd failed", errno);
    
    prog_id = info.id;
    printf("✓ Attached to tracepoint, prog_id=%d\n", prog_id);

    // Warm-up: trigger a few syscalls to ensure BPF stats are initialized
    printf("Warming up (triggering test syscalls to initialize stats)...\n");
    unsigned int warmup_n = 10;
    unsigned int key = 0;
    
    // Set control_map to a small value for warmup
    control_fd = bpf_map__fd(control_map);
    if (bpf_map_update_elem(control_fd, &key, &warmup_n, BPF_ANY) != 0) {
        fprintf(stderr, "Warning: Failed to set control_map for warmup\n");
    }
    
    // Trigger a few syscalls
    trigger_syscalls(10);
    usleep(100000); // Wait 100ms for stats to update
    printf("✓ Warmup complete\n");

    // Open CSV file in current working directory
    csv = fopen("map_iterator_results.csv", "w");
    if (!csv) {
        perror("Failed to open map_iterator_results.csv");
        goto cleanup;
    }
    fprintf(csv, "n,avg_component_total_ns,avg_map_iter_ns,avg_fill_loop_ns,map_iter_pct_component,fill_loop_pct_component,avg_bpftool_total_ns,invocations\n");

    printf("\n=======================================================\n");
    printf("Running benchmarks\n");
    printf("=======================================================\n");
    
    for (unsigned int n = 0; n <= 1000; n += 10) {
        if (run_benchmark_for_n(prog_id, ar_fd, timing_fd, control_fd, n, csv) != 0) {
            fprintf(stderr, "Benchmark failed for n=%u\n", n);
            goto cleanup;
        }
    }

    printf("\n=======================================================\n");
    printf("Benchmark completed successfully!\n");
    printf("Results saved to map_iterator_results.csv\n");
    printf("=======================================================\n");

cleanup:
    if (csv) fclose(csv);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    
    return 0;
}
