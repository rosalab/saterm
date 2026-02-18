// BPF Contention Benchmark - User Program
// BPF writes to map, userspace threads read from map
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define __NR_saterm_test 470
#define TEST_DURATION_SEC 120

typedef struct {
    unsigned long long update_ns;
    unsigned long long fill_loop_ns;
} contention_timing_t;

typedef struct {
    unsigned long run_time_ns;
    unsigned long run_cnt;
} bpf_stats_t;

static volatile int running = 0;
static int g_counter_fd = -1;
static int g_timing_fd = -1;
static int g_invocation_fd = -1;
static int g_prog_id = -1;
static int g_num_cpus = 0;
// Read and zero helpers for per-CPU maps
static int reset_percpu_timing_map(int fd) {
    __u32 key = 0;
    contention_timing_t *zeros = calloc(g_num_cpus, sizeof(*zeros));
    if (!zeros)
        return -1;
    int ret = bpf_map_update_elem(fd, &key, zeros, BPF_ANY);
    free(zeros);
    return ret;
}

static int reset_percpu_u64_map(int fd) {
    __u32 key = 0;
    __u64 *zeros = calloc(g_num_cpus, sizeof(__u64));
    if (!zeros)
        return -1;
    int ret = bpf_map_update_elem(fd, &key, zeros, BPF_ANY);
    free(zeros);
    return ret;
}

static __u64 read_percpu_u64_sum(int fd) {
    __u32 key = 0;
    __u64 sum = 0;
    __u64 *values = calloc(g_num_cpus, sizeof(__u64));
    if (!values)
        return 0;
    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (int i = 0; i < g_num_cpus; i++) {
            sum += values[i];
        }
    }
    free(values);
    return sum;
}

static contention_timing_t read_percpu_timing_sum(int fd) {
    __u32 key = 0;
    contention_timing_t total = {};
    contention_timing_t *values = calloc(g_num_cpus, sizeof(*values));
    if (!values)
        return total;
    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (int i = 0; i < g_num_cpus; i++) {
            total.update_ns += values[i].update_ns;
            total.fill_loop_ns += values[i].fill_loop_ns;
        }
    }
    free(values);
    return total;
}

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

// Read BPF program statistics
static int read_bpf_stats(int prog_id, bpf_stats_t *stats) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bpftool prog show id %d", prog_id);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Failed to execute bpftool\n");
        return -1;
    }
    
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
    
    if (!found_run_time) stats->run_time_ns = 0;
    if (!found_run_cnt) stats->run_cnt = 0;
    
    return 0;
}

// Thread that triggers syscall 470 (BPF writes)
static void *writer_thread(void *arg) {
    while (running) {
        syscall(__NR_saterm_test);
    }
    return NULL;
}

// Thread that updates map (creates contention with BPF writes)
static void *reader_thread(void *arg) {
    __u32 key = 0;
    __u64 value = 0;
    
    while (running) {
        // Use bpf_map_update_elem to take the map's spinlock and create contention
        bpf_map_update_elem(g_counter_fd, &key, &value, BPF_ANY);
    }
    return NULL;
}

// Run benchmark with N reader threads
static int run_benchmark(int num_readers, FILE *csv) {
    pthread_t writer;
    pthread_t *readers;
    __u32 key = 0;
    contention_timing_t start_timing = {};
    contention_timing_t end_timing = {};
    __u64 start_invocations = 0, end_invocations = 0;
    bpf_stats_t initial_stats, final_stats;
    
    printf("\n[num_readers=%d] Starting benchmark...\n", num_readers);
    
    // Allocate reader thread array
    readers = calloc(num_readers, sizeof(pthread_t));
    if (!readers) {
        perror("calloc");
        return -1;
    }
    
    // Reset maps
    __u64 zero = 0;
    contention_timing_t zero_timing = {};
    bpf_map_update_elem(g_counter_fd, &key, &zero, BPF_ANY);
    reset_percpu_timing_map(g_timing_fd);
    reset_percpu_u64_map(g_invocation_fd);
    
    // Read initial BPF stats
    read_bpf_stats(g_prog_id, &initial_stats);
    
    // Start threads
    running = 1;
    
    // Start single writer thread (triggers BPF)
    if (pthread_create(&writer, NULL, writer_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create writer thread\n");
        free(readers);
        return -1;
    }
    
    // Start reader threads
    printf("  Starting %d reader threads...\n", num_readers);
    for (int i = 0; i < num_readers; i++) {
        if (pthread_create(&readers[i], NULL, reader_thread, NULL) != 0) {
            fprintf(stderr, "Failed to create reader thread %d\n", i);
            running = 0;
            pthread_join(writer, NULL);
            for (int j = 0; j < i; j++) {
                pthread_join(readers[j], NULL);
            }
            free(readers);
            return -1;
        }
    }
    
    // Read start values from maps
    start_timing = read_percpu_timing_sum(g_timing_fd);
    start_invocations = read_percpu_u64_sum(g_invocation_fd);
    
    // Let it run
    printf("  Running for %d seconds...\n", TEST_DURATION_SEC);
    sleep(TEST_DURATION_SEC);
    
    // Read end values
    end_timing = read_percpu_timing_sum(g_timing_fd);
    end_invocations = read_percpu_u64_sum(g_invocation_fd);
    
    // Read final BPF stats
    read_bpf_stats(g_prog_id, &final_stats);
    
    // Stop threads
    running = 0;
    printf("  Stopping threads...\n");
    pthread_join(writer, NULL);
    for (int i = 0; i < num_readers; i++) {
        pthread_join(readers[i], NULL);
    }
    free(readers);
    
    // Calculate results
    __u64 total_update_timing = end_timing.update_ns - start_timing.update_ns;
    __u64 total_fill_timing = end_timing.fill_loop_ns - start_timing.fill_loop_ns;
    __u64 invocations = end_invocations - start_invocations;
    unsigned long delta_run_cnt = final_stats.run_cnt - initial_stats.run_cnt;
    unsigned long delta_run_time = final_stats.run_time_ns - initial_stats.run_time_ns;
    
    double avg_update_time_ns = invocations > 0 ? (double)total_update_timing / invocations : 0;
    double avg_fill_loop_ns = invocations > 0 ? (double)total_fill_timing / invocations : 0;
    double avg_component_total_ns = avg_update_time_ns + avg_fill_loop_ns;
    double avg_total_bpf_ns = delta_run_cnt > 0 ? (double)delta_run_time / delta_run_cnt : 0;
    double lookup_overhead_pct = avg_total_bpf_ns > 0 ? (avg_update_time_ns / avg_total_bpf_ns) * 100.0 : 0;
    double update_pct = avg_component_total_ns > 0 ? (avg_update_time_ns / avg_component_total_ns) * 100.0 : 0;
    double fill_pct = avg_component_total_ns > 0 ? (avg_fill_loop_ns / avg_component_total_ns) * 100.0 : 0;
    
    printf("  Results:\n");
    printf("    Invocations: %llu\n", (unsigned long long)invocations);
    printf("    Avg total BPF time: %.2f ns\n", avg_total_bpf_ns);
    printf("    Avg helper time: %.2f ns (%.1f%% of helper+loop)\n", avg_update_time_ns, update_pct);
    printf("    Avg fill-loop time: %.2f ns (%.1f%% of helper+loop)\n", avg_fill_loop_ns, fill_pct);
    printf("    Helper overhead vs bpftool: %.1f%%\n", lookup_overhead_pct);
    
    // Write to CSV
    fprintf(csv, "%d,%.2f,%.2f,%.2f,%.1f,%.1f,%.1f,%lu\n", 
            num_readers, avg_total_bpf_ns, avg_update_time_ns, avg_fill_loop_ns,
            update_pct, fill_pct, lookup_overhead_pct, delta_run_cnt);
    fflush(csv);
    
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_map *map = NULL;
    FILE *csv = NULL;
    int err, ret = 0;
    
    g_num_cpus = get_nprocs();
    
    printf("=======================================================\n");
    printf("BPF Contention Benchmark\n");
    printf("=======================================================\n\n");
    
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root\n");
        return 1;
    }
    
    // Enable BPF stats
    if (enable_bpf_stats() != 0) {
        return 1;
    }
    
    // Load BPF object
    printf("Loading BPF program...\n");
    obj = bpf_object__open_file("contention_lock.kern.o", NULL);
    if (!obj) {
        die("Failed to open BPF object", errno);
    }
    
    err = bpf_object__load(obj);
    if (err) {
        die("Failed to load BPF object", err);
    }
    printf("✓ BPF program loaded\n");
    
    // Find maps
    map = bpf_object__find_map_by_name(obj, "counter_map");
    if (!map) {
        die("Failed to find counter_map", ENOENT);
    }
    g_counter_fd = bpf_map__fd(map);
    printf("✓ Found counter_map\n");
    
    map = bpf_object__find_map_by_name(obj, "timing_map");
    if (!map) {
        die("Failed to find timing_map", ENOENT);
    }
    g_timing_fd = bpf_map__fd(map);
    printf("✓ Found timing_map\n");
    
    map = bpf_object__find_map_by_name(obj, "invocation_map");
    if (!map) {
        die("Failed to find invocation_map", ENOENT);
    }
    g_invocation_fd = bpf_map__fd(map);
    printf("✓ Found invocation_map\n");
    
    // Attach program
    prog = bpf_object__find_program_by_name(obj, "write_counter");
    if (!prog) {
        die("Failed to find program", ENOENT);
    }
    
    link = bpf_program__attach(prog);
    err = libbpf_get_error(link);
    if (err) {
        die("Failed to attach program", err);
    }
    
    // Get program ID for bpf_stats
    int prog_fd = bpf_program__fd(prog);
    struct bpf_prog_info info = {};
    unsigned int info_len = sizeof(info);
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err) {
        die("bpf_obj_get_info_by_fd failed", errno);
    }
    g_prog_id = info.id;
    printf("✓ Attached to tracepoint, prog_id=%d\n", g_prog_id);
    
    // Open CSV
    csv = fopen("contention_results.csv", "w");
    if (!csv) {
        perror("Failed to open CSV");
        ret = 1;
        goto cleanup;
    }
    fprintf(csv, "num_readers,avg_total_bpf_ns,avg_helper_time_ns,avg_fill_loop_ns,helper_pct_of_component,fill_pct_of_component,helper_overhead_pct,invocations\n");
    printf("✓ Opened contention_results.csv\n");
    
    printf("\n=======================================================\n");
    printf("Running benchmarks (readers = 4 to 64, step 4, %d sec each)\n", TEST_DURATION_SEC);
    printf("=======================================================\n");
    
    // Main loop: 4, 8, 12, ..., 64 reader threads
    for (int num_readers = 4; num_readers <= 64; num_readers += 4) {
        if (run_benchmark(num_readers, csv) != 0) {
            fprintf(stderr, "Benchmark failed for num_readers=%d\n", num_readers);
            ret = 1;
            break;
        }
    }
    
    if (ret == 0) {
        printf("\n=======================================================\n");
        printf("Benchmark completed!\n");
        printf("Results saved to contention_results.csv\n");
        printf("=======================================================\n");
    }

cleanup:
    if (csv) fclose(csv);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    
    return ret;
}
