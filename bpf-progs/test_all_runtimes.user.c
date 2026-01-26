// Unified BPF Runtime Benchmark
// Runs map iterator and contention benchmarks with shared utilities
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

//=============================================================================
// Shared Types
//=============================================================================

typedef struct {
    unsigned long run_time_ns;
    unsigned long run_cnt;
} bpf_stats_t;

// Matches timing_map value in map_iterator.kern.c
typedef struct {
    unsigned long long map_iter_ns;
    unsigned long long fill_loop_ns;
} timing_stats_t;

typedef struct {
    unsigned long long update_ns;
    unsigned long long fill_loop_ns;
} contention_timing_t;

typedef struct {
    unsigned long long probe_ns;
    unsigned long long fill_loop_ns;
} probe_timing_t;
// Common BPF context - both benchmarks share timing_map
typedef struct {
    struct bpf_object *obj;
    struct bpf_link *link;
    int prog_id;
    int timing_fd;      // Both benchmarks have timing_map
} bpf_ctx_t;

//=============================================================================
// Shared Utilities
//=============================================================================

static void die(const char *msg, int err) {
    fprintf(stderr, "%s: %s (%d)\n", msg, strerror(err > 0 ? err : -err), err);
    exit(1);
}

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

static void trigger_syscalls(int count) {
    for (int i = 0; i < count; i++) {
        syscall(__NR_saterm_test);
    }
}

static void print_benchmark_result(const char *name, int n, 
                                   double avg_total_ns, double avg_helper_ns,
                                   unsigned long invocations) {
    double overhead_pct = avg_total_ns > 0 ? (avg_helper_ns / avg_total_ns) * 100.0 : 0;
    printf("  [%s n=%d]\n", name, n);
    printf("    Invocations: %lu\n", invocations);
    printf("    Avg total BPF time: %.2f ns\n", avg_total_ns);
    printf("    Avg helper time: %.2f ns\n", avg_helper_ns);
    printf("    Helper overhead: %.1f%%\n", overhead_pct);
}

//=============================================================================
// Shared BPF Loading Utilities
//=============================================================================

// Load BPF object, attach program, get timing_map fd
static int load_bpf_program(const char *obj_file, const char *prog_name, bpf_ctx_t *ctx) {
    int err;
    
    memset(ctx, 0, sizeof(*ctx));
    
    // Load object
    ctx->obj = bpf_object__open_file(obj_file, NULL);
    if (!ctx->obj) {
        fprintf(stderr, "Failed to open %s\n", obj_file);
        return -1;
    }
    
    err = bpf_object__load(ctx->obj);
    if (err) {
        fprintf(stderr, "Failed to load %s: %d\n", obj_file, err);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }
    
    // Find and attach program
    struct bpf_program *prog = bpf_object__find_program_by_name(ctx->obj, prog_name);
    if (!prog) {
        fprintf(stderr, "Failed to find program %s\n", prog_name);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }
    
    ctx->link = bpf_program__attach(prog);
    if (libbpf_get_error(ctx->link)) {
        fprintf(stderr, "Failed to attach program %s\n", prog_name);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        ctx->link = NULL;
        return -1;
    }
    
    // Get prog_id
    int prog_fd = bpf_program__fd(prog);
    struct bpf_prog_info info = {};
    unsigned int info_len = sizeof(info);
    bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    ctx->prog_id = info.id;
    
    // Find timing_map (common to both benchmarks)
    struct bpf_map *timing_map = bpf_object__find_map_by_name(ctx->obj, "timing_map");
    if (timing_map) {
        ctx->timing_fd = bpf_map__fd(timing_map);
    } else {
        ctx->timing_fd = -1;
    }
    
    printf("✓ Loaded %s, prog_id=%d\n", obj_file, ctx->prog_id);
    return 0;
}

// Cleanup BPF context
static void cleanup_bpf_program(bpf_ctx_t *ctx) {
    if (ctx->link) bpf_link__destroy(ctx->link);
    if (ctx->obj) bpf_object__close(ctx->obj);
    memset(ctx, 0, sizeof(*ctx));
}

// Get map fd by name from loaded context
static int get_map_fd(bpf_ctx_t *ctx, const char *map_name) {
    struct bpf_map *map = bpf_object__find_map_by_name(ctx->obj, map_name);
    if (!map) {
        fprintf(stderr, "Failed to find map %s\n", map_name);
        return -1;
    }
    return bpf_map__fd(map);
}

// Reset contention timing_map (per-CPU) to zeroed values
static void reset_contention_timing_map(int timing_fd, int num_cpus) {
    __u32 key = 0;
    contention_timing_t *zeros = calloc(num_cpus, sizeof(*zeros));
    if (!zeros)
        return;
    bpf_map_update_elem(timing_fd, &key, zeros, BPF_ANY);
    free(zeros);
}

// Read contention timing_map (per-CPU) and sum
static contention_timing_t read_contention_timing_map(int timing_fd, int num_cpus) {
    __u32 key = 0;
    contention_timing_t total = {};
    contention_timing_t *values = calloc(num_cpus, sizeof(*values));
    if (!values)
        return total;
    if (bpf_map_lookup_elem(timing_fd, &key, values) == 0) {
        for (int i = 0; i < num_cpus; i++) {
            total.update_ns += values[i].update_ns;
            total.fill_loop_ns += values[i].fill_loop_ns;
        }
    }
    free(values);
    return total;
}

// Reset per-CPU u64 map (used for contention invocations)
static void reset_percpu_u64_map(int map_fd, int num_cpus) {
    __u32 key = 0;
    __u64 *zeros = calloc(num_cpus, sizeof(__u64));
    if (!zeros)
        return;
    bpf_map_update_elem(map_fd, &key, zeros, BPF_ANY);
    free(zeros);
}

// Sum per-CPU u64 map
static __u64 read_percpu_u64_sum(int map_fd, int num_cpus) {
    __u32 key = 0;
    __u64 sum = 0;
    __u64 *values = calloc(num_cpus, sizeof(__u64));
    if (!values)
        return 0;
    if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
        for (int i = 0; i < num_cpus; i++) {
            sum += values[i];
        }
    }
    free(values);
    return sum;
}

// Reset probe timing_map to zeroed struct
static void reset_probe_timing_map(int timing_fd) {
    __u32 key = 0;
    probe_timing_t zero = {};
    bpf_map_update_elem(timing_fd, &key, &zero, BPF_ANY);
}

// Read probe timing_map value
static probe_timing_t read_probe_timing_map(int timing_fd) {
    __u32 key = 0;
    probe_timing_t value = {};
    bpf_map_lookup_elem(timing_fd, &key, &value);
    return value;
}

// Map iterator specific: reset timing_map (struct timing_stats)
static void reset_map_iter_timing_map(int timing_fd) {
    __u32 key = 0;
    timing_stats_t zero = {};
    bpf_map_update_elem(timing_fd, &key, &zero, BPF_ANY);
}

// Map iterator specific: read timing_map (struct timing_stats)
static int read_map_iter_timing_map(int timing_fd, timing_stats_t *out) {
    __u32 key = 0;
    if (bpf_map_lookup_elem(timing_fd, &key, out) != 0) {
        return -1;
    }
    return 0;
}

//=============================================================================
// Map Iterator Benchmark
//=============================================================================

#define MAP_ITER_NUM_SYSCALLS 1000

static int run_map_iterator_benchmark(void) {
    bpf_ctx_t ctx;
    int ar_fd, control_fd;
    FILE *csv = NULL;
    int ret = 0;
    
    printf("\n=======================================================\n");
    printf("Map Iterator Benchmark\n");
    printf("=======================================================\n");
    
    // Load using shared utility
    if (load_bpf_program("map_iterator.kern.o", "iterate_over_map", &ctx) != 0) {
        return -1;
    }
    
    // Get additional maps specific to this benchmark
    ar_fd = get_map_fd(&ctx, "ar");
    control_fd = get_map_fd(&ctx, "control_map");
    if (ar_fd < 0 || control_fd < 0) {
        ret = -1;
        goto cleanup;
    }
    
    // Open CSV
    csv = fopen("map_iterator_results.csv", "w");
    if (!csv) {
        perror("Failed to open map_iterator_results.csv");
        ret = -1;
        goto cleanup;
    }
    fprintf(csv, "n,avg_component_total_ns,avg_map_iter_ns,avg_fill_loop_ns,map_iter_pct_component,fill_loop_pct_component,avg_bpftool_total_ns,invocations\n");
    
    // Run benchmarks: 0, 1000, 2000, ... 100000
    for (unsigned int n = 0; n <= 100000; n += 1000) {
        __u32 key = 0;
        bpf_stats_t initial_stats, final_stats;
        
        // Populate array
        for (unsigned int i = 0; i < n; i++) {
            __u32 val = i;
            bpf_map_update_elem(ar_fd, &i, &val, BPF_ANY);
        }
        
        // Set control and reset timing (using shared utility)
        bpf_map_update_elem(control_fd, &key, &n, BPF_ANY);
    reset_map_iter_timing_map(ctx.timing_fd);
        
        // Get initial stats
        read_bpf_stats(ctx.prog_id, &initial_stats);
        
        // Trigger syscalls
        trigger_syscalls(MAP_ITER_NUM_SYSCALLS);
        
        // Get final stats
        read_bpf_stats(ctx.prog_id, &final_stats);
        timing_stats_t timing_value = {};
        if (read_map_iter_timing_map(ctx.timing_fd, &timing_value) != 0) {
            fprintf(stderr, "Failed to read timing_map for map iterator\n");
            ret = -1;
            goto cleanup;
        }
        
        // Calculate
        unsigned long delta_run_cnt = final_stats.run_cnt - initial_stats.run_cnt;
        unsigned long delta_run_time = final_stats.run_time_ns - initial_stats.run_time_ns;
        
        double avg_bpftool_total_ns = delta_run_cnt > 0 ? (double)delta_run_time / delta_run_cnt : 0;
        double avg_map_iter_ns = delta_run_cnt > 0 ? (double)timing_value.map_iter_ns / delta_run_cnt : 0;
        double avg_fill_loop_ns = delta_run_cnt > 0 ? (double)timing_value.fill_loop_ns / delta_run_cnt : 0;
        double avg_component_total_ns = avg_map_iter_ns + avg_fill_loop_ns; // desired total = loop + helper
        double map_iter_pct = avg_component_total_ns > 0 ? (avg_map_iter_ns / avg_component_total_ns) * 100.0 : 0;
        double fill_loop_pct = avg_component_total_ns > 0 ? (avg_fill_loop_ns / avg_component_total_ns) * 100.0 : 0;
        
        printf("  [map_iter n=%u]\n", n);
        printf("    Invocations: %lu\n", delta_run_cnt);
        printf("    Avg component total (map+loop): %.2f ns\n", avg_component_total_ns);
        printf("    Avg map-iterator time: %.2f ns (%.1f%% of component)\n", avg_map_iter_ns, map_iter_pct);
        printf("    Avg fill-loop time: %.2f ns (%.1f%% of component)\n", avg_fill_loop_ns, fill_loop_pct);
        printf("    Avg bpftool total (reference): %.2f ns\n", avg_bpftool_total_ns);
        
        fprintf(csv, "%u,%.2f,%.2f,%.2f,%.1f,%.1f,%.2f,%lu\n",
                n, avg_component_total_ns, avg_map_iter_ns, avg_fill_loop_ns,
                map_iter_pct, fill_loop_pct, avg_bpftool_total_ns, delta_run_cnt);
        fflush(csv);
    }
    
    printf("✓ Results saved to map_iterator_results.csv\n");
    
cleanup:
    if (csv) fclose(csv);
    cleanup_bpf_program(&ctx);
    return ret;
}

//=============================================================================
// Contention Benchmark (Parallel with CPU pinning)
//=============================================================================

#include <sched.h>
#include <sys/sysinfo.h>

#define CONTENTION_DURATION_SEC 30
#define CONTENTION_NUM_RUNS 1
#define CONTENTION_THREAD_STEP 4
#define CONTENTION_MAX_THREADS 64

// Value size to match BPF side
#define CONTENTION_VALUE_SIZE 256
struct contention_large_value {
    __u64 counter;
    char padding[CONTENTION_VALUE_SIZE - sizeof(__u64)];
};

static volatile int contention_running = 0;
static int contention_counter_fd = -1;
static int g_num_cpus = 0;

typedef struct {
    int thread_id;
    int cpu_id;
    unsigned long syscall_count;
} contention_thread_data_t;

// Worker thread - pinned to CPU, calls syscall in tight loop
static void *contention_worker_thread(void *arg) {
    contention_thread_data_t *data = (contention_thread_data_t *)arg;
    cpu_set_t cpuset;
    
    // Pin to specific CPU
    CPU_ZERO(&cpuset);
    CPU_SET(data->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    data->syscall_count = 0;
    
    while (contention_running) {
        syscall(__NR_saterm_test);
        data->syscall_count++;
    }
    
    return NULL;
}

// Results from a single contention run
typedef struct {
    double avg_total_ns;
    double avg_helper_ns;
    double avg_fill_loop_ns;
    __u64 max_wait_ns;
    unsigned long invocations;
    __u64 failures;
} contention_result_t;

// Run a single 1-second contention test, returns results
static int run_single_contention_run(bpf_ctx_t *ctx, int num_threads,
                                     int invocation_fd, int failure_fd, 
                                     int max_wait_fd, contention_result_t *result) {
    pthread_t *threads = NULL;
    contention_thread_data_t *thread_data = NULL;
    __u32 key = 0;
    __u64 zero = 0;
    bpf_stats_t initial_stats, final_stats;
    int ret = 0;
    
    // Allocate threads
    threads = calloc(num_threads, sizeof(pthread_t));
    thread_data = calloc(num_threads, sizeof(contention_thread_data_t));
    if (!threads || !thread_data) {
        perror("calloc failed");
        free(threads);
        free(thread_data);
        return -1;
    }
    
    // Reset maps
    reset_contention_timing_map(ctx->timing_fd, g_num_cpus);
    reset_percpu_u64_map(invocation_fd, g_num_cpus);
    bpf_map_update_elem(failure_fd, &key, &zero, BPF_ANY);
    bpf_map_update_elem(max_wait_fd, &key, &zero, BPF_ANY);
    
    // Get initial stats
    read_bpf_stats(ctx->prog_id, &initial_stats);
    
    // Start threads
    contention_running = 1;
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].cpu_id = i % g_num_cpus;
        if (pthread_create(&threads[i], NULL, contention_worker_thread, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            ret = -1;
        }
    }
    
    // Wait
    sleep(CONTENTION_DURATION_SEC);
    
    // Stop threads
    contention_running = 0;
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Get final stats
    read_bpf_stats(ctx->prog_id, &final_stats);
    contention_timing_t timing_value = read_contention_timing_map(ctx->timing_fd, g_num_cpus);
    __u64 invocation_value = 0, failure_value = 0, max_wait_value = 0;
    invocation_value = read_percpu_u64_sum(invocation_fd, g_num_cpus);
    bpf_map_lookup_elem(failure_fd, &key, &failure_value);
    bpf_map_lookup_elem(max_wait_fd, &key, &max_wait_value);
    
    // Calculate
    unsigned long delta_run_cnt = final_stats.run_cnt - initial_stats.run_cnt;
    unsigned long delta_run_time = final_stats.run_time_ns - initial_stats.run_time_ns;
    
    result->avg_total_ns = delta_run_cnt > 0 ? (double)delta_run_time / delta_run_cnt : 0;
    result->avg_helper_ns = invocation_value > 0 ? (double)timing_value.update_ns / invocation_value : 0;
    result->avg_fill_loop_ns = invocation_value > 0 ? (double)timing_value.fill_loop_ns / invocation_value : 0;
    result->max_wait_ns = max_wait_value;
    result->invocations = invocation_value;
    result->failures = failure_value;
    
    free(threads);
    free(thread_data);
    return ret;
}

// Run multiple iterations and average the results
static int run_contention_iteration(bpf_ctx_t *ctx, int num_threads,
                                    int invocation_fd, int failure_fd, 
                                    int max_wait_fd, FILE *csv) {
    contention_result_t results[CONTENTION_NUM_RUNS];
    __u64 max_wait_sum = 0;
    double avg_total_sum = 0, avg_helper_sum = 0, avg_fill_sum = 0;
    unsigned long invocations_sum = 0;
    __u64 failures_sum = 0;
    
    printf("  [contention n=%d] Running %d iterations...\n", num_threads, CONTENTION_NUM_RUNS);
    
    for (int i = 0; i < CONTENTION_NUM_RUNS; i++) {
        if (run_single_contention_run(ctx, num_threads, invocation_fd, failure_fd, 
                                      max_wait_fd, &results[i]) != 0) {
            return -1;
        }
        printf("    Run %d: max_wait=%llu ns (%.2f ms)\n", 
               i + 1, (unsigned long long)results[i].max_wait_ns, 
               results[i].max_wait_ns / 1e6);
        
        max_wait_sum += results[i].max_wait_ns;
        avg_total_sum += results[i].avg_total_ns;
        avg_helper_sum += results[i].avg_helper_ns;
        avg_fill_sum += results[i].avg_fill_loop_ns;
        invocations_sum += results[i].invocations;
        failures_sum += results[i].failures;
    }
    
    // Calculate averages
    double avg_max_wait = (double)max_wait_sum / CONTENTION_NUM_RUNS;
    double avg_total_ns = avg_total_sum / CONTENTION_NUM_RUNS;
    double avg_helper_ns = avg_helper_sum / CONTENTION_NUM_RUNS;
    double avg_fill_loop_ns = avg_fill_sum / CONTENTION_NUM_RUNS;
    double component_total_ns = avg_helper_ns + avg_fill_loop_ns;
    double overhead_pct = avg_total_ns > 0 ? (avg_helper_ns / avg_total_ns) * 100.0 : 0;
    double helper_pct = component_total_ns > 0 ? (avg_helper_ns / component_total_ns) * 100.0 : 0;
    double fill_pct = component_total_ns > 0 ? (avg_fill_loop_ns / component_total_ns) * 100.0 : 0;
    unsigned long avg_invocations = invocations_sum / CONTENTION_NUM_RUNS;
    
    printf("  --- Averaged Results (n=%d) ---\n", num_threads);
    printf("    Avg invocations/run: %lu\n", avg_invocations);
    printf("    Avg total BPF time: %.2f ns\n", avg_total_ns);
    printf("    Avg helper time: %.2f ns (%.1f%% of helper+loop)\n", avg_helper_ns, helper_pct);
    printf("    Avg fill-loop time: %.2f ns (%.1f%% of helper+loop)\n", avg_fill_loop_ns, fill_pct);
    printf("    Avg max wait time: %.0f ns (%.2f ms)\n", avg_max_wait, avg_max_wait / 1e6);
    printf("    Helper overhead: %.1f%%\n", overhead_pct);
    printf("    Total failures: %llu\n", (unsigned long long)failures_sum);
    
    fprintf(csv, "%d,%.2f,%.2f,%.2f,%.1f,%.1f,%.1f,%lu,%llu,%.0f\n",
            num_threads, avg_total_ns, avg_helper_ns, avg_fill_loop_ns,
            helper_pct, fill_pct, overhead_pct, avg_invocations,
            (unsigned long long)failures_sum, avg_max_wait);
    fflush(csv);
    
    return 0;
}

static int run_contention_benchmark(void) {
    bpf_ctx_t ctx;
    int invocation_fd, failure_fd, max_wait_fd;
    FILE *csv = NULL;
    int ret = 0;
    
    printf("\n=======================================================\n");
    printf("Contention Benchmark (Parallel CPU-pinned, averaged max_wait)\n");
    printf("=======================================================\n");
    
    // Get number of CPUs
    g_num_cpus = get_nprocs();
    printf("Detected %d CPUs\n", g_num_cpus);
    printf("Thread range: 4 to %d (step %d)\n", CONTENTION_MAX_THREADS, CONTENTION_THREAD_STEP);
    printf("Each thread count: %d runs of %d second(s)\n", CONTENTION_NUM_RUNS, CONTENTION_DURATION_SEC);
    
    // Load using shared utility
    if (load_bpf_program("contention_lock.kern.o", "write_counter", &ctx) != 0) {
        return -1;
    }
    
    // Get maps
    contention_counter_fd = get_map_fd(&ctx, "counter_map");
    invocation_fd = get_map_fd(&ctx, "invocation_map");
    failure_fd = get_map_fd(&ctx, "failure_map");
    max_wait_fd = get_map_fd(&ctx, "max_wait_map");
    if (contention_counter_fd < 0 || invocation_fd < 0 || failure_fd < 0 || max_wait_fd < 0) {
        ret = -1;
        goto cleanup;
    }
    
    // Initialize counter_map
    __u32 key = 0;
    struct contention_large_value init_val = { .counter = 0 };
    bpf_map_update_elem(contention_counter_fd, &key, &init_val, BPF_ANY);
    
    // Open CSV
    csv = fopen("contention_results.csv", "w");
    if (!csv) {
        perror("Failed to open CSV");
        ret = -1;
        goto cleanup;
    }
    fprintf(csv, "num_threads,avg_total_bpf_ns,avg_helper_time_ns,avg_fill_loop_ns,helper_pct_of_component,fill_pct_of_component,helper_overhead_pct,avg_invocations,total_failures,avg_max_wait_ns\n");
    
    // Iterate: 4, 8, 12, ... up to CONTENTION_MAX_THREADS
    for (int num_threads = CONTENTION_THREAD_STEP; num_threads <= CONTENTION_MAX_THREADS; num_threads += CONTENTION_THREAD_STEP) {
        printf("\n--- Testing with %d threads ---\n", num_threads);
        
        if (run_contention_iteration(&ctx, num_threads, invocation_fd, failure_fd, max_wait_fd, csv) != 0) {
            fprintf(stderr, "Test failed for %d threads\n", num_threads);
            // Continue with other tests
        }
    }
    
    printf("\n✓ Results saved to contention_results.csv\n");
    
cleanup:
    if (csv) fclose(csv);
    cleanup_bpf_program(&ctx);
    return ret;
}

//=============================================================================
// Probe Read Size Benchmark
//=============================================================================

#define PROBE_READ_NUM_SYSCALLS 1000
#define PROBE_READ_MAX_SIZE 100000000  // 100MB
#define PROBE_READ_STEP 2000000       // 1MB steps

static int run_probe_read_benchmark(void) {
    bpf_ctx_t ctx;
    int control_fd, invocation_fd;
    FILE *csv = NULL;
    int ret = 0;
    
    printf("\n=======================================================\n");
    printf("Probe Read Size Benchmark\n");
    printf("=======================================================\n");
    
    // Load using shared utility
    if (load_bpf_program("probe_read_size.kern.o", "probe_read_benchmark", &ctx) != 0) {
        return -1;
    }
    
    // Get maps specific to this benchmark
    control_fd = get_map_fd(&ctx, "control_map");
    invocation_fd = get_map_fd(&ctx, "invocation_map");
    if (control_fd < 0 || invocation_fd < 0) {
        ret = -1;
        goto cleanup;
    }
    
    // Open CSV
    csv = fopen("probe_read_results.csv", "w");
    if (!csv) {
        perror("Failed to open CSV");
        ret = -1;
        goto cleanup;
    }
    fprintf(csv, "size_bytes,avg_total_bpf_ns,avg_probe_ns,avg_fill_loop_ns,probe_pct_of_component,fill_pct_of_component,probe_overhead_pct,invocations\n");
    
    // Run benchmarks: 1MB steps from 0 to 100MB
    for (unsigned int size = 0; size <= PROBE_READ_MAX_SIZE; size += PROBE_READ_STEP) {
        __u32 key = 0;
        __u64 zero = 0;
        bpf_stats_t initial_stats, final_stats;
        
        // Set read size in control_map
        bpf_map_update_elem(control_fd, &key, &size, BPF_ANY);
        
        // Reset timing and invocation maps
        reset_probe_timing_map(ctx.timing_fd);
        bpf_map_update_elem(invocation_fd, &key, &zero, BPF_ANY);
        
        // Get initial stats
        read_bpf_stats(ctx.prog_id, &initial_stats);
        
        // Trigger syscalls
        trigger_syscalls(PROBE_READ_NUM_SYSCALLS);
        
        // Get final stats
        read_bpf_stats(ctx.prog_id, &final_stats);
        probe_timing_t timing_value = read_probe_timing_map(ctx.timing_fd);
        __u64 invocation_value = 0;
        bpf_map_lookup_elem(invocation_fd, &key, &invocation_value);
        
        // Calculate
        unsigned long delta_run_cnt = final_stats.run_cnt - initial_stats.run_cnt;
        unsigned long delta_run_time = final_stats.run_time_ns - initial_stats.run_time_ns;
        
        double avg_total_ns = delta_run_cnt > 0 ? (double)delta_run_time / delta_run_cnt : 0;
        double avg_probe_ns = invocation_value > 0 ? (double)timing_value.probe_ns / invocation_value : 0;
        double avg_fill_loop_ns = invocation_value > 0 ? (double)timing_value.fill_loop_ns / invocation_value : 0;
        double component_total_ns = avg_probe_ns + avg_fill_loop_ns;
        double helper_pct = component_total_ns > 0 ? (avg_probe_ns / component_total_ns) * 100.0 : 0;
        double fill_pct = component_total_ns > 0 ? (avg_fill_loop_ns / component_total_ns) * 100.0 : 0;
        double overhead_pct = avg_total_ns > 0 ? (avg_probe_ns / avg_total_ns) * 100.0 : 0;
        
        printf("  [probe_read size=%u]\n", size);
        printf("    Invocations: %lu\n", delta_run_cnt);
        printf("    Avg total BPF time: %.2f ns\n", avg_total_ns);
        printf("    Avg probe time: %.2f ns (%.1f%% of probe+loop)\n", avg_probe_ns, helper_pct);
        printf("    Avg fill-loop time: %.2f ns (%.1f%% of probe+loop)\n", avg_fill_loop_ns, fill_pct);
        printf("    Probe overhead: %.1f%%\n", overhead_pct);
        
        fprintf(csv, "%u,%.2f,%.2f,%.2f,%.1f,%.1f,%.1f,%lu\n",
                size, avg_total_ns, avg_probe_ns, avg_fill_loop_ns,
                helper_pct, fill_pct, overhead_pct, delta_run_cnt);
        fflush(csv);
    }
    
    printf("✓ Results saved to probe_read_results.csv\n");
    
cleanup:
    if (csv) fclose(csv);
    cleanup_bpf_program(&ctx);
    return ret;
}

//=============================================================================
// Main
//=============================================================================

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOptions:\n");
    printf("  -m, --skip-map        Skip map iterator benchmark\n");
    printf("  -c, --skip-contention Skip contention benchmark\n");
    printf("  -p, --skip-probe      Skip probe read size benchmark\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char **argv) {
    int skip_map = 0;
    int skip_contention = 0;
    int skip_probe = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--skip-map") == 0) {
            skip_map = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--skip-contention") == 0) {
            skip_contention = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--skip-probe") == 0) {
            skip_probe = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("=======================================================\n");
    printf("Unified BPF Runtime Benchmarks\n");
    printf("=======================================================\n\n");
    
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root\n");
        return 1;
    }
    
    if (enable_bpf_stats() != 0) {
        return 1;
    }
    
    int ret = 0;
    
    // Run map iterator benchmark
    if (!skip_map) {
        if (run_map_iterator_benchmark() != 0) {
            fprintf(stderr, "Map iterator benchmark failed\n");
            ret = 1;
        }
    } else {
        printf("Skipping map iterator benchmark\n");
    }
    
    // Run contention benchmark
    if (!skip_contention) {
        if (run_contention_benchmark() != 0) {
            fprintf(stderr, "Contention benchmark failed\n");
            ret = 1;
        }
    } else {
        printf("Skipping contention benchmark\n");
    }
    
    // Run probe read size benchmark
    if (!skip_probe) {
        if (run_probe_read_benchmark() != 0) {
            fprintf(stderr, "Probe read size benchmark failed\n");
            ret = 1;
        }
    } else {
        printf("Skipping probe read size benchmark\n");
    }
    
    printf("\n=======================================================\n");
    printf("All benchmarks completed!\n");
    printf("=======================================================\n");
    
    return ret;
}

