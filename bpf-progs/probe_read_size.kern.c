// BPF Probe Read Size Benchmark - Kernel Program
// Measures bpf_probe_read_kernel performance with varying size arguments
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Maximum read size - 100MB for dramatic scaling
#define MAX_READ_SIZE 100000000  // 100MB

// Fill iterations - uses bpf_loop() to avoid verifier unrolling
#define FILL_ITERATIONS 1000000

// Buffer to hold read data - regular ARRAY allows larger values
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, char[MAX_READ_SIZE]);
    __uint(max_entries, 1);
} buffer_map SEC(".maps");

struct probe_timing_stats {
    __u64 probe_ns;
    __u64 fill_loop_ns;
};

// Timing map - accumulates total helper time
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct probe_timing_stats);
    __uint(max_entries, 1);
} timing_map SEC(".maps");

// Control map - specifies how many bytes to read
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} control_map SEC(".maps");

// Invocation count map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} invocation_map SEC(".maps");

// Callback for bpf_loop - does minimal work per iteration
static int fill_callback(__u32 index, void *ctx) {
    __u64 *counter = ctx;
    (*counter)++;
    return 0;  // Continue looping
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int probe_read_benchmark(void *ctx) {
    __u32 key = 0;
    __u32 *size_ptr;
    char *buffer;
    struct probe_timing_stats *timing;
    __u64 *invocations;
    __u64 fill_counter = 0;
    __u64 fill_loop_delta = 0;
    
    // Fill up to verifier limit using bpf_loop (avoids verifier unrolling)
    __u64 fill_start = bpf_ktime_get_ns();
    bpf_loop(FILL_ITERATIONS, fill_callback, &fill_counter, 0);
    __u64 fill_end = bpf_ktime_get_ns();
    fill_loop_delta = fill_end - fill_start;
    
    // Get the size to read from control_map
    size_ptr = bpf_map_lookup_elem(&control_map, &key);
    if (!size_ptr)
        return 0;
    
    __u32 size = *size_ptr;
    if (size == 0 || size > MAX_READ_SIZE)
        return 0;
    
    // Get buffer from percpu map
    buffer = bpf_map_lookup_elem(&buffer_map, &key);
    if (!buffer)
        return 0;
    
    // Get current task pointer - always valid
    void *task = (void *)bpf_get_current_task();
    if (!task)
        return 0;
    
    // Measure bpf_probe_read_kernel with the specified size
    __u64 start = bpf_ktime_get_ns();
    int ret = bpf_probe_read_kernel(buffer, size, task);
    __u64 end = bpf_ktime_get_ns();
    
    // Only count successful reads
    if (ret != 0)
        return 0;
    
    // Accumulate timing
    timing = bpf_map_lookup_elem(&timing_map, &key);
    if (timing) {
        __sync_fetch_and_add(&timing->probe_ns, end - start);
        __sync_fetch_and_add(&timing->fill_loop_ns, fill_loop_delta);
    }
    
    // Count invocations
    invocations = bpf_map_lookup_elem(&invocation_map, &key);
    if (invocations) {
        __sync_fetch_and_add(invocations, 1);
    }
    
    return 0;
}

