// BPF Contention Benchmark - Kernel Program
// Measures lock acquisition time via bpf_map_update_elem
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Fill iterations - uses bpf_loop() to avoid verifier unrolling
#define FILL_ITERATIONS 1000000

// Value size for the hash map (larger = longer critical section)
#define VALUE_SIZE 256
struct large_value {
    __u64 counter;
    char padding[VALUE_SIZE - sizeof(__u64)];
};

struct contention_timing_stats {
    __u64 update_ns;
    __u64 fill_loop_ns;
};

// Counter map - using HASH map which has bucket spinlocks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct large_value);
    __uint(max_entries, 1);
} counter_map SEC(".maps");

// Timing map - accumulates total helper time (per-CPU to reduce map cacheline contention)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct contention_timing_stats);
    __uint(max_entries, 1);
} timing_map SEC(".maps");

// Max wait time - tracks worst case
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} max_wait_map SEC(".maps");

// Invocation count map (per-CPU to reduce update contention)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} invocation_map SEC(".maps");

// Failed update count map (lock timeouts/errors)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} failure_map SEC(".maps");

// Per-CPU scratch space to avoid stack allocation
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct large_value);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

// Callback for bpf_loop - does minimal work per iteration
static int fill_callback(__u32 index, void *ctx) {
    __u64 *counter = ctx;
    (*counter)++;
    return 0;  // Continue looping
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int write_counter(void *ctx) {
    __u32 key = 0;
    struct large_value *val;
    struct large_value *new_val;
    struct contention_timing_stats *timing;
    __u64 *invocations;
    __u64 fill_counter = 0;
    __u64 fill_loop_delta = 0;
    
    // Fill up to verifier limit using bpf_loop (avoids verifier unrolling)
    __u64 fill_start = bpf_ktime_get_ns();
    bpf_loop(FILL_ITERATIONS, fill_callback, &fill_counter, 0);
    __u64 fill_end = bpf_ktime_get_ns();
    fill_loop_delta = fill_end - fill_start;
    
    // Get scratch space for new value (avoids stack allocation)
    new_val = bpf_map_lookup_elem(&scratch_map, &key);
    if (!new_val)
        return 0;
    
    // Get current value
    val = bpf_map_lookup_elem(&counter_map, &key);
    if (!val)
        return 0;
    new_val->counter = val->counter + 1;
    
    // Measure bpf_map_update_elem which takes the map's spinlock
    // The lock is ONLY held during this call
    __u64 start = bpf_ktime_get_ns();
    int ret = bpf_map_update_elem(&counter_map, &key, new_val, BPF_ANY);
    __u64 end = bpf_ktime_get_ns();
    
    if (ret != 0) {
        // Lock acquisition failed (timeout or error)
        __u64 *failures = bpf_map_lookup_elem(&failure_map, &key);
        if (failures) {
            __sync_fetch_and_add(failures, 1);
        }
        return 0;
    }
    
    // Accumulate timing for successful acquisitions only
    __u64 wait_time = end - start;
    timing = bpf_map_lookup_elem(&timing_map, &key);
    if (timing) {
        __sync_fetch_and_add(&timing->update_ns, wait_time);
        __sync_fetch_and_add(&timing->fill_loop_ns, fill_loop_delta);
    }
    
    // Track max wait time (best effort - race is ok for max tracking)
    __u64 *max_wait = bpf_map_lookup_elem(&max_wait_map, &key);
    if (max_wait && wait_time > *max_wait) {
        *max_wait = wait_time;  // Non-atomic is fine, we just want rough max
    }
    
    // Count successful invocations
    invocations = bpf_map_lookup_elem(&invocation_map, &key);
    if (invocations) {
        __sync_fetch_and_add(invocations, 1);
    }
    
    return 0;
}
