#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Forward declaration for bpf_for_each_map_elem callback
struct bpf_map;

#define MAX_ELEMS (100000)
#define FILL_ITERATIONS 100000

// Array map to iterate over
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_ELEMS);
} ar SEC(".maps");

// Map to store timing information (cumulative time per component)
struct timing_stats {
    __u64 map_iter_ns;
    __u64 fill_loop_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct timing_stats);
    __uint(max_entries, 1);
} timing_map SEC(".maps");

// Map to control how many elements to process
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} control_map SEC(".maps");

// Context structure to pass to callback
struct callback_ctx {
    __u32 counter;
    __u32 max_count;
};

static long callback_fn(struct bpf_map *map, const void *key, void *value, void *ctx) {
    struct callback_ctx *cb_ctx = (struct callback_ctx *)ctx;
    
    // Stop iterating once we've processed max_count elements
    if (cb_ctx->counter >= cb_ctx->max_count) {
        return 1; // Stop iteration
    }
    
    cb_ctx->counter++;
    return 0; // Continue iteration
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int iterate_over_map(void *ctx) {
    __u32 key = 0;
    __u32 *n_ptr;
    struct timing_stats *timing_ptr;
    
    // Fill up instruction budget with a tight loop and measure its cost
    volatile __u64 fill_counter = 0;
    __u64 fill_start = bpf_ktime_get_ns();
    // #pragma unroll
    for (int i = 0; i < FILL_ITERATIONS; i++) {
        fill_counter++;
    }
    __u64 fill_end = bpf_ktime_get_ns();
    
    // Get the number of elements to process from control_map
    n_ptr = bpf_map_lookup_elem(&control_map, &key);
    if (!n_ptr)
        return 0;
    
    __u32 n = *n_ptr;
    if (n == 0 || n > MAX_ELEMS)
        return 0;

    // Set up callback context
    struct callback_ctx cb_ctx = {
        .counter = 0,
        .max_count = n
    };
    
    long (*cb_p)(struct bpf_map *, const void *, void *, void *) = &callback_fn;
    
    // Measure execution time of bpf_for_each_map_elem
    __u64 iter_start = bpf_ktime_get_ns();
    bpf_for_each_map_elem(&ar, cb_p, &cb_ctx, 0);
    __u64 iter_end = bpf_ktime_get_ns();
    
    // Add the time delta to timing_map (accumulate across invocations)
    timing_ptr = bpf_map_lookup_elem(&timing_map, &key);
    if (timing_ptr) {
        __u64 map_delta = iter_end - iter_start;
        __u64 fill_delta = fill_end - fill_start;
        __sync_fetch_and_add(&timing_ptr->map_iter_ns, map_delta);
        __sync_fetch_and_add(&timing_ptr->fill_loop_ns, fill_delta);
    }
    
    return 0;
}
