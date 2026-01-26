// BPF Timeout Demonstration
// Shows how rqspinlock timeout protects waiters when a lock holder is stuck
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Define the resilient spinlock structure (matches kernel's definition)
struct bpf_res_spin_lock {
    __u32 val;
};

// Forward declaration of kfuncs
extern int bpf_res_spin_lock(struct bpf_res_spin_lock *lock) __ksym;
extern void bpf_res_spin_unlock(struct bpf_res_spin_lock *lock) __ksym;

// Global lock in BSS section (not in a map, avoids verifier map restriction)
static struct bpf_res_spin_lock global_lock SEC(".bss");
static __u64 global_counter SEC(".bss");

// Control map - userspace sets the number of iterations to hold the lock
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} hold_iterations_map SEC(".maps");

// Results map - tracks successful acquisitions and timeouts
struct results {
    __u64 success_count;
    __u64 timeout_count;
    __u64 total_wait_ns;
    __u64 max_wait_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct results);
    __uint(max_entries, 1);
} results_map SEC(".maps");

// Program 1: "Lock Holder" - acquires lock and holds it for N iterations
// Triggered by syscall 470 (saterm_test) on entry
SEC("tracepoint/syscalls/sys_enter_saterm_test")
int lock_holder(void *ctx) {
    __u32 key = 0;
    __u64 *iterations;
    int ret;
    
    iterations = bpf_map_lookup_elem(&hold_iterations_map, &key);
    if (!iterations)
        return 0;
    
    __u64 hold_count = *iterations;
    
    // Acquire the resilient spinlock
    ret = bpf_res_spin_lock(&global_lock);
    if (ret != 0) {
        // Lock acquisition failed (timeout or deadlock)
        return 0;
    }
    
    // Hold the lock for the configured number of iterations
    // This simulates a "stuck" or slow lock holder
    volatile __u64 dummy = 0;
    for (__u64 i = 0; i < hold_count; i++) {
        dummy += i;
        // Prevent compiler from optimizing away
        asm volatile("" : "+r"(dummy));
    }
    
    global_counter++;
    
    // Release the lock
    bpf_res_spin_unlock(&global_lock);
    
    return 0;
}

// Program 2: "Lock Waiter" - tries to acquire lock, measures wait time
// Triggered by syscall 470 (saterm_test) on exit
SEC("tracepoint/syscalls/sys_exit_saterm_test")
int lock_waiter(void *ctx) {
    __u32 key = 0;
    struct results *res;
    int ret;
    
    res = bpf_map_lookup_elem(&results_map, &key);
    if (!res)
        return 0;
    
    __u64 start = bpf_ktime_get_ns();
    
    // Try to acquire the lock - may timeout if holder is stuck
    ret = bpf_res_spin_lock(&global_lock);
    
    __u64 end = bpf_ktime_get_ns();
    __u64 wait_time = end - start;
    
    if (ret != 0) {
        // Lock acquisition FAILED - timeout or deadlock detected!
        __sync_fetch_and_add(&res->timeout_count, 1);
        __sync_fetch_and_add(&res->total_wait_ns, wait_time);
        if (wait_time > res->max_wait_ns) {
            res->max_wait_ns = wait_time;
        }
        return 0;
    }
    
    // Lock acquisition succeeded
    __sync_fetch_and_add(&res->success_count, 1);
    __sync_fetch_and_add(&res->total_wait_ns, wait_time);
    if (wait_time > res->max_wait_ns) {
        res->max_wait_ns = wait_time;
    }
    
    global_counter++;
    
    bpf_res_spin_unlock(&global_lock);
    
    return 0;
}
