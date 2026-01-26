// SPDX-License-Identifier: GPL-2.0
/* Synchronized termination test for comparing bpf_throw vs dynamic stubbing
 *
 * This program allows EXTERNAL triggering of bpf_throw via a control map,
 * enabling fair comparison with dynamic helper stubbing (which is also external).
 *
 * Usage:
 *   1. Load this program
 *   2. From external test: simultaneously
 *      - Write '1' to control_map[0] (triggers bpf_throw)
 *      - Call bpftool stub (triggers dynamic stubbing)
 *   3. Measure time from trigger to program termination
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern void bpf_throw(unsigned long cookie) __ksym;

/* Control map: write 1 to trigger bpf_throw */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} control_map SEC(".maps");

/* Statistics map: track when trigger was detected */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 10);
} stats_map SEC(".maps");

#define STAT_ITERATIONS 0
#define STAT_TRIGGER_DETECTED 1
#define STAT_THROW_TIMESTAMP 2
#define STAT_RESOURCES_ACQUIRED 3

/* Simulated resources for testing cleanup */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 100);
} resource_map SEC(".maps");

/* Check if we should terminate and call bpf_throw if so */
static __always_inline bool should_throw_exception(void)
{
	__u32 key = 0;
	__u64 *control;
	
	control = bpf_map_lookup_elem(&control_map, &key);
	if (!control)
		return false;
	
	/* Non-zero value means "throw exception now" */
	if (*control != 0) {
		/* Record that we detected the trigger */
		__u64 timestamp = bpf_ktime_get_ns();
		__u32 stat_key = STAT_TRIGGER_DETECTED;
		bpf_map_update_elem(&stats_map, &stat_key, &timestamp, BPF_ANY);
		
		return true;
	}
	
	return false;
}

/* Simulate acquiring resources that need cleanup */
static __noinline int acquire_test_resources(void)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	struct bpf_iter_num iter;
	int *num;
	int count = 0;
	__u32 tuple_size = sizeof(tuple.ipv4);
	
	/* Resource 1: Socket reference */
	sk = bpf_skc_lookup_tcp(NULL, &tuple, tuple_size, 0, 0);
	if (sk) {
		/* Track resource acquisition */
		__u32 stat_key = STAT_RESOURCES_ACQUIRED;
		__u64 one = 1;
		bpf_map_update_elem(&stats_map, &stat_key, &one, BPF_ANY);
		
		/* Check for termination trigger WHILE HOLDING RESOURCE */
		if (should_throw_exception()) {
			/* This will clean up the socket reference automatically! */
			__u64 timestamp = bpf_ktime_get_ns();
			__u32 stat_key = STAT_THROW_TIMESTAMP;
			bpf_map_update_elem(&stats_map, &stat_key, &timestamp, BPF_ANY);
			bpf_throw(1);  /* Cookie = 1 for "triggered by control map" */
		}
		
		bpf_sk_release(sk);
	}
	
	/* Resource 2: Iterator */
	bpf_iter_num_new(&iter, 0, 10);
	while ((num = bpf_iter_num_next(&iter))) {
		count++;
		
		/* Check for termination trigger WHILE HOLDING ITERATOR */
		if (should_throw_exception()) {
			/* Iterator will be cleaned up automatically! */
			__u64 timestamp = bpf_ktime_get_ns();
			__u32 stat_key = STAT_THROW_TIMESTAMP;
			bpf_map_update_elem(&stats_map, &stat_key, &timestamp, BPF_ANY);
			bpf_throw(2);  /* Cookie = 2 for "during iteration" */
		}
	}
	bpf_iter_num_destroy(&iter);
	
	return count;
}

/* Main test program - checks control map on every invocation */
SEC("fentry/tcp_sendmsg")
int test_synchronized_throw(void *ctx)
{
	__u32 key = 0;
	__u64 *iterations, iter_val;
	
	/* Increment iteration counter */
	iterations = bpf_map_lookup_elem(&stats_map, &key);
	if (iterations) {
		iter_val = *iterations + 1;
	} else {
		iter_val = 1;
	}
	bpf_map_update_elem(&stats_map, &key, &iter_val, BPF_ANY);
	
	/* Check BEFORE acquiring resources */
	if (should_throw_exception()) {
		__u64 timestamp = bpf_ktime_get_ns();
		__u32 stat_key = STAT_THROW_TIMESTAMP;
		bpf_map_update_elem(&stats_map, &stat_key, &timestamp, BPF_ANY);
		bpf_throw(0);  /* Cookie = 0 for "before resource acquisition" */
	}
	
	/* Acquire resources and check during */
	acquire_test_resources();
	
	/* Check AFTER releasing resources */
	if (should_throw_exception()) {
		__u64 timestamp = bpf_ktime_get_ns();
		__u32 stat_key = STAT_THROW_TIMESTAMP;
		bpf_map_update_elem(&stats_map, &stat_key, &timestamp, BPF_ANY);
		bpf_throw(3);  /* Cookie = 3 for "after resource release" */
	}
	
	return 0;
}

/* XDP variant for packet processing testing */
SEC("xdp")
int test_synchronized_throw_xdp(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 *iterations, iter_val;
	
	/* Increment counter */
	iterations = bpf_map_lookup_elem(&stats_map, &key);
	if (iterations) {
		iter_val = *iterations + 1;
	} else {
		iter_val = 1;
	}
	bpf_map_update_elem(&stats_map, &key, &iter_val, BPF_ANY);
	
	/* Check for throw trigger */
	if (should_throw_exception()) {
		__u64 timestamp = bpf_ktime_get_ns();
		__u32 stat_key = STAT_THROW_TIMESTAMP;
		bpf_map_update_elem(&stats_map, &stat_key, &timestamp, BPF_ANY);
		
		/* Simulate resource acquisition before throw */
		struct bpf_sock_tuple tuple = {};
		struct bpf_sock *sk;
		__u32 tuple_size = sizeof(tuple.ipv4);
		
		sk = bpf_skc_lookup_tcp(ctx, &tuple, tuple_size, 0, 0);
		if (sk) {
			/* Throw with resource held - will be cleaned up! */
			bpf_throw(10);
		}
		
		bpf_throw(11);
	}
	
	return XDP_PASS;
}

/*
 * USAGE NOTES:
 * ============
 * 
 * To trigger bpf_throw from external test harness:
 *   bpftool map update name control_map key 0 value 1
 * 
 * To reset trigger (after exception or for next test):
 *   bpftool map update name control_map key 0 value 0
 * 
 * To read statistics:
 *   bpftool map dump name stats_map
 *   - Key 0: Total iterations
 *   - Key 1: Timestamp when trigger detected
 *   - Key 2: Timestamp when bpf_throw called
 *   - Key 3: Resources acquired count
 * 
 * For synchronized comparison:
 *   1. Start program execution (packets flowing, syscalls happening)
 *   2. Record start time: T0
 *   3. Simultaneously trigger both:
 *      - Thread A: bpftool map update name control_map key 0 value 1
 *      - Thread B: bpftool prog stub <id>
 *   4. Measure termination time for each
 *      - bpf_throw: check when exception handler completes
 *      - Stubbing: check when JIT patch completes
 */

