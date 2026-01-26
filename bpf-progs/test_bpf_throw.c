// SPDX-License-Identifier: GPL-2.0
/* Example BPF program demonstrating bpf_throw() with resource cleanup (KFLEX)
 *
 * This program shows how bpf_throw() triggers exception handling that
 * automatically cleans up acquired resources (references, iterators, etc.)
 * across all frames in the call stack.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* External declarations for bpf_throw */
extern void bpf_throw(unsigned long cookie) __ksym;

/* Map for testing */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} test_map SEC(".maps");

/* Example 1: Simple throw without resources */
SEC("tc")
int test_simple_throw(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *value;

	/* Do some work */
	value = bpf_map_lookup_elem(&test_map, &key);
	if (!value)
		return 0;

	/* Trigger exception */
	if (*value > 100) {
		bpf_printk("Throwing exception: value=%llu\n", *value);
		bpf_throw(0); /* This will trigger exception handling */
	}

	return 0;
}

/* Example 2: Throw with acquired reference (demonstrates cleanup) */
SEC("fentry/tcp_sendmsg")
int test_throw_with_socket(void *ctx)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	__u32 tuple_size = sizeof(tuple.ipv4);

	/* Acquire a socket reference */
	sk = bpf_skc_lookup_tcp(ctx, &tuple, tuple_size, 0, 0);
	if (!sk)
		return 0;

	/* Normally you would need to call bpf_sk_release(sk) here,
	 * but if we throw an exception, the KFLEX mechanism will
	 * automatically clean it up via the frame descriptors!
	 */
	
	/* Simulate some condition that triggers exception */
	if (sk->src_port > 8000) {
		bpf_printk("Exception: port too high, cleaning up socket ref\n");
		/* The socket reference will be automatically released
		 * by the exception handler using the frame descriptor */
		bpf_throw(1);
	}

	/* Normal path - manual cleanup */
	bpf_sk_release(sk);
	return 0;
}

/* Example 3: Nested function calls with throw */
static __noinline int helper_function_that_throws(__u64 val)
{
	struct bpf_iter_num iter;
	int *num;
	int sum = 0;

	/* Create an iterator (another resource that needs cleanup) */
	bpf_iter_num_new(&iter, 0, 10);
	
	/* Iterate a bit */
	while ((num = bpf_iter_num_next(&iter))) {
		sum += *num;
		
		/* Throw exception in the middle of iteration */
		if (*num == 5 && val > 50) {
			bpf_printk("Exception in helper: sum=%d\n", sum);
			/* Iterator will be automatically destroyed by exception handler */
			bpf_throw(2);
		}
	}

	/* Normal cleanup */
	bpf_iter_num_destroy(&iter);
	return sum;
}

SEC("tp/syscalls/sys_enter_read")
int test_nested_throw(void *ctx)
{
	__u32 key = 0;
	__u64 *value;
	int result;

	value = bpf_map_lookup_elem(&test_map, &key);
	if (!value)
		return 0;

	/* Call helper that might throw
	 * If it throws, the exception will propagate up and
	 * all resources in the helper's frame will be cleaned up
	 */
	result = helper_function_that_throws(*value);

	bpf_printk("Helper returned: %d\n", result);
	return 0;
}

/* Example 4: Multiple resources across frames */
static __noinline int allocate_and_process(void)
{
	struct bpf_iter_num iter;
	int *num;
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	/* Allocate first resource */
	bpf_iter_num_new(&iter, 0, 5);
	
	/* Allocate second resource */
	sk = bpf_skc_lookup_tcp(NULL, &tuple, sizeof(tuple.ipv4), 0, 0);
	if (!sk) {
		bpf_iter_num_destroy(&iter);
		return -1;
	}

	/* Process some data */
	while ((num = bpf_iter_num_next(&iter))) {
		if (*num == 3) {
			/* Throw with multiple resources held
			 * Both iterator and socket will be cleaned up! */
			bpf_printk("Throwing with 2 resources\n");
			bpf_throw(3);
		}
	}

	/* Normal cleanup path */
	bpf_iter_num_destroy(&iter);
	bpf_sk_release(sk);
	return 0;
}

SEC("kprobe/tcp_connect")
int test_multi_resource_throw(void *ctx)
{
	int ret;

	ret = allocate_and_process();
	
	bpf_printk("allocate_and_process returned: %d\n", ret);
	return 0;
}

/*
 * HOW KFLEX EXCEPTION HANDLING WORKS:
 * ====================================
 * 
 * 1. Verification Time:
 *    - The verifier generates "frame descriptors" for each instruction that
 *      might throw an exception (direct bpf_throw() or calls to functions
 *      that might throw).
 *    - Frame descriptors catalog all resources held at that point:
 *      * Register references (sockets, BTF objects, etc.)
 *      * Stack references (iterators, dynptrs, etc.)
 *      * Information needed to release each resource
 * 
 * 2. Runtime (when bpf_throw() is called):
 *    - bpf_throw() walks the entire BPF call stack using bpf_stack_walker()
 *    - For each frame, it:
 *      * Locates the frame descriptor for that instruction pointer
 *      * Calls arch_bpf_cleanup_frame_resource() with the descriptor
 *      * Releases all resources: calls release functions for references,
 *        destroys iterators, discards ringbuf reservations, etc.
 *    - After cleanup, control transfers to the exception handler
 * 
 * 3. Why the callback_ref removal is safe:
 *    - Old approach: Prevented callbacks from releasing caller's refs
 *    - New approach: Frame descriptors track ownership per-frame
 *    - KFLEX: Runtime cleanup uses frame descriptors, not verification-time
 *      reference tracking, so it handles all resources correctly regardless
 *      of callback context.
 */

