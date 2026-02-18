/*
 * Figure-7: baseline instruction benchmark.
 *
 * Pure instruction loop with no helpers and no termination call.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#ifndef MAX_ITERS
#define MAX_ITERS 1000000
#endif

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_baseline(void *ctx)
{
	volatile __u64 counter = 0;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_ITERS; i++)
		counter++;

	return (int)counter;
}
