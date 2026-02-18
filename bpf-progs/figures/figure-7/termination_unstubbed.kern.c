/*
 * Figure-7: unstubbed helper termination benchmark.
 *
 * Matches the stubbed-helper structure, but executes helper calls before
 * terminating with bpf_die_kfunc().
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

extern void bpf_die_kfunc(void) __ksym;

char _license[] SEC("license") = "GPL";

#ifndef MAX_HELPERS
#define MAX_HELPERS 62
#endif

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_unstubbed(void *ctx)
{
	volatile __u64 sink = 0;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_HELPERS; i++)
		sink += bpf_get_prandom_u32();

	bpf_die_kfunc();
	return (int)sink;
}
