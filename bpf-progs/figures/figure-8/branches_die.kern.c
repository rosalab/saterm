/*
 * Figure-8 branch sweep benchmark (saterm variant).
 *
 * This program increases branch-work as MAX_BRANCHES increases by executing
 * a bounded loop with one conditional branch per iteration, then terminates
 * via bpf_die_kfunc().
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

extern void bpf_die_kfunc(void) __ksym;

char _license[] SEC("license") = "GPL";

#ifndef MAX_BRANCHES
#define MAX_BRANCHES 10
#endif

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int branch_die_sample(void *ctx)
{
	__u64 result = 0;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_BRANCHES; i++) {
		__u32 rnd = bpf_get_prandom_u32();

		if (rnd & 1)
			result += i;
		else
			result -= 1;
	}

	bpf_die_kfunc();
	return (int)result;
}
