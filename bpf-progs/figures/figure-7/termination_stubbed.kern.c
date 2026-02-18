/*
 * Figure-7: stubbed helper termination benchmark.
 *
 * Uses a helper loop that does not require explicit free calls, then
 * terminates with bpf_die_kfunc().
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
int tracepoint_exit_termination_stubbed(void *ctx)
{
	volatile __u64 sink = 0;
	int i;

	/* Terminate before helper loop execution. */
	bpf_die_kfunc();

	for (i = 0; i < MAX_HELPERS; i++)
		sink += bpf_get_prandom_u32();

	return 0;
}
