/*
 * Figure-7: empty baseline.
 *
 * Minimal tracepoint program with no helper work and no termination call.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_empty(void *ctx)
{
	return 0;
}
