/*
 * Figure-7: empty baseline with termination.
 *
 * Minimal tracepoint program that immediately calls bpf_die_kfunc().
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

extern void bpf_die_kfunc(void) __ksym;

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_empty_die(void *ctx)
{
	bpf_die_kfunc();
	return 0;
}
