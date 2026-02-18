/*
 * Figure-7: unstubbed expensive-helper termination benchmark.
 *
 * Uses repeated bpf_probe_read_kernel() calls (from Figure-2 style) before
 * bpf_die_kfunc() to model an expensive helper path.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

extern void bpf_die_kfunc(void) __ksym;

char _license[] SEC("license") = "GPL";

#ifndef MAX_HELPERS
#define MAX_HELPERS 62
#endif

#ifndef PROBE_READ_SIZE
#define PROBE_READ_SIZE 4096
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, char[PROBE_READ_SIZE]);
	__uint(max_entries, 1);
} buffer_map SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_unstubbed_expensive(void *ctx)
{
	__u32 key = 0;
	char *buffer;
	void *task;
	volatile __u64 sink = 0;
	int i;

	buffer = bpf_map_lookup_elem(&buffer_map, &key);
	if (!buffer)
		return 0;

	task = (void *)bpf_get_current_task();
	if (!task)
		return 0;

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_HELPERS; i++) {
		int ret = bpf_probe_read_kernel(buffer, PROBE_READ_SIZE, task);
		sink += (ret == 0);
	}

	bpf_die_kfunc();
	return (int)sink;
}
