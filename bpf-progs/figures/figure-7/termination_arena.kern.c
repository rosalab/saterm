/*
 * Figure-7: arena free-call termination benchmark.
 *
 * Mirrors the real-free benchmark shape:
 *  - allocate refs in a loop and measure allocation cost;
 *  - terminate with refs still live at bpf_die_kfunc();
 *  - keep explicit free calls after die for resource-state accounting.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

extern void bpf_die_kfunc(void) __ksym;
void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
				    int node_id, __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt) __ksym __weak;

char _license[] SEC("license") = "GPL";

#ifndef MAX_HELPERS
#define MAX_HELPERS 62
#endif

#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(max_entries, 1); /* pages */
	__uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} alloc_time_map SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_arena(void *ctx)
{
	__u32 key = 0;
	__u64 *alloc_ns_ptr;
	__u64 alloc_start = 0;
	__u64 alloc_end = 0;
	__u64 alloc_delta = 0;
	void __arena *local[(MAX_HELPERS > 0) ? MAX_HELPERS : 1];
	int i;

	__builtin_memset(local, 0, sizeof(local));

	if (MAX_HELPERS > 0) {
		alloc_start = bpf_ktime_get_ns();
#pragma clang loop unroll(disable)
		for (i = 0; i < MAX_HELPERS; i++) {
			local[i] = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
			if (!local[i])
				goto done_alloc;
		}
done_alloc:
		alloc_end = bpf_ktime_get_ns();
		alloc_delta = alloc_end - alloc_start;
	}

	alloc_ns_ptr = bpf_map_lookup_elem(&alloc_time_map, &key);
	if (alloc_ns_ptr)
		*alloc_ns_ptr = alloc_delta;

	/* Die with local refs still live. */
	bpf_die_kfunc();

	if (MAX_HELPERS > 0) {
#pragma clang loop unroll(disable)
		for (i = 0; i < MAX_HELPERS; i++) {
			if (local[i])
				bpf_arena_free_pages(&arena, local[i], 1);
		}
	}

	return 0;
}
