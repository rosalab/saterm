/*
 * Figure-7: real-free termination benchmark.
 *
 * Keeps refs local at bpf_die_kfunc() by storing allocated objects in a
 * stack-local array, then placing explicit drop calls after die for
 * verifier/resource-state accounting.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;
extern void bpf_die_kfunc(void) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

char _license[] SEC("license") = "GPL";

#ifndef MAX_HELPERS
#define MAX_HELPERS 62
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} alloc_time_map SEC(".maps");

struct test_obj {
	__u64 index;
	__u64 cookie;
	__u8 padding[32];
};

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_termination_realfree(void *ctx)
{
	__u32 key = 0;
	__u64 *alloc_ns_ptr;
	__u64 alloc_start = 0;
	__u64 alloc_end = 0;
	__u64 alloc_delta = 0;
	struct test_obj *local[(MAX_HELPERS > 0) ? MAX_HELPERS : 1];
	int i;

	__builtin_memset(local, 0, sizeof(local));

	if (MAX_HELPERS > 0) {
		alloc_start = bpf_ktime_get_ns();
#pragma clang loop unroll(disable)
		for (i = 0; i < MAX_HELPERS; i++) {
			local[i] = bpf_obj_new(struct test_obj);
			if (!local[i])
				goto done_alloc;
			local[i]->index = i;
			local[i]->cookie = 0xdeadbeefULL ^ i;
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

	/*
	 * Keep explicit drop calls after die for verifier/resource-state
	 * accounting in this benchmark design.
	 */
	if (MAX_HELPERS > 0) {
#pragma clang loop unroll(disable)
		for (i = 0; i < MAX_HELPERS; i++) {
			if (local[i])
				bpf_obj_drop(local[i]);
		}
	}

	return 0;
}
