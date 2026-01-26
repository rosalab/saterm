/*
 * BPF program for termination latency testing - baseline mode
 * Attaches to: tracepoint/syscalls/sys_exit_saterm_test
 * 
 * Baseline: No termination at all, just overhead work
 * 
 * This version allocates resources to match other test versions.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* For bpf_obj_new/bpf_obj_drop */
extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

char _license[] SEC("license") = "GPL";

/* Simple struct for resource allocation testing */
struct test_obj {
	int value;
	__u64 data;
};

/* Control map - not used for baseline but kept for compatibility */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} control_map SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int trace_saterm_exit(void *ctx)
{
	struct test_obj *objs[50] = {};
	int i;
	__u32 key = 0;
	volatile __u64 dummy = 0;

	/* Allocate resources to match other test versions */
	for (i = 0; i < 50; i++) {
		objs[i] = bpf_obj_new(typeof(*objs[0]));
		if (!objs[i]) {
			/* If allocation fails, clean up and exit */
			goto cleanup;
		}
		
		/* Do some work with the allocated object */
		objs[i]->value = i;
		objs[i]->data = i * 1000;
		dummy += objs[i]->data;

		bpf_printk("iter: %d, dummy: %llu", i, dummy);
	}
	
	/* No termination - just complete normally and clean up */
	
cleanup:
	for (i = 0; i < 50; i++) {
		if (objs[i]) {
			bpf_obj_drop(objs[i]);
		}
	}
	
	return 0;
}


