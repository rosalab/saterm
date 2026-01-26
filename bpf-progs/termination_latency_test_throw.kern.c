/*
 * BPF program for termination latency testing - bpf_throw mode
 * Attaches to: tracepoint/syscalls/sys_exit_saterm_test
 * 
 * For use on the bpf_throw branch.
 * Termination: Check control_map and call bpf_throw()
 * 
 * This version allocates resources to test cleanup on termination.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Declaration for bpf_throw kfunc */
extern void bpf_throw(__u64 cookie) __ksym;

/* For bpf_obj_new/bpf_obj_drop */
extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

char _license[] SEC("license") = "GPL";

/* Control map - write 1 to trigger bpf_throw */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} control_map SEC(".maps");

// __u32 key = 0;
// __u64 *control;

int only_count = 0;
int res_count = 0;

#define MAX_ENTRIES 20

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int trace_saterm_exit(void *ctx)
{
    struct { int i; } *f[MAX_ENTRIES] = {};
    int i;
 
    only_count = 1;
 
    for (i = 0; i < MAX_ENTRIES; i++) {
        f[i] = bpf_obj_new(typeof(*f[0]));
        if (!f[i])
            goto end;
        res_count++;

        /* Check control_map and throw if triggered */
		// control = bpf_map_lookup_elem(&control_map, &key);
		// if (control && *control == 1) {
		// 	bpf_throw(0);
		// }

		if (i == MAX_ENTRIES - 1) {
			bpf_throw(0);
		}
    }
end:
    for (i = 0; i < MAX_ENTRIES; i++) {
        if (!f[i])
            continue;
        bpf_obj_drop(f[i]);
    }
    return 0;

}