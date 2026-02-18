/*
 * Figure-8 object sweep benchmark (saterm variant).
 *
 * Allocates MAX_LOCAL_OBJS local objects and then terminates with
 * bpf_die_kfunc() while references are still live.
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

#ifndef MAX_LOCAL_OBJS
#define MAX_LOCAL_OBJS 62
#endif

struct test_obj {
	__u64 index;
	__u64 cookie;
	__u8 padding[32];
};

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int objects_die_sample(void *ctx)
{
#if MAX_LOCAL_OBJS > 0
	struct test_obj *local[MAX_LOCAL_OBJS];
	int i;

	__builtin_memset(local, 0, sizeof(local));

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_LOCAL_OBJS; i++) {
		local[i] = bpf_obj_new(struct test_obj);
		if (!local[i])
			goto cleanup;
		local[i]->index = i;
		local[i]->cookie = 0xdeadbeefULL ^ i;
	}
#endif

	bpf_die_kfunc();

#if MAX_LOCAL_OBJS > 0
cleanup:
#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_LOCAL_OBJS; i++) {
		if (local[i])
			bpf_obj_drop(local[i]);
	}
#endif
	return 0;
}
