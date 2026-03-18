/*
 * Figure-8 branch sweep benchmark (saterm variant).
 *
 * This program increases branch-work as MAX_BRANCHES increases by executing
 * a bounded loop with one conditional branch per iteration. Each branch arm
 * allocates and drops its own local object before the program terminates via
 * bpf_die_kfunc().
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

#ifndef MAX_BRANCHES
#define MAX_BRANCHES 10
#endif

struct test_obj {
	__u64 index;
	__u64 cookie;
	__u8 padding[32];
};

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int branch_die_sample(void *ctx)
{
	__u64 result = 0;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_BRANCHES; i++) {
		__u32 rnd = bpf_get_prandom_u32();

		if (rnd & 1) {
			struct test_obj *left = bpf_obj_new(struct test_obj);

			if (!left)
				goto out;
			left->index = i;
			left->cookie = 0xdeadbeefULL ^ ((__u64)i << 1);
			result += left->index + (left->cookie & 1);
			bpf_obj_drop(left);
		} else {
			struct test_obj *right = bpf_obj_new(struct test_obj);

			if (!right)
				goto out;
			right->index = i;
			right->cookie = 0xcafef00dULL ^ ((__u64)i << 1);
			result -= right->index + (right->cookie & 1);
			bpf_obj_drop(right);
		}
	}

out:
	bpf_die_kfunc();
	return (int)result;
}
