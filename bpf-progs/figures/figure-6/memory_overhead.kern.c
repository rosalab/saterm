/*
 * eBPF program for measuring runtime memory overhead using bpf_obj_new.
 * Attaches to: tracepoint/syscalls/sys_exit_saterm_test
 *
 * The program allocates up to target_objects objects and stores them
 * in a BPF map using kptrs so the allocations persist across invocations.
 * A cleanup mode drops all objects to reset between runs.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* For bpf_obj_new/bpf_obj_drop */
extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

char _license[] SEC("license") = "GPL";

#define MAX_OBJECTS 512

struct test_obj {
	__u64 index;
	__u64 cookie;
	__u8 padding[32];
};

struct obj_slot {
	struct test_obj __kptr *ptr;
};

struct control_args {
	__u32 target_objects;
	__u32 cleanup;
};

struct stats {
	__u32 allocated;
	__u32 failed;
	__u32 dropped;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_OBJECTS);
	__type(key, __u32);
	__type(value, struct obj_slot);
} object_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct control_args);
} control_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats);
} stats_map SEC(".maps");

struct loop_ctx {
	__u32 target_objects;
	__u32 cleanup;
};

static __always_inline void update_stats_alloc(struct stats *st, bool ok)
{
	if (ok)
		st->allocated++;
	else
		st->failed++;
}

static __always_inline void update_stats_drop(struct stats *st)
{
	st->dropped++;
}

static int handle_index(__u32 idx, void *data)
{
	__u32 zero = 0;
	struct loop_ctx *ctx = data;
	struct obj_slot *slot;
	struct stats *st;

	slot = bpf_map_lookup_elem(&object_map, &idx);
	if (!slot)
		return 0;

	st = bpf_map_lookup_elem(&stats_map, &zero);
	if (!st)
		return 0;

	if (ctx->cleanup) {
		struct test_obj *old = bpf_kptr_xchg(&slot->ptr, NULL);

		if (old) {
			bpf_obj_drop(old);
			update_stats_drop(st);
		}
		return 0;
	}

	if (idx >= ctx->target_objects)
		return 0;

	if (!slot->ptr) {
		struct test_obj *obj = bpf_obj_new(struct test_obj);
		struct test_obj *old;

		if (!obj) {
			update_stats_alloc(st, false);
			return 0;
		}

		obj->index = idx;
		obj->cookie = 0xdeadbeefULL ^ idx;

		old = bpf_kptr_xchg(&slot->ptr, obj);
		if (old)
			bpf_obj_drop(old);

		update_stats_alloc(st, old == NULL);
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_memory_overhead(void *ctx)
{
	__u32 zero = 0;
	struct control_args *ctl;
	struct stats *st;
	struct loop_ctx lctx = {};

	ctl = bpf_map_lookup_elem(&control_map, &zero);
	if (!ctl)
		return 0;

	st = bpf_map_lookup_elem(&stats_map, &zero);
	if (!st)
		return 0;

	lctx.target_objects = ctl->target_objects;
	lctx.cleanup = ctl->cleanup;

	bpf_loop(MAX_OBJECTS, handle_index, &lctx, 0);

	return 0;
}
