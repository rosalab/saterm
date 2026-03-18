/*
 * Worst-case verifier runtime benchmark:
 * many states funnel into a single exception PC with NULL-or-pointer slots.
 */

#include "worstcase_common.h"

char _license[] SEC("license") = "GPL";

#ifndef FANIN_SLOTS
#define FANIN_SLOTS 8
#endif

#define CLEANUP_SLOT(slots, idx)                                                \
	do {                                                                    \
		if ((slots)[idx])                                                \
			bpf_obj_drop((slots)[idx]);                              \
	} while (0)

SEC("tc")
int rt_fanin(struct __sk_buff *ctx)
{
	volatile __u8 pad[256];
	struct worstcase_obj *volatile slots[FANIN_SLOTS];
	__u32 mask = ctx->mark;
	int i;

	pad[0] = 0;
	pad[255] = 1;

#pragma clang loop unroll(full)
	for (i = 0; i < FANIN_SLOTS; i++) {
		slots[i] = 0;
		if (mask & (1u << i))
			slots[i] = bpf_obj_new(struct worstcase_obj);
	}

	BENCH_TERMINATE();

#pragma clang loop unroll(full)
	for (i = 0; i < FANIN_SLOTS; i++)
		CLEANUP_SLOT(slots, i);

	return pad[0] + pad[255];
}
