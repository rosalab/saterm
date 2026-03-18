/*
 * Worst-case verifier runtime benchmark:
 * throw-reachable global-subprog ladder with dense state in the deepest frame.
 */

#include "worstcase_common.h"

char _license[] SEC("license") = "GPL";

#ifndef LADDER_DEPTH
#define LADDER_DEPTH 8
#endif

#if LADDER_DEPTH < 1 || LADDER_DEPTH > 8
#error "LADDER_DEPTH must be in [1, 8]"
#endif

#define RT_LADDER_SET_SLOT(mask, slots, idx)                                     \
	do {                                                                    \
		(slots)[idx] = 0;                                               \
		if ((mask) & (1u << (idx)))                                     \
			(slots)[idx] = bpf_obj_new(struct worstcase_obj);       \
	} while (0)

#define RT_LADDER_ALLOC(mask, slots)                                            \
	do {                                                                    \
		RT_LADDER_SET_SLOT(mask, slots, 0);                           \
		RT_LADDER_SET_SLOT(mask, slots, 1);                           \
		RT_LADDER_SET_SLOT(mask, slots, 2);                           \
		RT_LADDER_SET_SLOT(mask, slots, 3);                           \
		RT_LADDER_SET_SLOT(mask, slots, 4);                           \
		RT_LADDER_SET_SLOT(mask, slots, 5);                           \
		RT_LADDER_SET_SLOT(mask, slots, 6);                           \
		RT_LADDER_SET_SLOT(mask, slots, 7);                           \
	} while (0)

#define RT_LADDER_DROP_SLOT(slots, idx)                                          \
	do {                                                                    \
		if ((slots)[idx])                                                \
			bpf_obj_drop((slots)[idx]);                              \
	} while (0)

#define RT_LADDER_CLEANUP(slots)                                                \
	do {                                                                    \
		RT_LADDER_DROP_SLOT(slots, 0);                                 \
		RT_LADDER_DROP_SLOT(slots, 1);                                 \
		RT_LADDER_DROP_SLOT(slots, 2);                                 \
		RT_LADDER_DROP_SLOT(slots, 3);                                 \
		RT_LADDER_DROP_SLOT(slots, 4);                                 \
		RT_LADDER_DROP_SLOT(slots, 5);                                 \
		RT_LADDER_DROP_SLOT(slots, 6);                                 \
		RT_LADDER_DROP_SLOT(slots, 7);                                 \
	} while (0)

__noinline int rt_ladder_g7(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 7;
#if LADDER_DEPTH == 8
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
	}
#endif
	return pad[0] + pad[63];
}

__noinline int rt_ladder_g6(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 6;
#if LADDER_DEPTH == 7
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
		return pad[0] + pad[63];
	}
#else
	return rt_ladder_g7(mask >> 1);
#endif
}

__noinline int rt_ladder_g5(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 5;
#if LADDER_DEPTH == 6
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
		return pad[0] + pad[63];
	}
#else
	return rt_ladder_g6(mask >> 1);
#endif
}

__noinline int rt_ladder_g4(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 4;
#if LADDER_DEPTH == 5
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
		return pad[0] + pad[63];
	}
#else
	return rt_ladder_g5(mask >> 1);
#endif
}

__noinline int rt_ladder_g3(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 3;
#if LADDER_DEPTH == 4
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
		return pad[0] + pad[63];
	}
#else
	return rt_ladder_g4(mask >> 1);
#endif
}

__noinline int rt_ladder_g2(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 2;
#if LADDER_DEPTH == 3
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
		return pad[0] + pad[63];
	}
#else
	return rt_ladder_g3(mask >> 1);
#endif
}

__noinline int rt_ladder_g1(__u32 mask)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 1;
#if LADDER_DEPTH == 2
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(mask, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
		return pad[0] + pad[63];
	}
#else
	return rt_ladder_g2(mask >> 1);
#endif
}

SEC("tc")
int rt_ladder(struct __sk_buff *ctx)
{
	volatile __u8 pad[64];

	pad[0] = 0;
	pad[63] = 0;
#if LADDER_DEPTH == 1
	{
		struct worstcase_obj *volatile slots[8];

		RT_LADDER_ALLOC(ctx->mark, slots);
		BENCH_TERMINATE();
		RT_LADDER_CLEANUP(slots);
	}
#else
	return rt_ladder_g1(ctx->mark >> 1);
#endif
	return pad[0] + pad[63];
}
