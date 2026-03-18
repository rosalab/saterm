/*
 * Worst-case verifier memory benchmark:
 * near-max frame size replicated across the full global-subprog call chain.
 */

#include "worstcase_common.h"

char _license[] SEC("license") = "GPL";

#ifndef FRAME_DEPTH
#define FRAME_DEPTH 8
#endif

#if FRAME_DEPTH < 1 || FRAME_DEPTH > 8
#error "FRAME_DEPTH must be in [1, 8]"
#endif

#define DEEP_FRAME_BYTES 56

__noinline int mem_deep_ladder_g7(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 7;
#if FRAME_DEPTH == 8
	BENCH_TERMINATE();
#endif
	return p[0] + p[DEEP_FRAME_BYTES - 1];
}

__noinline int mem_deep_ladder_g6(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 6;
#if FRAME_DEPTH == 7
	BENCH_TERMINATE();
	return 6;
#else
	return mem_deep_ladder_g7();
#endif
}

__noinline int mem_deep_ladder_g5(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 5;
#if FRAME_DEPTH == 6
	BENCH_TERMINATE();
	return 5;
#else
	return mem_deep_ladder_g6();
#endif
}

__noinline int mem_deep_ladder_g4(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 4;
#if FRAME_DEPTH == 5
	BENCH_TERMINATE();
	return 4;
#else
	return mem_deep_ladder_g5();
#endif
}

__noinline int mem_deep_ladder_g3(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 3;
#if FRAME_DEPTH == 4
	BENCH_TERMINATE();
	return 3;
#else
	return mem_deep_ladder_g4();
#endif
}

__noinline int mem_deep_ladder_g2(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 2;
#if FRAME_DEPTH == 3
	BENCH_TERMINATE();
	return 2;
#else
	return mem_deep_ladder_g3();
#endif
}

__noinline int mem_deep_ladder_g1(void)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = 1;
#if FRAME_DEPTH == 2
	BENCH_TERMINATE();
	return 1;
#else
	return mem_deep_ladder_g2();
#endif
}

SEC("tc")
int mem_deep_ladder(struct __sk_buff *ctx)
{
	volatile __u8 pad[DEEP_FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[DEEP_FRAME_BYTES - 1] = (__u8)ctx->len;
#if FRAME_DEPTH == 1
	BENCH_TERMINATE();
	return p[0] + p[DEEP_FRAME_BYTES - 1];
#else
	return mem_deep_ladder_g1();
#endif
}
