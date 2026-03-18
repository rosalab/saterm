/*
 * Worst-case verifier memory benchmark:
 * one near-max frame shape to inflate a single descriptor's stack array.
 */

#include "worstcase_common.h"

char _license[] SEC("license") = "GPL";

#ifndef FRAME_BYTES
#define FRAME_BYTES 504
#endif

#if FRAME_BYTES < 1 || FRAME_BYTES > 504
#error "FRAME_BYTES must be in [1, 504]"
#endif

SEC("tc")
int mem_big_single_desc(struct __sk_buff *ctx)
{
	volatile __u8 pad[FRAME_BYTES];
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[FRAME_BYTES - 1] = (__u8)ctx->len;

	BENCH_TERMINATE();
	return p[0] + p[FRAME_BYTES - 1];
}
