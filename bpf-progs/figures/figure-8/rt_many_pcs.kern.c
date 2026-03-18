/*
 * Worst-case verifier runtime benchmark:
 * one subprog with many distinct exception PCs, each with a dense stack shape.
 */

#include "worstcase_common.h"

char _license[] SEC("license") = "GPL";

#ifndef THROW_PCS
#define THROW_PCS 56
#endif

#if THROW_PCS < 1 || THROW_PCS > 64
#error "THROW_PCS must be in [1, 64]"
#endif

#define ZERO_SLOTS16(slots)                                                     \
	do {                                                                    \
		(slots)[0] = 0;                                                 \
		(slots)[1] = 0;                                                 \
		(slots)[2] = 0;                                                 \
		(slots)[3] = 0;                                                 \
		(slots)[4] = 0;                                                 \
		(slots)[5] = 0;                                                 \
		(slots)[6] = 0;                                                 \
		(slots)[7] = 0;                                                 \
		(slots)[8] = 0;                                                 \
		(slots)[9] = 0;                                                 \
		(slots)[10] = 0;                                                \
		(slots)[11] = 0;                                                \
		(slots)[12] = 0;                                                \
		(slots)[13] = 0;                                                \
		(slots)[14] = 0;                                                \
		(slots)[15] = 0;                                                \
	} while (0)

#define SITE_MASK_BIT(mask_lo, mask_hi, idx)                                     \
	(((idx) < 32) ? ((mask_lo) & (1u << (idx)))                            \
		     : ((mask_hi) & (1u << ((idx) - 32))))

#define THROW_BLOCK(I)                                                           \
	do {                                                                    \
		pad[0] = 0;                                                     \
		pad[127] = (I);                                                 \
		ZERO_SLOTS16(slots);                                            \
		if (SITE_MASK_BIT(alloc_mask_lo, alloc_mask_hi, (I)))           \
			slots[(I) & 15] = bpf_obj_new(struct worstcase_obj);    \
		if (SITE_MASK_BIT(throw_mask_lo, throw_mask_hi, (I)))           \
			BENCH_TERMINATE();                                      \
		if (slots[(I) & 15])                                            \
			bpf_obj_drop(slots[(I) & 15]);                         \
	} while (0)

SEC("tc")
int rt_many_pcs(struct __sk_buff *ctx)
{
	volatile __u8 pad[128];
	struct worstcase_obj *volatile slots[16];
	/* Keep sites 32..63 distinct instead of aliasing the lower-half bits. */
	__u32 alloc_mask_lo = ctx->mark;
	__u32 alloc_mask_hi = ctx->priority;
	__u32 throw_mask_lo = ctx->len;
	__u32 throw_mask_hi = ctx->ifindex;

#if THROW_PCS > 0
	THROW_BLOCK(0);
#endif
#if THROW_PCS > 1
	THROW_BLOCK(1);
#endif
#if THROW_PCS > 2
	THROW_BLOCK(2);
#endif
#if THROW_PCS > 3
	THROW_BLOCK(3);
#endif
#if THROW_PCS > 4
	THROW_BLOCK(4);
#endif
#if THROW_PCS > 5
	THROW_BLOCK(5);
#endif
#if THROW_PCS > 6
	THROW_BLOCK(6);
#endif
#if THROW_PCS > 7
	THROW_BLOCK(7);
#endif
#if THROW_PCS > 8
	THROW_BLOCK(8);
#endif
#if THROW_PCS > 9
	THROW_BLOCK(9);
#endif
#if THROW_PCS > 10
	THROW_BLOCK(10);
#endif
#if THROW_PCS > 11
	THROW_BLOCK(11);
#endif
#if THROW_PCS > 12
	THROW_BLOCK(12);
#endif
#if THROW_PCS > 13
	THROW_BLOCK(13);
#endif
#if THROW_PCS > 14
	THROW_BLOCK(14);
#endif
#if THROW_PCS > 15
	THROW_BLOCK(15);
#endif
#if THROW_PCS > 16
	THROW_BLOCK(16);
#endif
#if THROW_PCS > 17
	THROW_BLOCK(17);
#endif
#if THROW_PCS > 18
	THROW_BLOCK(18);
#endif
#if THROW_PCS > 19
	THROW_BLOCK(19);
#endif
#if THROW_PCS > 20
	THROW_BLOCK(20);
#endif
#if THROW_PCS > 21
	THROW_BLOCK(21);
#endif
#if THROW_PCS > 22
	THROW_BLOCK(22);
#endif
#if THROW_PCS > 23
	THROW_BLOCK(23);
#endif
#if THROW_PCS > 24
	THROW_BLOCK(24);
#endif
#if THROW_PCS > 25
	THROW_BLOCK(25);
#endif
#if THROW_PCS > 26
	THROW_BLOCK(26);
#endif
#if THROW_PCS > 27
	THROW_BLOCK(27);
#endif
#if THROW_PCS > 28
	THROW_BLOCK(28);
#endif
#if THROW_PCS > 29
	THROW_BLOCK(29);
#endif
#if THROW_PCS > 30
	THROW_BLOCK(30);
#endif
#if THROW_PCS > 31
	THROW_BLOCK(31);
#endif
#if THROW_PCS > 32
	THROW_BLOCK(32);
#endif
#if THROW_PCS > 33
	THROW_BLOCK(33);
#endif
#if THROW_PCS > 34
	THROW_BLOCK(34);
#endif
#if THROW_PCS > 35
	THROW_BLOCK(35);
#endif
#if THROW_PCS > 36
	THROW_BLOCK(36);
#endif
#if THROW_PCS > 37
	THROW_BLOCK(37);
#endif
#if THROW_PCS > 38
	THROW_BLOCK(38);
#endif
#if THROW_PCS > 39
	THROW_BLOCK(39);
#endif
#if THROW_PCS > 40
	THROW_BLOCK(40);
#endif
#if THROW_PCS > 41
	THROW_BLOCK(41);
#endif
#if THROW_PCS > 42
	THROW_BLOCK(42);
#endif
#if THROW_PCS > 43
	THROW_BLOCK(43);
#endif
#if THROW_PCS > 44
	THROW_BLOCK(44);
#endif
#if THROW_PCS > 45
	THROW_BLOCK(45);
#endif
#if THROW_PCS > 46
	THROW_BLOCK(46);
#endif
#if THROW_PCS > 47
	THROW_BLOCK(47);
#endif
#if THROW_PCS > 48
	THROW_BLOCK(48);
#endif
#if THROW_PCS > 49
	THROW_BLOCK(49);
#endif
#if THROW_PCS > 50
	THROW_BLOCK(50);
#endif
#if THROW_PCS > 51
	THROW_BLOCK(51);
#endif
#if THROW_PCS > 52
	THROW_BLOCK(52);
#endif
#if THROW_PCS > 53
	THROW_BLOCK(53);
#endif
#if THROW_PCS > 54
	THROW_BLOCK(54);
#endif
#if THROW_PCS > 55
	THROW_BLOCK(55);
#endif
#if THROW_PCS > 56
	THROW_BLOCK(56);
#endif
#if THROW_PCS > 57
	THROW_BLOCK(57);
#endif
#if THROW_PCS > 58
	THROW_BLOCK(58);
#endif
#if THROW_PCS > 59
	THROW_BLOCK(59);
#endif
#if THROW_PCS > 60
	THROW_BLOCK(60);
#endif
#if THROW_PCS > 61
	THROW_BLOCK(61);
#endif
#if THROW_PCS > 62
	THROW_BLOCK(62);
#endif
#if THROW_PCS > 63
	THROW_BLOCK(63);
#endif

	return 0;
}
