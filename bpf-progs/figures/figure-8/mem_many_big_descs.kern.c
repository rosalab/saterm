/*
 * Worst-case verifier memory benchmark:
 * many unique exception PCs sharing the same near-max frame shape.
 */

#include "worstcase_common.h"

char _license[] SEC("license") = "GPL";

#ifndef DESC_PCS
#define DESC_PCS 32
#endif

#if DESC_PCS < 1 || DESC_PCS > 64
#error "DESC_PCS must be in [1, 64]"
#endif

#define SITE_MASK_BIT(mask_lo, mask_hi, idx)                                     \
	(((idx) < 32) ? ((mask_lo) & (1u << (idx)))                            \
		     : ((mask_hi) & (1u << ((idx) - 32))))

#define DESC_THROW_SITE(I)                                                       \
	do {                                                                    \
		if (SITE_MASK_BIT(mask_lo, mask_hi, (I)))                       \
			BENCH_TERMINATE();                                      \
	} while (0)

SEC("tc")
int mem_many_big_descs(struct __sk_buff *ctx)
{
	volatile __u8 pad[504];
	/* Keep throw predicates unique through all 64 sites. */
	__u32 mask_lo = ctx->mark;
	__u32 mask_hi = ctx->priority;
	volatile __u8 *p = pad;

	BENCH_FORCE_STACK_PTR(p);
	p[0] = 0;
	p[503] = (__u8)ctx->len;
#if DESC_PCS > 0
	DESC_THROW_SITE(0);
#endif
#if DESC_PCS > 1
	DESC_THROW_SITE(1);
#endif
#if DESC_PCS > 2
	DESC_THROW_SITE(2);
#endif
#if DESC_PCS > 3
	DESC_THROW_SITE(3);
#endif
#if DESC_PCS > 4
	DESC_THROW_SITE(4);
#endif
#if DESC_PCS > 5
	DESC_THROW_SITE(5);
#endif
#if DESC_PCS > 6
	DESC_THROW_SITE(6);
#endif
#if DESC_PCS > 7
	DESC_THROW_SITE(7);
#endif
#if DESC_PCS > 8
	DESC_THROW_SITE(8);
#endif
#if DESC_PCS > 9
	DESC_THROW_SITE(9);
#endif
#if DESC_PCS > 10
	DESC_THROW_SITE(10);
#endif
#if DESC_PCS > 11
	DESC_THROW_SITE(11);
#endif
#if DESC_PCS > 12
	DESC_THROW_SITE(12);
#endif
#if DESC_PCS > 13
	DESC_THROW_SITE(13);
#endif
#if DESC_PCS > 14
	DESC_THROW_SITE(14);
#endif
#if DESC_PCS > 15
	DESC_THROW_SITE(15);
#endif
#if DESC_PCS > 16
	DESC_THROW_SITE(16);
#endif
#if DESC_PCS > 17
	DESC_THROW_SITE(17);
#endif
#if DESC_PCS > 18
	DESC_THROW_SITE(18);
#endif
#if DESC_PCS > 19
	DESC_THROW_SITE(19);
#endif
#if DESC_PCS > 20
	DESC_THROW_SITE(20);
#endif
#if DESC_PCS > 21
	DESC_THROW_SITE(21);
#endif
#if DESC_PCS > 22
	DESC_THROW_SITE(22);
#endif
#if DESC_PCS > 23
	DESC_THROW_SITE(23);
#endif
#if DESC_PCS > 24
	DESC_THROW_SITE(24);
#endif
#if DESC_PCS > 25
	DESC_THROW_SITE(25);
#endif
#if DESC_PCS > 26
	DESC_THROW_SITE(26);
#endif
#if DESC_PCS > 27
	DESC_THROW_SITE(27);
#endif
#if DESC_PCS > 28
	DESC_THROW_SITE(28);
#endif
#if DESC_PCS > 29
	DESC_THROW_SITE(29);
#endif
#if DESC_PCS > 30
	DESC_THROW_SITE(30);
#endif
#if DESC_PCS > 31
	DESC_THROW_SITE(31);
#endif
#if DESC_PCS > 32
	DESC_THROW_SITE(32);
#endif
#if DESC_PCS > 33
	DESC_THROW_SITE(33);
#endif
#if DESC_PCS > 34
	DESC_THROW_SITE(34);
#endif
#if DESC_PCS > 35
	DESC_THROW_SITE(35);
#endif
#if DESC_PCS > 36
	DESC_THROW_SITE(36);
#endif
#if DESC_PCS > 37
	DESC_THROW_SITE(37);
#endif
#if DESC_PCS > 38
	DESC_THROW_SITE(38);
#endif
#if DESC_PCS > 39
	DESC_THROW_SITE(39);
#endif
#if DESC_PCS > 40
	DESC_THROW_SITE(40);
#endif
#if DESC_PCS > 41
	DESC_THROW_SITE(41);
#endif
#if DESC_PCS > 42
	DESC_THROW_SITE(42);
#endif
#if DESC_PCS > 43
	DESC_THROW_SITE(43);
#endif
#if DESC_PCS > 44
	DESC_THROW_SITE(44);
#endif
#if DESC_PCS > 45
	DESC_THROW_SITE(45);
#endif
#if DESC_PCS > 46
	DESC_THROW_SITE(46);
#endif
#if DESC_PCS > 47
	DESC_THROW_SITE(47);
#endif
#if DESC_PCS > 48
	DESC_THROW_SITE(48);
#endif
#if DESC_PCS > 49
	DESC_THROW_SITE(49);
#endif
#if DESC_PCS > 50
	DESC_THROW_SITE(50);
#endif
#if DESC_PCS > 51
	DESC_THROW_SITE(51);
#endif
#if DESC_PCS > 52
	DESC_THROW_SITE(52);
#endif
#if DESC_PCS > 53
	DESC_THROW_SITE(53);
#endif
#if DESC_PCS > 54
	DESC_THROW_SITE(54);
#endif
#if DESC_PCS > 55
	DESC_THROW_SITE(55);
#endif
#if DESC_PCS > 56
	DESC_THROW_SITE(56);
#endif
#if DESC_PCS > 57
	DESC_THROW_SITE(57);
#endif
#if DESC_PCS > 58
	DESC_THROW_SITE(58);
#endif
#if DESC_PCS > 59
	DESC_THROW_SITE(59);
#endif
#if DESC_PCS > 60
	DESC_THROW_SITE(60);
#endif
#if DESC_PCS > 61
	DESC_THROW_SITE(61);
#endif
#if DESC_PCS > 62
	DESC_THROW_SITE(62);
#endif
#if DESC_PCS > 63
	DESC_THROW_SITE(63);
#endif

	return p[0] + p[503];
}
