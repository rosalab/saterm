#ifndef FIGURE8_WORSTCASE_COMMON_H
#define FIGURE8_WORSTCASE_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;
extern void bpf_throw(__u64 cookie) __ksym;
extern void bpf_die_kfunc(void) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

#if defined(BENCH_VARIANT_SATERM) && defined(BENCH_VARIANT_KFLEX)
#error "Select only one benchmark variant"
#endif

#if !defined(BENCH_VARIANT_SATERM) && !defined(BENCH_VARIANT_KFLEX)
#define BENCH_VARIANT_SATERM
#endif

#ifdef BENCH_VARIANT_SATERM
#define BENCH_TERMINATE() bpf_die_kfunc()
#else
#define BENCH_TERMINATE() bpf_throw(0)
#endif

#define BENCH_FORCE_STACK_PTR(ptr) asm volatile("" : "+r"(ptr) : : "memory")

struct worstcase_obj {
	__u64 index;
	__u64 cookie;
	__u8 padding[32];
};

#endif
