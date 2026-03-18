#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern void bpf_throw(__u64 cookie) __ksym;

/*
 * Verifier's loop-jump complexity limit is 8193 jumps. With a block-unrolled
 * loop, keep LOOP_UNROLL * 8192 as the max useful workload ceiling.
 */
#define LOOP_UNROLL 128
#define BUDGET_CHECK_BLOCKS 8
#define MAX_WORK_ITERS (LOOP_UNROLL * 8192)
#define MAX_WORK_BLOCKS (MAX_WORK_ITERS / LOOP_UNROLL)
#define MODE_NO_TERMINATION 0
#define MODE_TERM_IMMEDIATE 1
#define MODE_TERM_BUDGETED 2

struct control_args {
    __u32 work_iters;
    __u32 mode;
    __u64 time_limit_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct control_args);
    __uint(max_entries, 1);
} control_map SEC(".maps");

struct termination_stats {
    __u64 hits;
    __u64 total_elapsed_ns;
    __u64 total_completed_work_iters;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct termination_stats);
    __uint(max_entries, 1);
} termination_stats_map SEC(".maps");

#define ADD8(base)            \
    do {                      \
        sink += (base) + 0;   \
        sink += (base) + 1;   \
        sink += (base) + 2;   \
        sink += (base) + 3;   \
        sink += (base) + 4;   \
        sink += (base) + 5;   \
        sink += (base) + 6;   \
        sink += (base) + 7;   \
    } while (0)

#define RUN_WORK_BLOCK(base)  \
    do {                      \
        ADD8((base) + 0);     \
        ADD8((base) + 8);     \
        ADD8((base) + 16);    \
        ADD8((base) + 24);    \
        ADD8((base) + 32);    \
        ADD8((base) + 40);    \
        ADD8((base) + 48);    \
        ADD8((base) + 56);    \
        ADD8((base) + 64);    \
        ADD8((base) + 72);    \
        ADD8((base) + 80);    \
        ADD8((base) + 88);    \
        ADD8((base) + 96);    \
        ADD8((base) + 104);   \
        ADD8((base) + 112);   \
        ADD8((base) + 120);   \
    } while (0)

static __always_inline void record_termination_stats(__u64 start_ns,
                                                     __u32 completed_work_iters)
{
    __u32 key = 0;
    struct termination_stats *stats;

    stats = bpf_map_lookup_elem(&termination_stats_map, &key);
    if (!stats)
        return;

    stats->hits += 1;
    stats->total_elapsed_ns += bpf_ktime_get_ns() - start_ns;
    stats->total_completed_work_iters += completed_work_iters;
}

static __always_inline int throw_with_stats(__u64 start_ns,
                                            __u32 completed_work_iters)
{
    record_termination_stats(start_ns, completed_work_iters);
    bpf_throw(0);
    return 0;
}

SEC("tracepoint/placeholder/placeholder")
int malicious_terminate(void *ctx)
{
    __u32 key = 0;
    struct control_args *ctl = bpf_map_lookup_elem(&control_map, &key);
    __u32 work_iters;
    __u64 sink = 0;
    __u64 start_ns;
    __u64 deadline_ns;

    if (!ctl)
        return 0;

    if (ctl->mode == MODE_TERM_IMMEDIATE) {
        start_ns = bpf_ktime_get_ns();
        /*
         * Exit the current invocation immediately, while leaving the loaded
         * program intact so subsequent invocations still start fresh.
         */
        for (int i = 0; i < MAX_WORK_ITERS; i += LOOP_UNROLL) {
            return throw_with_stats(start_ns, 0);
        }
    }

    if (ctl->mode == MODE_TERM_BUDGETED) {
        __u32 work_blocks;
        __u32 full_groups;
        __u32 tail_blocks;
        __u32 completed_work_iters = 0;
        __u32 group;
        __u32 base;

        work_iters = ctl->work_iters;
        if (work_iters > MAX_WORK_ITERS)
            work_iters = MAX_WORK_ITERS;

        work_blocks = work_iters / LOOP_UNROLL;
        full_groups = work_blocks / BUDGET_CHECK_BLOCKS;
        tail_blocks = work_blocks % BUDGET_CHECK_BLOCKS;
        if (full_groups > (MAX_WORK_BLOCKS / BUDGET_CHECK_BLOCKS))
            full_groups = MAX_WORK_BLOCKS / BUDGET_CHECK_BLOCKS;
        start_ns = bpf_ktime_get_ns();
        deadline_ns = start_ns + ctl->time_limit_ns;

        for (group = 0; group < full_groups; group++) {
            base = group * LOOP_UNROLL * BUDGET_CHECK_BLOCKS;
            RUN_WORK_BLOCK(base + (0 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (1 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (2 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (3 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (4 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (5 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (6 * LOOP_UNROLL));
            RUN_WORK_BLOCK(base + (7 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL * BUDGET_CHECK_BLOCKS;

            /*
             * Check the deadline after each fixed work group so a non-zero
             * workload always executes meaningful work before termination,
             * while amortizing time-helper overhead across more work.
             */
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
        }

        base = full_groups * LOOP_UNROLL * BUDGET_CHECK_BLOCKS;
        switch (tail_blocks) {
        case 7:
            RUN_WORK_BLOCK(base + (6 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            /* fall through */
        case 6:
            RUN_WORK_BLOCK(base + (5 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            /* fall through */
        case 5:
            RUN_WORK_BLOCK(base + (4 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            /* fall through */
        case 4:
            RUN_WORK_BLOCK(base + (3 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            /* fall through */
        case 3:
            RUN_WORK_BLOCK(base + (2 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            /* fall through */
        case 2:
            RUN_WORK_BLOCK(base + (1 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            /* fall through */
        case 1:
            RUN_WORK_BLOCK(base + (0 * LOOP_UNROLL));
            completed_work_iters += LOOP_UNROLL;
            if (bpf_ktime_get_ns() >= deadline_ns)
                return throw_with_stats(start_ns, completed_work_iters);
            break;
        default:
            break;
        }

        return (int)sink;
    }

    if (ctl->mode != MODE_NO_TERMINATION)
        return 0;

    work_iters = ctl->work_iters;
    if (work_iters > MAX_WORK_ITERS)
        work_iters = MAX_WORK_ITERS;

    for (int i = 0; i < MAX_WORK_ITERS; i += LOOP_UNROLL) {
        if ((__u32)(i + LOOP_UNROLL) > work_iters)
            return (int)sink;

        RUN_WORK_BLOCK(i);
    }

    return (int)sink;
}
