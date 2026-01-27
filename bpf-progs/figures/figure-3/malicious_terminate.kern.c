#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern void bpf_die_kfunc(void) __ksym;

#define MAX_LOOP_ITERS 10000

struct control_args {
    __u32 die_after;  /* counter threshold (0 = immediate) */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct control_args);
    __uint(max_entries, 1);
} control_map SEC(".maps");


SEC("tracepoint/placeholder/placeholder")
int malicious_terminate(void *ctx)
{
    __u32 key = 0;
    struct control_args *ctl = bpf_map_lookup_elem(&control_map, &key);
    __u64 sink = 0;

    if (!ctl)
        return 0;

    if (ctl->die_after == 0) {
        bpf_die_kfunc();
        return 0;
    }

    for (int i = 0; i < MAX_LOOP_ITERS; i++) {
        sink += i;
        if (ctl->die_after > 0 && (unsigned int)i + 1 >= ctl->die_after) {
            bpf_die_kfunc();
            return 0;
        }
    }

    return (int)sink;
}
