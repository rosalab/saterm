#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LISENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} ar SEC(".maps");


/**
 * Counter program that traces the number of times this
 * hookpoint has been hit
 */
SEC("tp/syscalls/sys_enter_getcwd")
// SEC("tracepoint/syscalls/sys_exit_saterm_test")
int array(void *ctx)
{
    __u32 key = 0;
    __u32 * val = bpf_map_lookup_elem(&ar, &key);
    if (!val) {
        return -1;
    } else {
        __u32 new = (*val) + 1;
        bpf_map_update_elem(&ar, &key, &new, BPF_ANY);
    }
    return 0;
}
