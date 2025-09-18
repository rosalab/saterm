#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LISENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int empty(void *ctx)
{
    return 0;
}
