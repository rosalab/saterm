//#include <linux/ptrace.h>
//#include <linux/version.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif

#define MAX_DICT_SIZE 1000 
#define MAX_DICT_VAL  10000

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DICT_SIZE);
    __type(key, int);
    __type(value, int);
} 
my_map SEC(".maps");

void map_access()
{
	int k = bpf_get_prandom_u32() % MAX_DICT_SIZE;
	int v = bpf_get_prandom_u32() % MAX_DICT_VAL;
	bpf_map_update_elem(&my_map, &k, &v, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_saterm_connect1(struct pt_regs *ctx)
{
	// TODO: this should be like Listing 1
	map_access();
	return 0;
}


char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

