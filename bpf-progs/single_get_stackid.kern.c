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

// why not
#define PERF_MAX_STACK_DEPTH 127

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(int));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(long));
	__uint(max_entries, 10000);
} stack_traces SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_saterm_connect3(struct pt_regs *ctx)
{
	volatile long kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	return 0;
}


char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

