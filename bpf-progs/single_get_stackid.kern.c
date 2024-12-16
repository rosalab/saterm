//#include <linux/ptrace.h>
//#include <linux/version.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif

// default is 127 i believe
//#undef PERF_MAX_STACK_DEPTH
//#define PERF_MAX_STACK_DEPTH 4096
//#define PERF_MAX_STACK_DEPTH (128*2 - 1)
//#define PERF_MAX_STACK_DEPTH 127
//#define PERF_MAX_STACK_DEPTH 127 

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(int));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(long));
	__uint(max_entries, 100);
} stack_traces SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_saterm_connect4(struct pt_regs *ctx)
{
	int start_time = bpf_ktime_get_ns();
	volatile long kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	volatile long user_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_USER_STACK);
	int end_time = bpf_ktime_get_ns();
	bpf_printk("Time stack_id: %d\n", end_time - start_time);
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

