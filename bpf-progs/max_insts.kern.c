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


SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_saterm_connect3(struct pt_regs *ctx)
{
	int start_time = bpf_ktime_get_ns();

	volatile int z = 0;
	for(int i = 0; i < 100000; i++){
		z++;
	}

	int end_time = bpf_ktime_get_ns();
	bpf_printk("Time max_insts: %d\n", end_time - start_time);
	return 0;
}


char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

