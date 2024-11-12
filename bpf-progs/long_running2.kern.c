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

#define ITERS 1 << 23

static int simple()
{
	bpf_printk("Hello world ;)\n");
	return 0;
}

static int loop4()
{
	bpf_loop(ITERS, simple, NULL, 0);
	return 0;
}

static int loop3()
{
	bpf_loop(ITERS, loop4, NULL, 0);
	return 0;
}

static int loop2()
{
	bpf_loop(ITERS, loop3, NULL, 0);
	return 0;
}

static int loop1()
{
	bpf_loop(ITERS, loop2, NULL, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_saterm_connect2(struct pt_regs *ctx)
{
	loop1();
	return 0;
}


char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

