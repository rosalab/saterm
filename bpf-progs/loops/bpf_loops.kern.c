#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#define ITERS 1 << 5

// This isn't needed for the kern program but for the user
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

int callback_selector;
int callback_selector2;

static int loops1(void);
static int loops2(void);
static int loops3(void);
static int loops4(void);
static int loops5(void);

static int loops5(void) 
{
	bpf_printk("Calling bpf_loops5 function");
	return 0;
}

static int loops4(void) 
{
	bpf_printk("Calling bpf_loop4 function");
	return 0;
}

static int loops3(void)
{
	//bpf_printk("Calling bpf_loop3 function");
	int (*callback)(void);
	if (callback_selector == 0xF)
		callback = loops5;
	else
		callback = loops4;

	bpf_loop(ITERS, callback, NULL, 0);
	return 0;
}

static int loops2(void)
{
	//bpf_printk("Calling bpf_loop2 function");

	int (*callback)(void);
	if (callback_selector == 0)
		callback = loops1;
	else
		callback = loops3;

	bpf_loop(ITERS, callback, NULL, 0);

	return 0;
}

static int loops1(void)
{

	//bpf_printk("Calling bpf_loop1 function");

	int (*callback)(void);
	if (callback_selector2 == 0)
		callback = loops3;
	else
		callback = loops4;

	bpf_loop(ITERS, callback, NULL, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_saterm(struct pt_regs *ctx)
{
	
	int (*callback)(void);

	if (callback_selector == 0x0F)
		callback = loops1;
	else
		callback = loops2;

	bpf_loop(ITERS, callback, NULL, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
