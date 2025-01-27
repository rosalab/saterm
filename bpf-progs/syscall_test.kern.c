 #include <linux/bpf.h>
 #include <linux/types.h>
 #include <linux/version.h>
 #include <bpf/bpf_helpers.h>

 char _license[] SEC("license") = "GPL";

 //10 without spin lock
 #define ITERS 1 << 10

 static int simple()
 {
 	//bpf_printk("Hello world ;)\n");
 	return 0;
 }


 static int loop3()
 {
 	bpf_loop(ITERS, simple, NULL, 0);
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

 struct hmap_elem {
 	struct bpf_spin_lock lock;
     int cnt;
 };

 struct {
 	__uint(type, BPF_MAP_TYPE_HASH);
 	__uint(max_entries, 1);
 	__type(key, int);
 	__type(value, struct hmap_elem);
 } hmap SEC(".maps");

 SEC("tracepoint/syscalls/sys_exit_saterm_test")
 int tracepoint_exit_saterm_connect1(struct pt_regs *ctx)
 {
 	bpf_printk("sys_exit_saterm_test: triggered syscall\n");
     struct hmap_elem zero = {}, *val;
     int key = 0;
     val = bpf_map_lookup_elem(&hmap, &key);
     if (!val) {
         bpf_map_update_elem(&hmap, &key, &zero, 0);
 		val = bpf_map_lookup_elem(&hmap, &key);
 		if (!val) {
 			return 0;
 		}
     }

     bpf_spin_lock(&val->lock);
     loop1();
     //start timer here?
 	//bpf_get_numa_node_id();
 	__u64 start = bpf_ktime_get_ns();
 	bpf_printk("Donia- Release function starts at time : %ld\n", start);
     val->cnt++;
    bpf_spin_unlock(&val->lock);

    bpf_printk("sys_exit_saterm_test: cnt val %d\n", val->cnt);


 	return 0;
 }
// #include <linux/ptrace.h>
// #include <linux/version.h>
// #include <linux/bpf.h>
// #include <linux/in6.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// #include "trace_common.h"

//#include <linux/bpf.h>
//#include <linux/types.h>
//#include <linux/version.h>
//#include <bpf/bpf_helpers.h>
//
//#if defined(CONFIG_FUNCTION_TRACER)
//#define CC_USING_FENTRY
//#endif
//
//static int cbck(void* ctx)
//{
//	return 	bpf_get_smp_processor_id()%2;
//}
//
////SEC("tracepoint/syscalls/sys_exit_hello")
//SEC("tracepoint/syscalls/sys_exit_connect")
//int trace_sys_connect1(struct pt_regs *ctx)
//{
//	    bpf_printk("Inside trace_sys_connect\n");
//    	bpf_printk("processor id: %d\n", bpf_get_smp_processor_id());
//    	u32 iter = (1<<2);
//    	bpf_printk("Loop iteration count: %dk\n",iter);
//    	bpf_loop(iter, cbck, NULL,0);
//    	int unique_id = bpf_test_acquire();
//    	bpf_printk("Add timer logs here");
//    	bpf_test_release(unique_id);
//	return 0;
//}
//char _license[] SEC("license") = "GPL";
//int _version SEC("version") = LINUX_VERSION_CODE;
