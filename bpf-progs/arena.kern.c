#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LISENSE[] SEC("license") = "Dual BSD/GPL";

int size;
void *arena_ptr;

#ifndef __arena
# define __arena __attribute__((address_space(1)))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* number of pages */
} arena SEC(".maps");

struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

static __noinline void subprog(void)
{
	int __arena *addr = (int __arena *)0xdeadbeef;
	// int __arena *addr = (int __arena *)(unsigned long)4096;
	arena_ptr = &arena;
	*addr = 1;
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
// SEC("kprobe/__x64_sys_saterm_test")
int stream_arena_subprog_fault(void *ctx)
{
    // bpf_printk("ARENA prog entered\n");
	subprog();
	return 0;
}
