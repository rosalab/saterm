#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LISENSE[] SEC("license") = "Dual BSD/GPL";

#define MB_256_IN_PAGES (65536) // 256MB worth of pages (65536 * 4096 = 256MB)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(max_entries, MB_256_IN_PAGES);
	__uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int stream_arena_subprog_fault(void *ctx)
{
	unsigned char *data = (unsigned char *)&arena;
	unsigned char val;

	bpf_probe_read_kernel(&val, sizeof(val), data);

	return 0;
}
