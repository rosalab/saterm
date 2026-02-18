/*
 * BPF program for runtime testing - terminated version
 * Attaches to: tracepoint/syscalls/sys_exit_saterm_test
 *
 * This program has nested loops like runtime_nested_long but calls
 * bpf_die_kfunc() inside the innermost loop to terminate early,
 * showing constant runtime regardless of iteration count.
 * This guarantees that the program is terminated in its first iteration.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Forward declaration */
extern void bpf_die_kfunc(void) __ksym;

/* Control map to configure iteration count */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32); /* iteration count */
} control_map SEC(".maps");

/* Default iteration count if not set */
#define DEFAULT_ITERS 32

static __noinline int simple() {
  // bpf_printk("terminated\n");
  bpf_die_kfunc();
  bpf_printk("not terminated\n");
  return 0;
}

static int loop3() {
  __u32 key = 0;
  __u32 *iters = bpf_map_lookup_elem(&control_map, &key);
  __u32 count = iters ? *iters : DEFAULT_ITERS;

  bpf_loop(count, simple, NULL, 0);
  return 0;
}

static int loop2() {
  __u32 key = 0;
  __u32 *iters = bpf_map_lookup_elem(&control_map, &key);
  __u32 count = iters ? *iters : DEFAULT_ITERS;

  bpf_loop(count, loop3, NULL, 0);
  return 0;
}

static int loop1() {
  __u32 key = 0;
  __u32 *iters = bpf_map_lookup_elem(&control_map, &key);
  __u32 count = iters ? *iters : DEFAULT_ITERS;

  bpf_loop(count, loop2, NULL, 0);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_saterm_test")
int tracepoint_exit_runtime_terminated(struct pt_regs *ctx) {
  loop1();
  return 0;
}
