/*
 * BPF program for runtime testing - nested loops (exponential complexity)
 * Attaches to: tracepoint/syscalls/sys_exit_saterm_test
 *
 * This program uses multiple nested iterators that lead to exponential
 * runtimes with an increase in iterations.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Control map to configure iteration count */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32); /* iteration count */
} control_map SEC(".maps");

/* Default iteration count if not set */
#define DEFAULT_ITERS 32

static int simple() {
  volatile int dummy = 0;
  dummy++;
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
int tracepoint_exit_runtime_nested_long(struct pt_regs *ctx) {
  loop1();
  return 0;
}
