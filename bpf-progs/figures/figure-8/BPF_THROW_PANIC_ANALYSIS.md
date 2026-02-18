# BPF bpf_throw Kernel Panic Analysis

## Panic Snippets

```
RIP: 0010:trace_call_bpf+0x14d/0x1b0
CR2: ffff8ebe00f281d6
...
Process ... exited with preempt_count 1, irqs disabled
...
Voluntary context switch within RCU read-side critical section!
 rcu_note_context_switch+0x519/0x580
 schedule+0x.../0x...
 synchronize_rcu_tasks_generic+0x.../0x...
 perf_event_detach_bpf_prog+0x.../0x...
 bpf_link_release+0x.../0x...
 __fput+0x.../0x...
 do_exit+0x.../0x...
 make_task_dead+0x.../0x...
 rewind_stack_and_make_dead+0x.../0x...
```

## Call Chain

```
syscall_exit_work() [syscall-common.c:106]
  trace_sys_exit(regs, ret)
    → perf_syscall_exit() [trace_syscalls.c:699]
        guard(preempt_notrace)();
        perf_call_bpf_exit() → trace_call_bpf()
          bpf_prog_run_array() → objects_throw_sample()
            bpf_throw(0)
              arch_bpf_stack_walk(bpf_stack_walker, &ctx)
              ctx.aux->bpf_exception_cb(...)  // longjmp
```

## Key Source Snippets

**trace_call_bpf** (`bpf_trace.c`):
```c
rcu_read_lock();
ret = bpf_prog_run_array(rcu_dereference(call->prog_array), ctx, bpf_prog_run);
rcu_read_unlock();   // never reached on fault
out:
__this_cpu_dec(bpf_prog_active);  // RIP+0x14d ≈ here
```

**bpf_throw** (`helpers.c`):
```c
arch_bpf_stack_walk(bpf_stack_walker, &ctx);
// ...
ctx.aux->bpf_exception_cb(cookie, ctx.sp, ctx.bp, 0, 0);
```

**arch_bpf_stack_walk** (`bpf_jit_comp.c`):
```c
for (unwind_start(&state, current, NULL, NULL); !unwind_done(&state);
     unwind_next_frame(&state)) {
    addr = unwind_get_return_address(&state);
    if (!addr || !consume_fn(cookie, (u64)addr, (u64)state.sp, (u64)state.bp))
        break;
}
```

**Exception callback** (`bpf_jit_comp.c`):
```asm
mov rsp, rsi   ; ctx.sp
mov rbp, rdx   ; ctx.bp
pop_callee_regs
pop_r12
mov rsp, rbp
ret            ; longjmp to tracepoint caller
```

**ORC fallback for JIT** (`unwind_orc.c`):
```c
/* Fake frame pointer entry -- used as a fallback for generated code */
static struct orc_entry orc_fp_entry = {
    .type   = ORC_TYPE_CALL,
    .sp_reg = ORC_REG_BP,
    .sp_offset = 16,
    .bp_reg = ORC_REG_PREV_SP,
    .bp_offset = -16,
};
// orc_find(ip) returns NULL for BPF JIT → use orc_fp_entry, state->error = true
```

**arch_bpf_cleanup_frame_resource** (`bpf_jit_comp.c`):
```c
for (int i = 0; i < fd->stack_cnt; i++) {
    void *ptr = (void *)((s64)bp + fd->stack[i].off);  // bad bp → fault
    bpf_cleanup_resource(fd->stack + i, ptr);
}
```

## Root Cause

1. **ORC + tracepoint**: BPF JIT has no ORC entries → `orc_fp_entry` fallback. Tracepoint stack (`guard(preempt_notrace)`, syscall exit path) may not match frame-pointer heuristic.
2. **Bad ctx.sp/ctx.bp**: Unwinder yields wrong values → exception callback does `mov rsp,rsi; mov rbp,rdx` with invalid pointers → fault on `pop`/`ret`, or corrupt return.
3. **CR2 `ffff8ebe00f281d6`**: Per-CPU-like (GS+offset). Fault at `__this_cpu_dec(bpf_prog_active)` or in exception callback.
4. **RCU warning**: Page fault with `rcu_read_lock` held → exit path hits `synchronize_rcu_tasks_generic` → `schedule()` → "Voluntary context switch within RCU read-side critical section!".

## Workaround

- **kretprobe**: Not viable — verifier rejects `bpf_obj_new_impl` for kretprobe.
- Use `objects_die.kern.o` (no bpf_throw) for object sweep until fixed.
