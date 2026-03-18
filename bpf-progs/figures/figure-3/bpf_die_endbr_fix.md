# x86/bpf: fix bpf_die() prologue patch offset when ENDBR is absent

## Problem statement

bpf_die() patched a fixed prog->bpf_func + 4 location (from commit a46cd780f42e), assuming ENDBR always precedes the 5-byte patch slot.
On the running kernel config, IBT is disabled (`# CONFIG_X86_KERNEL_IBT is not set`) at config-6.17.0-rc1-saterm+ (line 502).

## Call path

- BPF program calls bpf_die_kfunc() from malicious_terminate.kern.c:41.
- Kfunc entry is helpers.c:3741 and calls arch_bpf_stack_walk(...) helpers.c:3743.
- Stack walker dispatches to bpf_term_stack_walker() bpf_jit_comp.c:3976.
- bpf_term_stack_walker() calls bpf_die(prog) on direct kfunc path bpf_jit_comp.c:3993.
- bpf_die() patches prologue and callsites bpf_jit_comp.c:3917, bpf_jit_comp.c:3950, bpf_jit_comp.c:3954.

## Root cause

- Prologue emits the 5-byte patch slot via emit_nops(..., X86_PATCH_SIZE) at bpf_jit_comp.c:528.
- ENDBR emission is conditional (EMIT_ENDBR()) at bpf_jit_comp.c:557.
- Therefore, fixed +4 is only valid when ENDBR exists before the slot; with IBT off, it targets the wrong bytes.

## Fix correctness check

New code derives patch_ip from function entry and conditionally skips ENDBR:

- bpf_jit_comp.c:3921
- bpf_jit_comp.c:3923

Uses emit_jump() for rethunk branch:

- bpf_jit_comp.c:3940

emit_jump() semantics are rel32 from ip + X86_PATCH_SIZE bpf_jit_comp.c:567, bpf_jit_comp.c:594

Applies patch at computed patch_ip bpf_jit_comp.c:3950.

This matches existing x86 BPF text-poke ENDBR handling pattern in bpf_jit_comp.c:650 through bpf_jit_comp.c:655.

## Clang regression check

Rebuilt malicious_terminate.kern.o with clang 23 and disassembled.
The bpf_die_kfunc call relocation is present (R_BPF_64_32 bpf_die_kfunc), so codegen still emits the call path correctly.

---

If you want, I can now add a small --reopen-per-point off flag (default on) so this behavior is explicit/tunable.

After you reboot into the kernel containing the x86 JIT fix, rerun figure-3 sweep and I can help compare old/new CSV trends quickly.

## Figure-3 experiment mode note

The figure-3 loader now supports explicit experiment modes:
- `--exp-mode no-termination`: BPF program performs configurable loop work and never calls `bpf_die_kfunc()`
- `--exp-mode termination`: BPF program triggers `bpf_die_kfunc()` immediately from inside loop path

For sweep reproducibility, loader behavior is:
- fresh open/load/attach per point,
- fresh map update per point,
- close/detach per point,
- program-ID verification that IDs rotate per point and old IDs disappear after close.

This setup is intended to generate two CSVs on the same x-grid (`--max/--step`) and
overlay them in plotting as a no-termination vs termination comparison.
