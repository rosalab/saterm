# BPF Instruction Count: `malicious_terminate.kern.o`

Derived from `llvm-objdump -d malicious_terminate.kern.o` (compiled with `clang -O2 -target bpf`).

## Compiler optimization

The 128 individual `sink += (base) + N` additions per loop body (16 × ADD8) are
compiled into a closed-form using a register-doubling trick: 7 doubles + 7 adds
(14 ALU ops) replace 128 source-level additions.

## Per-execution instruction breakdown

| Phase | PC range | Instructions | Description |
|---|---|---|---|
| Prologue | 0–9, 13–15 | 12 | map lookup, mode check, sink/counter init |
| Loop body (×N) | 16–41 | 26 | bounds checks, doubling-trick ALU, loop advance |
| Exit | 16–18, 44–45 | 5 | final bounds check (taken) + return |

Each loop body iteration covers **128 work_iters**.

## Conversion formula

```
total_instructions = 17 + 26 × ⌊work_iters / 128⌋
```

| work_iters | loop iterations | total instructions |
|---|---|---|
| 0 | 0 | 17 |
| 2,000 | 15 | 407 |
| 10,000 | 78 | 2,045 |
| 50,000 | 390 | 10,157 |

## Raw disassembly (`llvm-objdump -d --no-show-raw-insn`)

```asm
<malicious_terminate>:
;; === Prologue (12 insns executed on NO_TERMINATION path) ===
       0:  w6 = 0x0                        ; key = 0
       1:  *(u32 *)(r10 - 0x4) = w6        ; store key on stack
       2:  r2 = r10                         ; r2 = &key
       3:  r2 += -0x4
       4:  r1 = 0x0 ll                      ; r1 = &control_map  (ld_imm64, 2 slots)
       6:  call 0x1                          ; bpf_map_lookup_elem
       7:  if r0 == 0x0 goto +0x24          ; if (!ctl) goto exit
       8:  w1 = *(u32 *)(r0 + 0x4)          ; w1 = ctl->mode
       9:  if w1 == 0x0 goto +0x3            ; MODE_NO_TERMINATION → pc 13
      10:  if w1 != 0x1 goto +0x21           ; unknown mode → exit
;; --- MODE_TERM_IMMEDIATE path ---
      11:  call -0x1                          ; bpf_die_kfunc()
      12:  goto +0x1f                         ; → exit
;; === NO_TERMINATION: loop setup ===
      13:  r6 = 0x0                          ; sink = 0
      14:  r1 = -0x80                        ; shifted loop counter (i − 128)
      15:  w2 = *(u32 *)(r0 + 0x0)           ; r2 = ctl->work_iters
;; === Loop body — 26 insns, each iteration covers 128 work_iters ===
      16:  r3 = r1                           ; r3 = shifted_i
      17:  r3 += 0x100                       ; r3 = shifted_i + 256 = i + 128
      18:  if r3 > r2 goto +0x19             ; early exit: (i+128) > work_iters
      19:  if r3 > 0x100000 goto +0x18       ; safety: (i+128) > MAX_WORK_ITERS
      20:  r3 = r1                           ; r3 = shifted_i
      21:  r3 += 0x80                        ; r3 = i (original)
      22:  r6 += r3                          ; sink += 1·i
      23:  r3 += r3                          ; r3 = 2·i
      24:  r6 += r3                          ; sink += 2·i
      25:  r3 += r3                          ; r3 = 4·i
      26:  r6 += r3                          ; sink += 4·i
      27:  r3 += r3                          ; r3 = 8·i
      28:  r6 += r3                          ; sink += 8·i
      29:  r3 += r3                          ; r3 = 16·i
      30:  r6 += r3                          ; sink += 16·i
      31:  r3 += r3                          ; r3 = 32·i
      32:  r6 += r3                          ; sink += 32·i
      33:  r3 += r3                          ; r3 = 64·i
      34:  r6 += r3                          ; sink += 64·i   (cumulative: 127·i)
      35:  r1 += 0x80                        ; advance counter: shifted_i += 128
      36:  r3 = r6                           ; r3 = sink + 127·i
      37:  r3 += 0x1fc0                      ; r3 += 8128 (closed-form constant)
      38:  r6 = r1                           ; r6 = new shifted_i = i
      39:  r6 += r3                          ; sink = old_sink + 128·i + 8128
      40:  if r1 > 0xfff7f goto +0x1         ; loop end: shifted_i > MAX−129
      41:  goto -0x1a                        ; → pc 16 (loop back)
;; === Exit paths ===
      42:  w3 += w1                          ; (reached when outer loop exhausts)
      43:  w6 = w3
      44:  w0 = w6                           ; return (int)sink
      45:  exit
```
