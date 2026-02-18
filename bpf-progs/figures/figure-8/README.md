# Figure 8 and Figure 9

Benchmarks verification time, termination time, and load-time memory for BPF programs.

## Sweeps

1. **Figure 8**: Verification time vs number of branches (saterm/kflex only)
2. **Figure 9**: Termination time vs number of local objects (saterm/kflex only)
   - kflex uses `/proc/bpf_throw_stats` for accurate bpf_throw timing
   - Note: kflex objects_throw uses tracepoint; bpf_throw from tracepoint may kernel-panic
     (kretprobe workaround not viable: bpf_obj_new_impl not allowed for kprobe programs)
3. **Figure 8 (memory)**: Load-time memory vs number of local objects (all variants including baseline)

## Usage

### saterm / kflex (modified kernel)

```bash
sudo ./figure8.user saterm 100 62 10 5
# or
sudo ./figure8.user kflex 100 62 10 5
```

Produces: `saterm_branches.csv`, `saterm_objects.csv`, `saterm_memory.csv` (and similarly for kflex).

### baseline (unmodified kernel, manual tag)

Run on a vanilla/unmodified kernel to measure baseline memory:

```bash
sudo ./figure8.user baseline 0 62 10 5
```

Produces: `baseline_memory.csv` only (no branches or termination sweeps).

Merge `baseline_memory.csv` with your saterm/kflex results, then plot:

```bash
python3 plot_figure8.py
```

The plot script looks for `baseline_memory.csv` by default; use `--memory-baseline` to override.
