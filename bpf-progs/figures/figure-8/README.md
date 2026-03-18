# Figure 8 and Figure 9

Benchmarks verification time, termination time, and load-time memory for BPF programs.

## Sweeps

1. **Figure 8**: Verification time vs number of branches (saterm/kflex only)
2. **Figure 9**: Termination time vs number of local objects (saterm only by default)
   - kflex uses `/proc/bpf_throw_stats` for accurate bpf_throw timing when explicitly enabled
   - Note: kflex `objects_throw` uses a tracepoint; `bpf_throw()` from that context may
     kernel-panic or stall during detach. `figure8.user` skips the kflex object sweep by
     default; pass `--unsafe-kflex-throw` to force it.
   - kretprobe workaround is not viable: `bpf_obj_new_impl` is not allowed for kprobe programs
3. **Figure 8 (memory)**: Load-time memory vs number of local objects (all variants including baseline)

## Usage

### saterm / kflex (modified kernel)

```bash
sudo ./figure8.user saterm 100 62 10 5
# or
sudo ./figure8.user kflex 100 62 10 5
# force the unsafe kflex object sweep only if you really want it
sudo ./figure8.user kflex 100 62 10 5 --unsafe-kflex-throw
```

Produces: `saterm_branches.csv`, `saterm_objects.csv`, `saterm_memory.csv`.
For `kflex`, the default run writes `kflex_branches.csv` and `kflex_memory.csv`; the
`kflex_objects.csv` sweep is skipped unless `--unsafe-kflex-throw` is provided.

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

## Worst-Case Verifier Benchmark

An additive benchmark for the six verifier worst-case shapes lives alongside the
original figure-8 runner. It is load-only, so it is safe to use with `kflex`
without attaching or executing `bpf_throw()` from the earlier tracepoint setup.

### Run

```bash
sudo ./figure8_worstcase.user saterm
sudo ./figure8_worstcase.user kflex
```

The canonical plot inputs are `saterm_worstcase.csv` and `kflex_worstcase.csv`.
For `kflex`, the runner also refreshes `worstcase.csv` as a convenience mirror so
ad hoc inspection stays in sync with the default plotting input.

Optional flags:

```bash
sudo ./figure8_worstcase.user saterm custom.csv --runs 5 --verbose
```

If you provide a custom output path, the runner still syncs the canonical
`<variant>_worstcase.csv` file after the run so `plot_figure8_worstcase.py`
continues to pick up the latest regenerated data by default.

Each run writes one long-form CSV with columns:

```text
kernel_type,shape,param_name,param_value,run,verification_time_ns,processed_insns,max_states_per_insn,total_states,peak_states,unwind_bytes,memory_source
```

`memory_source` prefers exact `total unwind info memory overhead` bytes from the
kernel log, and falls back to summing `vzalloc size:` lines only when the exact
per-program total is absent.

The runner bounds each individual `bpftool prog load` attempt with a 30-second
timeout. If a pathological sweep point exceeds that budget, it is treated as a
load failure, that shape stops increasing, and the benchmark continues with the
remaining shapes.

### Plot

```bash
python3 plot_figure8_worstcase.py --saterm saterm_worstcase.csv --kflex kflex_worstcase.csv
```

This produces `figure8_worstcase.png` and `figure8_worstcase.pdf` as a 3x2
comparison grid:

1. `rt_fanin`
2. `rt_ladder`
3. `rt_many_pcs`
4. `mem_big_single_desc`
5. `mem_deep_ladder`
6. `mem_many_big_descs`

The plot script expects `matplotlib` and `pandas` to be installed in the Python
environment you use to generate the figure. It also refuses to plot a flat
`kflex` `mem_deep_ladder` series, which usually means `kflex_worstcase.csv`
was not refreshed after a kernel-side fix.
