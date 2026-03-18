# Figure 3: Malicious eBPF termination macro benchmark

This folder contains a minimal eBPF program plus user-space loader for three
deterministic experiment modes:
- `no-termination`: run configurable in-program loop work and return normally
- `termination (immediate)`: unwind the current invocation immediately from inside the loop path
- `termination (budgeted)`: unwind the current invocation after a configured in-program time budget expires

Figure 3 now models **per-invocation termination**. A terminated invocation exits
via exception-style unwind, but the loaded BPF program remains attached so the
next invocation starts fresh. This benchmark no longer models destructive
`bpf_die_kfunc()` program patching semantics.

## Build

First, ensure libbpf is built:
```bash
cd ../../../linux/tools/lib/bpf && make
```

Then build the benchmark:
```bash
cd -  # back to figure-3
make
```

## Run flow (macro benchmark)

By default, the loader will:
1. Start redis-server locally
2. Run baseline memtier benchmark (no BPF attached) to measure reference throughput
3. Attach the BPF program to the specified tracepoint
4. Run memtier benchmark via SSH to deimos-vm (120 second test by default)

When started by the loader, Redis persistence is disabled (`--save "" --appendonly no`)
and a dedicated `/tmp/figure3_redis.rdb` is used/cleaned up per run to avoid
RDB background-save noise and stale DB reload effects in measurements.

## Networking preflight

This benchmark assumes the dedicated Redis-facing NIC on the local VM owns
`192.168.10.1/24` and is reachable from `deimos-vm` on the paired SR-IOV /
Mellanox link.

On this setup, the Mellanox VF may enumerate as `enp0s4` rather than `ens4`.
To avoid silent breakage when predictable interface naming changes, prefer a
MAC-matched netplan stanza that assigns `192.168.10.1/24` to the VF and
`set-name`s it explicitly, instead of relying on a hard-coded interface name.

Before running the benchmark, verify:
- `ip -brief addr show enp0s4` includes `192.168.10.1/24`
- `ssh deimos-vm 'ping -c 1 192.168.10.1'` succeeds

If these checks fail, `redis-server` will not bind the expected address and the
baseline memtier phase will fail before any BPF measurement starts.

Manual setup (if not using defaults):
1. On phobos VM (B), start redis:
```bash
taskset -c 0-15:2 redis-server --bind 192.168.10.1 --port 11212 \
  --io-threads 8 --protected-mode no \
  --save "" --appendonly no --dir /tmp --dbfilename figure3_redis.rdb
```

2. On deimos VM (A), run memtier:
```
memtier_benchmark --server=192.168.10.1 --port=11212 --protocol=redis \
  --clients=128 --threads=32 --test-time=120 --json-out-file results.json
```

## Loader usage

```
sudo ./malicious_terminate.user --tracepoint CATEGORY:EVENT [options]
```

Options:
- `--work-iters N` (loop-work iterations for no-termination mode, default 1)
- `--die-after N` (compatibility alias for `--work-iters`)
- `--exp-mode MODE` (`no-termination|termination|both`, default `no-termination`)
- `--termination-style STYLE` (`immediate|budgeted`, default `immediate`)
- `--time-limit-us F` (required with `--termination-style budgeted`)
- `--max [N]` (iterate work-iters from 0..N, inclusive; defaults to verifier-safe cap 1048576)
- `--step N` (step size for `--max`, default 1)
- `--runs N` (memtier runs per point, averaged, default 3)
- `--test-time N` (memtier test duration in seconds, default 120)
- `--csv PATH` (default `figure3_results.csv`)
- `--raw-json PATH` (save latest raw memtier output to `PATH` and append all runs to `PATH.archive`, default `memtier_raw.json`)
- `--redis-host HOST` (Redis bind address and memtier server host, default `192.168.10.1`)
- `--redis-port PORT` (Redis port and memtier server port, default `11212`)
- `--ssh-target HOST` (SSH target used to run memtier, default `deimos-vm`)
- `--no-redis` (don't start redis-server, default: start it)
- `--no-memtier` (don't run memtier benchmark, default: run it)
- `--verbose` (print best-effort libbpf + verifier logs and kernel dmesg emitted during load/attach; automatically falls back if verifier logs overflow)
- `--no-verify-reload` (disable per-point program ID detach/reload checks during `--max` sweeps)

`--work-iters`/`--die-after` and `--max` are clamped to the current verifier-safe ceiling
(`1048576`) for this unrolled loop shape.
When memtier-backed measurements run, the loader enables `kernel.bpf_stats_enabled`
for the duration of the benchmark and restores the previous value on exit so
`avg_bpf_runtime_ns` is populated in the CSV output.
For budgeted runs, the time budget is interpreted as **total BPF wall time for
that invocation**, including budget-check overhead.

Example (basic run with defaults - starts redis and runs 120-second memtier):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter
```

Example (quick test with custom settings):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter \
  --exp-mode no-termination --work-iters 100000 --test-time 10
```

Example (no-termination sweep):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter \
  --exp-mode no-termination \
  --max 50000 --step 2000 --runs 1 --test-time 50 \
  --csv figure3_no_term.csv
```

Example (termination-immediate sweep, same x-grid):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter \
  --exp-mode termination \
  --max 50000 --step 2000 --runs 1 --test-time 50 \
  --csv figure3_term.csv
```

Example (paired no-termination + budgeted-termination sweep for the paper figure):
```bash
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter \
  --exp-mode both --termination-style budgeted --time-limit-us 2.0 \
  --max 50000 --step 2000 --runs 1 --test-time 50 \
  --csv figure3_no_term.csv
```

This produces:
- `figure3_no_term.csv` — no-termination sweep
- `figure3_no_term-budget.csv` — budgeted-termination sweep

If your VM does not own `192.168.10.1`, override the benchmark endpoints explicitly.
The loader now fails fast if Redis cannot bind its configured address, instead of
silently hanging in the baseline memtier step.

When using `--max`, the loader opens/loads/attaches a fresh BPF instance for
each point, verifies loaded program ID changes between points, and verifies the
previous point's program ID is gone after detach/close.

The tracepoint is intentionally a placeholder so you can select a high-traffic
event at runtime via `--tracepoint`.

## Plotting results

After collecting data, render the motivating plot:

```bash
python3 plot_results.py \
  --figure motivating \
  --csv figure3_no_term.csv \
  --output figure3_p99_motivating.png
```

This produces:
- `figure3_p99_motivating.png` / `.pdf` — p99 latency vs configured eBPF instructions

Render the evaluation plot:
```bash
python3 plot_results.py \
  --figure evaluation \
  --no-term-csv figure3_no_term.csv \
  --budget-csv figure3_no_term-budget.csv \
  --output figure3_p99_evaluation.png
```

This produces:
- `figure3_p99_evaluation.png` / `.pdf` — no-termination vs budgeted-termination p99 latency, plus a measured cutoff marker derived from the budgeted run's termination stats

Expected behavior:
- Motivating figure: the no-termination p99 curve rises with configured instruction count
- Evaluation figure: the budgeted-termination p99 curve follows the no-termination curve at low work, then flattens once per-invocation termination hits begin

The CSV includes averaged values across runs per point (ops/sec, avg/max/p99/p99.9 latency) plus baseline throughput/latency references. The figure-3 rework also adds:
- `configured_insn_count`
- `time_limit_ns`
- `time_limit_us`
- `avg_bpf_runtime_ns`
- `termination_hits`
- `avg_elapsed_ns_before_termination`
- `avg_completed_work_iters_before_termination`

For redundancy, raw benchmark output is also persisted in:
- Latest snapshot: `memtier_raw.json` (or your `--raw-json` path)
- Full append-only archive of all runs: `memtier_raw.json.archive`
