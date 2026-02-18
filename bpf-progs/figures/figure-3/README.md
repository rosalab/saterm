# Figure 3: Malicious eBPF termination macro benchmark

This folder contains a minimal eBPF program that self-terminates via
`bpf_die_kfunc()` at configurable points, plus a small user-space loader.

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

Manual setup (if not using defaults):
1. On phobos VM (B), start redis:
```
taskset -c 0-15:2 redis-server --bind 192.168.10.1 --port 11212 --io-threads 8 --protected-mode no
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
- `--die-after N` (iterations before calling bpf_die, 0 = immediate, default 1)
- `--max N` (iterate die_after from 0..N, inclusive, run multiple benchmarks)
- `--step N` (step size for `--max`, default 1)
- `--test-time N` (memtier test duration in seconds, default 120)
- `--csv PATH` (default `figure3_results.csv`)
- `--raw-json PATH` (save raw memtier JSON, default `memtier_raw.json`)
- `--no-redis` (don't start redis-server, default: start it)
- `--no-memtier` (don't run memtier benchmark, default: run it)

Example (basic run with defaults - starts redis and runs 120-second memtier):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter
```

Example (quick test with custom settings):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter \
  --die-after 100000 --test-time 10
```

Example (run 0..5000 in steps of 1000, memtier each iteration):
```
sudo ./malicious_terminate.user --tracepoint raw_syscalls:sys_enter \
  --max 5000 --step 1000 --test-time 120
```

The tracepoint is intentionally a placeholder so you can select a high-traffic
event at runtime via `--tracepoint`.

## Plotting results

After collecting data, plot the results:

```bash
python3 plot_results.py [csv_path] [output_path]
```

Example:
```bash
python3 plot_results.py figure3_results.csv figure3.png
```

This generates:
- A dual-panel plot showing:
  - **Left**: App throughput loss (%) vs iterations until termination (relative to baseline with no BPF)
  - **Right**: Average latency vs iterations until termination
- Summary statistics of the performance impact

The CSV file includes a baseline measurement (first run with no BPF program attached) for calculating throughput loss.
