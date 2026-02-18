#!/bin/bash
#
# Sweep MAX_LOCAL_OBJS from 0..max, measuring load-time memory overhead.
#
# Selects the BPF program based on the kernel label:
#   saterm  -> die_sample.kern.c   (uses bpf_die_kfunc)
#   kflex   -> throw_sample.kern.c (uses bpf_throw)
#
# Usage:
#   sudo ./run_sweep.sh <saterm|kflex> <max_local_objs> <num_runs> [output_csv]
#
# Examples:
#   sudo ./run_sweep.sh saterm 62 5 saterm.csv
#   sudo ./run_sweep.sh kflex 62 5 kflex.csv

LABEL="${1:?Usage: $0 <saterm|kflex> <max_local_objs> <num_runs> [output_csv]}"
MAX_OBJS="${2:?Usage: $0 <saterm|kflex> <max_local_objs> <num_runs> [output_csv]}"
NUM_RUNS="${3:?Usage: $0 <saterm|kflex> <max_local_objs> <num_runs> [output_csv]}"
CSV="${4:-${LABEL}.csv}"

case "$LABEL" in
    saterm)
        KERN_SRC="die_sample.kern.c"
        KERN_OBJ="die_sample.kern.o"
        ;;
    kflex)
        KERN_SRC="throw_sample.kern.c"
        KERN_OBJ="throw_sample.kern.o"
        ;;
    *)
        echo "ERROR: kernel_label must be 'saterm' or 'kflex', got '$LABEL'" >&2
        exit 1
        ;;
esac

MEASURE="./measure.user"

# Build the loader via make
make measure.user

# CSV header
echo "kernel_type,num_local_objs,run,mem_avail_before_kb,mem_avail_after_kb,mem_free_before_kb,mem_free_after_kb,xlated_prog_len,jited_prog_len" > "$CSV"

echo "=== kernel=$LABEL  prog=$KERN_SRC  N=0..$MAX_OBJS  runs=$NUM_RUNS ==="

for n in $(seq 0 "$MAX_OBJS"); do
    # Recompile with this object count
    if ! make -B "$KERN_OBJ" EXTRA_CFLAGS="-DMAX_LOCAL_OBJS=$n" 2>&1; then
        echo "  ERROR: compilation failed for MAX_LOCAL_OBJS=$n, skipping" >&2
        continue
    fi

    for run in $(seq 1 "$NUM_RUNS"); do
        result=$($MEASURE "$KERN_OBJ" 2>&1)
        rc=$?
        if [ $rc -eq 0 ] && [ -n "$result" ]; then
            echo "$LABEL,$n,$run,$result" >> "$CSV"
        else
            echo "  WARN: measurement failed (n=$n run=$run rc=$rc): $result" >&2
        fi
    done

    printf "  N=%d/%d done\n" "$n" "$MAX_OBJS"
done

echo ""
echo "Results written to $CSV"
