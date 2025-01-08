#!/bin/bash

# Log file for tracking output
LOGFILE="/var/log/bpf_monitor.log"

# Step 1: Simulate concurrent workloads
echo "Starting concurrent workloads..." >> "$LOGFILE"
# CPU-intensive workload
echo "Starting CPU-intensive workload..." >> "$LOGFILE"
while :; do md5sum /dev/zero &>/dev/null; done &
CPU_WORKLOAD_PID=$!

# Memory-intensive workload
#echo "Starting memory-intensive workload..." >> "$LOGFILE"
#stress --vm 1 --vm-bytes 512M --timeout 60 &
#MEM_WORKLOAD_PID=$!

# I/O-intensive workload
#echo "Starting I/O-intensive workload..." >> "$LOGFILE"
#dd if=/dev/zero of=tempfile bs=1M count=1024 oflag=direct &
#IO_WORKLOAD_PID=$!

# Track all workload PIDs for cleanup
WORKLOAD_PIDS="$CPU_WORKLOAD_PID"

# Step 2: Compile the binaries
echo "Compiling BPF binaries..." >> "$LOGFILE"
cd /linux-dev-env/bpf-progs/loops || exit
make clean
make -j"$(nproc)"

# Step 3: Run the binaries in sequence
echo "Starting /linux-dev-env/bpf-progs/loops/bpf_loops.user in background..." >> "$LOGFILE"
./bpf_loops.user &  # Run first binary in background
sleep 1         # Wait for 1 second
echo "Starting /linux-dev-env/bpf-progs/loops/trigger in background..." >> "$LOGFILE"
./trigger &  # Run second binary in background

# Step 4: Find the BPF program ID
echo "Fetching BPF program ID..." >> "$LOGFILE"
bpf_prog_id=$(/linux/tools/bpf/bpftool/bpftool prog show | awk '/tracepoint_exit_saterm/ {print $1}' | tr -d ':')

if [ -n "$bpf_prog_id" ]; then
    echo "Found BPF program ID: $bpf_prog_id" >> "$LOGFILE"

    # Step 5: Terminate the BPF program
    echo "Terminating BPF program ID $bpf_prog_id..." >> "$LOGFILE"
    /linux/tools/bpf/bpftool/bpftool prog terminate "$bpf_prog_id"
    echo "Terminated BPF program ID $bpf_prog_id..." >> "$LOGFILE"

    # Step 6: Measure impact on other processes
    echo "Measuring impact on workloads..." >> "$LOGFILE"
    ps -p $WORKLOAD_PIDS -o pid,cmd,%cpu,%mem >> "$LOGFILE"

    # Measure task latency (e.g., sort operation)
#    echo "Measuring latency of a sort operation..." >> "$LOGFILE"
#    start=$(date +%s.%N)
#    sort largefile.txt > /dev/null
#    end=$(date +%s.%N)
#    echo "Sort operation time: $(echo "$end - $start" | bc) seconds" >> "$LOGFILE"

    # Step 7: Capture Termination Handler Time from trace_pipe
    echo "Capturing termination handler logs..." >> "$LOGFILE"
    dmesg | grep -i -E "bpf|termination|verifier" | tail -n 10 >> "$LOGFILE"
else
    echo "BPF program ID not found. Ensure the BPF program is loaded." >> "$LOGFILE"
fi

# Step 8: Cleanup
echo "Cleaning up background workloads..." >> "$LOGFILE"
kill $WORKLOAD_PIDS
#rm tempfile  # Remove temporary file created by dd
echo "Cleanup complete." >> "$LOGFILE"
