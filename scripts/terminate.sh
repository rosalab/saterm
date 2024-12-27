#!/bin/bash

# Log file for tracking output
LOGFILE="/var/log/bpf_monitor.log"

# Step 1: Compile the binaries
cd /linux-dev-env/bpf-progs
make clean
make -j"$(nproc)"

# Step 2: Run the binaries in sequence
echo "Starting /linux-dev-env/bpf-progs/loops.user in background..."
./loops.user &  # Run first binary in background
sleep 1         # Wait for 1 second
echo "Starting /linux-dev-env/bpf-progs/trigger_loops.user in background..."
./trigger_loops.user &  # Run second binary in background

# Step 3: Find the BPF program ID
echo "Fetching BPF program ID..."
bpf_prog_id=$(/linux/tools/bpf/bpftool/bpftool prog show | awk '/trace_sys_connect1/ {print $1}' | tr -d ':')

if [ -n "$bpf_prog_id" ]; then
    echo "Found BPF program ID: $bpf_prog_id"
    
    # Step 4: Terminate the BPF program
    echo "Terminating BPF program ID $bpf_prog_id..."
    /linux/tools/bpf/bpftool/bpftool prog terminate "$bpf_prog_id"
    echo "Terminated BPF program ID $bpf_prog_id..."

    # Step 5: Capture Termination Handler Time from trace_pipe
    # Wait briefly to ensure trace_pipe has the log entry
    sleep 1
    echo "Writing to log..."
    echo "Killing user process"
    
    dmesg | grep -i -E "bpf|termination|verifier" | tail -n 10 >> "$LOGFILE"
else
    echo "BPF program ID not found. Ensure the BPF program is loaded." >> "$LOGFILE"
fi