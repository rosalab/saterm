#!/bin/bash

# Log file for tracking output
LOGFILE="/var/log/bpf_monitor.log"

# Define the duration for running the script (in seconds)
DURATION=$((60 * 60 * 8))  # 8 hours
START_TIME=$(date +%s)

# Function to terminate and restart the BPF program
terminate_and_restart() {
    # Compile the binaries
    echo "Compiling BPF binaries..." >> "$LOGFILE"
    cd /linux-dev-env/bpf-progs/loops || exit
    make clean
    make -j"$(nproc)"

    # Run the binaries
    echo "Starting /linux-dev-env/bpf-progs/loops/bpf_loops.user in background..." >> "$LOGFILE"
    ./bpf_loops.user &  # Run first binary in background
    sleep 1
    echo "Starting /linux-dev-env/bpf-progs/loops/trigger in background..." >> "$LOGFILE"
    ./trigger &  # Run second binary in background

    # Find the BPF program ID
    echo "Fetching BPF program ID..." >> "$LOGFILE"
    bpf_prog_id=$(/linux/tools/bpf/bpftool/bpftool prog show | awk '/tracepoint_exit_saterm/ {print $1}' | tr -d ':')

    if [ -n "$bpf_prog_id" ]; then
        echo "Found BPF program ID: $bpf_prog_id" >> "$LOGFILE"

        # Terminate the BPF program
        echo "Terminating BPF program ID $bpf_prog_id..." >> "$LOGFILE"
        /linux/tools/bpf/bpftool/bpftool prog terminate "$bpf_prog_id"
        echo "Terminated BPF program ID $bpf_prog_id..." >> "$LOGFILE"
    else
        echo "BPF program ID not found. Ensure the BPF program is loaded." >> "$LOGFILE"
    fi

    # Sleep for a short interval before restarting
    sleep 10
}

# Main loop to run the termination process for the specified duration
echo "Starting overnight BPF termination process..." >> "$LOGFILE"
while [ $(( $(date +%s) - START_TIME )) -lt $DURATION ]; do
    terminate_and_restart
done

echo "Overnight BPF termination process complete." >> "$LOGFILE"N
