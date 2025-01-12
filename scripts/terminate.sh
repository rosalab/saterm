#!/bin/bash

 # Log file for tracking output
 LOGFILE="/var/log/bpf_monitor.log"

 # Define the duration for running the script (in seconds)
 DURATION=$((60 * 60 * 8))  # 8 hours
 START_TIME=$(date +%s)
 RESTART_COUNT=0

 # Function to warm up the system
 warm_up_system() {
     echo "Warming up the system..." >> "$LOGFILE"

     # Preload binaries
     echo "Preloading binaries into memory..." >> "$LOGFILE"
     cat /linux-dev-env/bpf-progs/loops/bpf_loops.user > /dev/null
     cat /linux-dev-env/bpf-progs/loops/trigger > /dev/null
     echo "Preloaded binaries into memory." >> "$LOGFILE"

     # Run a CPU warm-up task
     echo "Running CPU warm-up task..." >> "$LOGFILE"
     for i in {1..100000}; do :; done
     echo "CPU warm-up task complete." >> "$LOGFILE"

     # Generate network traffic (if needed)
     echo "Generating network traffic for warm-up..." >> "$LOGFILE"
     ping -c 10 localhost > /dev/null
     echo "Network traffic warm-up complete." >> "$LOGFILE"

     echo "System warm-up complete." >> "$LOGFILE"
     echo "System warm-up complete."
 }

 # Function to terminate and restart the BPF program
 terminate_and_restart() {
     # Compile the binaries
     RESTART_COUNT=$((RESTART_COUNT + 1))
     echo "terminate_and_restart called $RESTART_COUNT times" >> "$LOGFILE"
     echo "Compiling BPF binaries..." >> "$LOGFILE"
     cd /linux-dev-env/bpf-progs/loops || exit
     make clean
     make -j"$(nproc)"

     # Kill the user-space process managing the BPF program
     echo "Identifying the user-space process managing the BPF program..." >> "$LOGFILE"
     user_pid=$(ps aux | grep "./bpf_loops.user" | grep -v grep | awk '{print $2}')
     if [ -n "$user_pid" ]; then
         echo "Found user-space process with PID: $user_pid. Killing it..." >> "$LOGFILE"
         kill -9 "$user_pid"
         echo "Killed user-space process with PID: $user_pid." >> "$LOGFILE"
     else
         echo "No user-space process found for bpf_loops.user." >> "$LOGFILE"
     fi

     # Run the binaries
     echo "Starting /linux-dev-env/bpf-progs/loops/bpf_loops.user in background..." >> "$LOGFILE"
     ./bpf_loops.user &  # Run first binary in background
     sleep 1
     echo "Starting /linux-dev-env/bpf-progs/loops/trigger in background..." >> "$LOGFILE"
     ./trigger &  # Run second binary in background

     # Find the BPF program ID
     echo "Fetching BPF program ID..." >> "$LOGFILE"
     bpf_prog_id=$(/linux/tools/bpf/bpftool/bpftool prog show | awk '/tracepoint_exit_saterm/ {print $1}' | tr -d ':' | tail -n 1)
     if [ -n "$bpf_prog_id" ]; then
         echo "Found BPF program ID: $bpf_prog_id" >> "$LOGFILE"

         # Terminate the BPF program
         echo "Terminating BPF program ID $bpf_prog_id..." >> "$LOGFILE"
         /linux/tools/bpf/bpftool/bpftool prog terminate "$bpf_prog_id"
         echo "Terminated BPF program ID $bpf_prog_id." >> "$LOGFILE"
     else
         echo "BPF program ID not found. Ensure the BPF program is loaded." >> "$LOGFILE"
     fi

     # Sleep for a short interval before restarting
     sleep 10
 }

 # Warm up the system before starting the main loop
 warm_up_system

 # Main loop to run the termination process for the specified duration
 echo "Starting overnight BPF termination process..." >> "$LOGFILE"
 while [ $(( $(date +%s) - START_TIME )) -lt $DURATION ]; do
     terminate_and_restart
 done

 echo "Overnight BPF termination process complete." >> "$LOGFILE"
 echo "Total terminate_and_restart calls: $RESTART_COUNT" >> "$LOGFILE"
