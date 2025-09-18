#!/bin/bash

 # Log file for tracking output
 LOGFILE="/var/log/bpf_monitor.log"
 BPF_DIR="/linux-dev-env/bpf-progs/loops"  # Directory containing the BPF programs

 # Define the duration for running the script (in seconds)
 DURATION=$((60 * 60 * 80))  # 8 hours
 START_TIME=$(date +%s)
 RESTART_COUNT=0

 # Function to terminate and restart the BPF program
 terminate_and_restart() {
     # Compile the binaries
     RESTART_COUNT=$((RESTART_COUNT + 1))
     echo "terminate_and_restart called $RESTART_COUNT times" >> "$LOGFILE"

#     echo "Compiling BPF binaries..." >> "$LOGFILE"
#     cd /linux-dev-env/bpf-progs/loops || exit
#     make clean
#     make -j"$(nproc)"

     # Kill the user-space process managing the BPF program
#     echo "Identifying the user-space process managing the BPF program..." >> "$LOGFILE"
#     user_pid=$(ps aux | grep "./bpf_loops.user" | grep -v grep | awk '{print $2}')
#     if [ -n "$user_pid" ]; then
#         echo "Found user-space process with PID: $user_pid. Killing it..." >> "$LOGFILE"
#         kill -9 "$user_pid"
#         echo "Killed user-space process with PID: $user_pid." >> "$LOGFILE"
#     else
#         echo "No user-space process found for bpf_loops.user." >> "$LOGFILE"
#     fi

     # Run the binaries
     echo "Starting /linux-dev-env/bpf-progs/loops/bpf_loops.user in background..." >> "$LOGFILE"
     cd "$BPF_DIR" || exit
     ./bpf_loops.user &  # Run first binary in background
#     sleep 3

     # Find the BPF program ID
     echo "Fetching BPF program ID..." >> "$LOGFILE"
     bpf_prog_id=$(/linux/tools/bpf/bpftool/bpftool prog show | awk '/tracepoint_exit_saterm/ {print $1}' | tr -d ':')
     if [ -n "$bpf_prog_id" ]; then
         echo "Found BPF program ID: $bpf_prog_id" >> "$LOGFILE"
#         echo "Starting /linux-dev-env/bpf-progs/loops/trigger in background..." >> "$LOGFILE"
#         ./trigger &  # Run second binary in background
#         echo "Terminating BPF program ID $bpf_prog_id..." >> "$LOGFILE"
         # /linux/tools/bpf/bpftool/bpftool prog terminate "$bpf_prog_id"
         # echo "Terminated BPF program ID $bpf_prog_id." >> "$LOGFILE"
     else
          echo "BPF program ID not found. Ensure the BPF program is loaded." >> "$LOGFILE"
     fi
#     echo "Identifying the user-space process managing the BPF program..." >> "$LOGFILE"
#     user_pid=$(ps aux | grep "./bpf_loops.user" | grep -v grep | awk '{print $2}')
#     if [ -n "$user_pid" ]; then
#       echo "Found user-space process with PID: $user_pid. Killing it..." >> "$LOGFILE"
#       kill -9 "$user_pid"
#       echo "Killed user-space process with PID: $user_pid." >> "$LOGFILE"
#     else
#       echo "No user-space process found for bpf_loops.user." >> "$LOGFILE"
#     fi
     # Sleep for a short interval before restarting
     sleep 20
 }

 # Main loop to run the termination process for the specified duration
 echo "Starting overnight BPF termination process..." >> "$LOGFILE"
 while [ $(( $(date +%s) - START_TIME )) -lt $DURATION ]; do
     terminate_and_restart
 done

 echo "Overnight BPF termination process complete." >> "$LOGFILE"
 echo "Total terminate_and_restart calls: $RESTART_COUNT" >> "$LOGFILE"
