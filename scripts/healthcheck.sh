#!/bin/bash

# Set the log file for each cron run
LOGFILE="/var/log/system_healthcheck.log"

# Function to collect and append system information
monitor_system() {
    echo "------ System Check at $(date) ------" >> "$LOGFILE"

    # CPU Usage
    echo "CPU Usage:" >> "$LOGFILE"
    mpstat 1 1 | awk '/Average:/ {print "CPU Idle: "$NF"%"}' >> "$LOGFILE"

    # Memory Usage
    echo "Memory Usage:" >> "$LOGFILE"
    free -h | awk '/Mem:/ {print "Used: "$3", Free: "$4}' >> "$LOGFILE"

    # Top Processes by Memory and CPU
    echo "Top Processes (by memory and CPU usage):" >> "$LOGFILE"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 6 >> "$LOGFILE"

    # Task Latency Measurement
    echo "Measuring latency of a sort operation..." >> "$LOGFILE"
    touch largefile.txt  # Create a dummy file if it doesn't exist
    seq 1 1000000 | shuf > largefile.txt  # Generate a large file with random data
    start=$(date +%s.%N)
    sort largefile.txt > /dev/null
    end=$(date +%s.%N)
    echo "Sort operation time: $(echo "$end - $start" | bc) seconds" >> "$LOGFILE"
    rm -f largefile.txt  # Remove the dummy file after use

    echo "" >> "$LOGFILE"
}

# Run the health check function
monitor_system
