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

    # Top Processes by Memory and CPU (highlight potential BPF impact)
    echo "Top Processes (by memory and CPU usage):" >> "$LOGFILE"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 6 >> "$LOGFILE"

    # Network Statistics
    echo "Network Statistics:" >> "$LOGFILE"
    netstat -i >> "$LOGFILE"
    
    echo "" >> "$LOGFILE"
}

# Run the health check function
monitor_system