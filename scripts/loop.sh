#!/bin/bash
while true; do
    echo "Inside Loop script ......"
    /linux-dev-env/scripts/healthcheck.sh &
    sleep 60  # Run every 60 seconds
done
