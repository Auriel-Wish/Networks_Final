#!/bin/bash

# Function to clean up background processes
cleanup() {
    echo
    echo "Cleaning Up"
    make clean > /dev/null
    PIDS=$(lsof -t -i:1026)
    if [ -n "$PIDS" ]; then
        kill -9 $PIDS > /dev/null
    fi
    PIDS=$(lsof -t -i:5001)
    if [ -n "$PIDS" ]; then
        kill -9 $PIDS > /dev/null
    fi
}

find . -type f -name "*.crt" ! -name "Networks_Final_Project.crt" -exec rm -f {} +
find . -type f -name "*.key" ! -name "Networks_Final_Project.key" -exec rm -f {} +
