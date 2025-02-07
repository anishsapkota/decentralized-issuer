#!/bin/bash

# start_nodes.sh
# Usage: ./start_nodes.sh <total_nodes> <threshold>

if [ $# -ne 2 ]; then
    echo "Usage: $0 <total_nodes> <threshold>"
    exit 1
fi

TOTAL_NODES=$1
THRESHOLD=$2

# Create new tmux session
tmux new-session -d -s frost-cluster

# Start first node in base window
tmux send-keys -t frost-cluster:0 "cargo run -- --node-id 1 --total-nodes $TOTAL_NODES --threshold $THRESHOLD" C-m

# Create split panes for remaining nodes
for (( NODE_ID=2; NODE_ID<=$TOTAL_NODES; NODE_ID++ )); do
    tmux split-window -v -t frost-cluster:0
    tmux send-keys -t frost-cluster:0 "cargo run -- --node-id $NODE_ID --total-nodes $TOTAL_NODES --threshold $THRESHOLD" C-m
    tmux select-layout -t frost-cluster:0 tiled
    sleep 1  # Short delay between node starts
done

# Final layout arrangement and attach
tmux select-layout -t frost-cluster:0 tiled
tmux attach -t frost-cluster