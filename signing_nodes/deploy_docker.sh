#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <total_nodes> <threshold> <mode>"
    exit 1
fi

# Configuration
TOTAL_NODES=$1
THRESHOLD=$2
MODE=$3
NETWORK="signing_nodes_my-network"
IMAGE_NAME="frost-node"
BASE_PORT=3030
KEYS_VOLUME="./keys"

# Validate input
if [ -z "$TOTAL_NODES" ] || [ -z "$THRESHOLD" ]; then
    echo "Please set TOTAL_NODES and THRESHOLD."
    exit 1
fi

#Start redis
docker run --rm -d --name redis -p 6379:6379 --network signing_nodes_my-network redis:latest

# Start N containers
for (( NODE_ID=1; NODE_ID<=$TOTAL_NODES; NODE_ID++ )); do
    PORT=$((BASE_PORT + NODE_ID - 1))  # Assign unique port for each node
    CONTAINER_NAME="frost-node-$NODE_ID"

    echo "Starting container $CONTAINER_NAME on port $PORT..."

    docker run --rm -d \
        -v $KEYS_VOLUME:/app/keys \
        -e NODE_ID=$NODE_ID \
        -e N=$TOTAL_NODES \
        -e T=$THRESHOLD \
        -e NUM_COMMITMENTS=100000 \
        -e MODE=$MODE \
        --network $NETWORK \
        --name $CONTAINER_NAME \
        $IMAGE_NAME
done

echo "Started $TOTAL_NODES containers."

docker run --rm -it \
  -p "3030:80" \
  -v ./nginx/nginx.conf:/etc/nginx/nginx.conf \
  --network signing_nodes_my-network \
  --name nginx-load-balancer \
  nginx

echo "Started nginx load balancer."

#        -e KAFKA_BROKER="kafka1:9092,kafka2:9092" \
