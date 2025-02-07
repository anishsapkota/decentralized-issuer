#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <total_nodes>"
    exit 1
fi

TOTAL_NODES=$1

# Stop each container
for (( NODE_ID=1; NODE_ID<=$TOTAL_NODES; NODE_ID++ )); do
    CONTAINER_NAME="frost-node-$NODE_ID"

    if docker ps -q -f name="^${CONTAINER_NAME}$" | grep -q .; then
        echo "Stopping container $CONTAINER_NAME..."
        docker stop $CONTAINER_NAME
    else
        echo "Container $CONTAINER_NAME is not running."
    fi
done

echo "Stopped all $TOTAL_NODES containers."

docker stop redis