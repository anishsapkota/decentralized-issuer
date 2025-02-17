#!/bin/bash

NETWORK="signing_nodes_my-network"
IMAGE_NAME="issuer-frontend"
CONTAINER_NAME="issuer-frontend"
PROXY_URL="http://nginx-load-balancer/sign"
SERVER_URL=https://e7eb-149-233-55-5.ngrok-free.app

docker run --rm  \
        -p "3000:3000" \
        -e PROXY_URL=$PROXY_URL \
        -e SERVER_URL=$SERVER_URL \
        --network $NETWORK \
        --name $CONTAINER_NAME \
        $IMAGE_NAME