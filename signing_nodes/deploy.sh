#!/bin/bash

# Build the image
docker build -t frost-node .

# Run the container
docker run --rm -it \
  -v ./keys:/app/keys \
  -e N=15 \
  -e T=7 \
  --network signing_nodes_my-network \
  --name frost-container \
  frost-node
  #-p 3030:3030 \
