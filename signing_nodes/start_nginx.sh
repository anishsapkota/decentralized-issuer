#!/bin/bash

docker run --rm -it \
  -p "3030:80" \
  -v ./nginx/nginx.conf:/etc/nginx/nginx.conf \
  --network signing_nodes_my-network \
  --name nginx-load-balancer \
  nginx
