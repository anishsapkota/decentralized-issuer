#!/bin/bash

# Define the number of nodes
NUM_NODES=15

# Define the Kafka broker address inside the Docker container (assuming it's the default address)
BROKER="localhost:29092"

# Docker container name where Kafka is running
KAFKA_CONTAINER="kafka"

# List of topics to alter
topics=(
    "commitments"
    "key-gen-finished-announcements"
    "signing_commitments"
    "signing_responses"
    "heartbeats"
    "master_announcements"
    "signing_requests"
    "signing_results"
    "preprocessed_commitments"
    "retry_dkg"
)

# Set the number of partitions
NUM_PARTITIONS=3

# Loop through each topic and alter the partition count
for topic in "${topics[@]}"; do
    echo "Creating topic: $topic"
    
    # Run kafka-topics.sh inside the Kafka Docker container
    docker exec -it $KAFKA_CONTAINER ./opt/kafka/bin/kafka-topics.sh --create \
        --bootstrap-server $BROKER \
        --topic "$topic" \
        #--partitions $NUM_PARTITIONS

    if [ $? -eq 0 ]; then
        echo "Successfully created partitions for topic: $topic"
    else
        echo "Failed to create partitions for topic: $topic"
    fi
done

for (( NODE_ID=1; NODE_ID<=NUM_NODES; NODE_ID++ )); do
    topic="shares-${NODE_ID}"
    # Run kafka-topics.sh inside the Kafka Docker container for each shares topic
    docker exec -it $KAFKA_CONTAINER ./opt/kafka/bin/kafka-topics.sh --create \
        --bootstrap-server $BROKER \
        --topic "$topic" \
        #--partitions $NUM_PARTITIONS

    if [ $? -eq 0 ]; then
        echo "Successfully created partitions for topic: $topic"
    else
        echo "Failed to create partitions for topic: $topic"
    fi
done
