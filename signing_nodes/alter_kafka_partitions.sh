#!/bin/bash

# Define the Kafka broker address inside the Docker container (assuming it's the default address)
BROKER="localhost:9092"

# Docker container name where Kafka is running
KAFKA_CONTAINER="kafka"

# List of topics to alter
topics=(
    "commitments"
    "key-gen-finished-announcements"
    # "shares-${NODE_ID}"
    "signing_commitments"
    "signing_responses"
    "heartbeats"
    "master_announcements"
    "signing_requests"
    "signing_results"
)

# Set the number of partitions
NUM_PARTITIONS=3

# Loop through each topic and alter the partition count
for topic in "${topics[@]}"; do
    echo "Altering topic: $topic"
    
    # Run kafka-topics.sh inside the Kafka Docker container
    docker exec -it $KAFKA_CONTAINER ./opt/kafka/bin/kafka-topics.sh --alter \
        --bootstrap-server $BROKER \
        --topic "$topic" \
        --partitions $NUM_PARTITIONS

    if [ $? -eq 0 ]; then
        echo "Successfully altered partitions for topic: $topic"
    else
        echo "Failed to alter partitions for topic: $topic"
    fi
done


#Now, for the topics that depend on NODE_ID ranging from 1 to 5
for NODE_ID in {1..5}; do
    topic="shares-${NODE_ID}"
    echo "Altering topic: $topic"

    # Run kafka-topics.sh inside the Kafka Docker container for each shares topic
    docker exec -it $KAFKA_CONTAINER ./opt/kafka/bin/kafka-topics.sh --alter \
        --bootstrap-server $BROKER \
        --topic "$topic" \
        --partitions $NUM_PARTITIONS

    if [ $? -eq 0 ]; then
        echo "Successfully altered partitions for topic: $topic"
    else
        echo "Failed to alter partitions for topic: $topic"
    fi
done