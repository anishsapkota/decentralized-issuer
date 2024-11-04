mod broker;
mod constants;
mod frost_lib;
mod messages;
mod node;
mod node_state;
mod utils;

use broker::{consume_messages, create_consumer};
use frost_lib::keygen::{KeyGenDKGPropsedCommitment, KeyPair, Share};
use node::{finalize_keygen, initiate_signing, leader_election, start_http_server, start_keygen};
use node_state::{Db, NodeState};
use scc::HashMap;
use utils::check_and_read_keypair;

use rdkafka::consumer::StreamConsumer;
use rdkafka::producer::FutureProducer;
use rdkafka::ClientConfig;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short = 'n', long, default_value_t = 5)]
    num_nodes: usize,

    #[arg(short = 't', long, default_value_t = 3)]
    threshold: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let num_nodes = args.num_nodes;
    let threshold = args.threshold;

    let mut tasks = Vec::new();

    println!("Number of nodes: {}", num_nodes);
    println!("Threshold: {}", threshold);

    for i in 0..num_nodes {
        let node_id = i as u32 + 1; // Node IDs start from 1
        let total_nodes = num_nodes as u32;
        let threshold = threshold as u32;

        let task = tokio::spawn(async move {
            // Initialize Kafka producer and consumer
            let producer: FutureProducer = ClientConfig::new()
                .set("bootstrap.servers", "localhost:9092")
                .set("compression.type", "lz4")
                .create()
                .expect("Producer creation error");

            let consumer1: StreamConsumer = create_consumer(node_id, 0)
                .await
                .expect("Consumer1 creation failed");
            // let consumer2: StreamConsumer = create_consumer(node_id, 1)
            //     .await
            //     .expect("Consumer2 creation failed");
            // let consumer3: StreamConsumer = create_consumer(node_id, 2)
            //     .await
            //     .expect("Consumer2 creation failed");

            // Initialize node state
            let commitments_db: Db<KeyGenDKGPropsedCommitment> = Arc::new(HashMap::default());
            let shares_db: Db<Vec<Share>> = Arc::new(HashMap::default());
            let keypair_db: Db<KeyPair> = Arc::new(HashMap::default());

            let signing_requests = Arc::new(Mutex::new(std::collections::HashMap::new()));

            let is_master = Arc::new(Mutex::new(false));
            let master_id = Arc::new(Mutex::new(0));
            let last_heartbeat = Arc::new(HashMap::default());
            let signing_sessions = Arc::new(HashMap::default());

            let state = NodeState {
                node_id,
                total_nodes,
                threshold,
                commitments_db,
                shares_db,
                keypair_db,
                signing_requests,
                is_master,
                master_id,
                last_heartbeat,
                signing_sessions,
                producer: producer.clone(),
            };

            // Start background tasks
            let consumer_state1 = state.clone();
            // let consumer_state2 = state.clone();
            // let consumer_state3 = state.clone();

            let consumer_task1 = tokio::spawn(async move {
                consume_messages(consumer_state1, consumer1).await;
            });

            // let consumer_task2 = tokio::spawn(async move {
            //     consume_messages(consumer_state2, consumer2).await;
            // });
            // let consumer_task3 = tokio::spawn(async move {
            //     consume_messages(consumer_state3, consumer3).await;
            // });

            //let failure_detector_state = state.clone();
            // let failure_detector_task = tokio::spawn(async move {
            //     detect_failure(failure_detector_state).await;
            // });

            // Wait a bit for all nodes to start
            sleep(Duration::from_secs(2)).await;

            // Leader Election
            leader_election(state.clone()).await;

            // Wait a bit
            sleep(Duration::from_secs(2)).await;

            if !check_and_read_keypair(state.clone()).unwrap() {
                println!("No keys found: initiating distributed key-gen");

                // Start key generation
                start_keygen(state.clone()).await;

                // Wait for key generation to complete
                sleep(Duration::from_secs(5)).await;

                // Finalize key generation
                finalize_keygen(state.clone()).await;
            }

            // Wait a bit
            sleep(Duration::from_secs(2)).await;

            {
                let is_master = {
                    let is_master_lock = state.is_master.lock().unwrap();
                    *is_master_lock
                };

                let mut http_task = None;
                //let mut heartbeat_task = None;
                if is_master {
                    // let heartbeat_state = state.clone();
                    // let _heartbeat_task = tokio::spawn(async move {
                    //     send_heartbeat(heartbeat_state).await;
                    // });

                    // heartbeat_task = Some(_heartbeat_task);

                    println!("Node {}: Starting HTTP server", state.node_id);
                    let http_state = state.clone();
                    let task = tokio::spawn(async move {
                        start_http_server(http_state).await;
                    });
                    http_task = Some(task);

                    // for i in 0..10 {
                    //     let payload = serde_json::json!({
                    //             "message": i
                    //     });
                    //     initiate_signing(state.clone(), payload, i.to_string()).await;
                    //     // if i == 5 {
                    //     //tokio::time::sleep(Duration::from_secs(2)).await;
                    //     // }
                    // }
                }
                consumer_task1.await.unwrap();
                // consumer_task2.await.unwrap();
                // consumer_task3.await.unwrap();

                //failure_detector_task.await.unwrap();

                // if let Some(task) = heartbeat_task {
                //     task.await.unwrap();
                // }

                if let Some(task) = http_task {
                    task.await.unwrap();
                }
            }
            // Wait for the background tasks to finish
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.unwrap();
    }

    Ok(())
}
