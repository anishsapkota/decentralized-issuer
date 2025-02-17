mod broker;
mod constants;
mod frost_lib;
mod messages;
mod node;
mod node_state;
mod utils;

use broker::{consume_messages, create_consumer, create_producer};
use frost_lib::keygen::{KeyGenDKGPropsedCommitment, KeyPair, Share};
use node::{finalize_keygen, preprocess_nonces_commitments, start_http_server, start_keygen};
use node_state::{Db, NodeState};
use scc::HashMap;
use utils::check_and_read_keypair;
use dotenv::dotenv;
use rdkafka::consumer::StreamConsumer;
use rdkafka::producer::FutureProducer;
use rdkafka::ClientConfig;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'i', long, default_value_t = 1)]
    node_id: u32,

    #[arg(short = 'n', long, default_value_t = 1)]
    total_nodes: usize,

    #[arg(short = 't', long, default_value_t = 1)]
    threshold: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let args = Args::parse();

    let total_nodes = env::var("N")
    .ok()
    .and_then(|s| s.parse::<usize>().ok())
    .unwrap_or(args.total_nodes);

    let threshold = env::var("T")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(args.threshold);
    let node_id = env::var("NODE_ID")
    .ok()
    .and_then(|s| s.parse::<u32>().ok()) 
    .unwrap_or(args.node_id);

    let mode = env::var("MODE").unwrap_or_else(|_| "two_round".to_string());


    println!("Starting node {}", node_id);
    println!("Total nodes: {}", total_nodes);
    println!("Threshold: {}", threshold);
    println!("Mode: {}", mode);

    // Initialize Kafka producer and consumer
    let producer: FutureProducer = create_producer()
        .await
        .expect("Producer creation error");

    let consumer: StreamConsumer = create_consumer(node_id, 0)
        .await
        .expect("Consumer creation failed");

    // Initialize node state
    let commitments_db: Db<KeyGenDKGPropsedCommitment> = Arc::new(HashMap::default());
    let shares_db: Db<Vec<Share>> = Arc::new(HashMap::default());
    let keypair_db: Db<KeyPair> = Arc::new(HashMap::default());

    let signing_requests = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let is_master = Arc::new(Mutex::new(false));
    let master_id = Arc::new(Mutex::new(1));
    let last_heartbeat = Arc::new(HashMap::default());
    let signing_sessions = Arc::new(HashMap::default());

    let state = NodeState {
        node_id: node_id,
        total_nodes: total_nodes as u32,
        threshold: threshold as u32,
        commitments_db,
        shares_db,
        keypair_db,
        signing_requests,
        is_master,
        master_id,
        last_heartbeat,
        signing_sessions,
        producer: producer.clone(),
        preprocessed_nonces: Arc::new(HashMap::default()),
    };

    // Start background tasks
    let consumer_state = state.clone();
    let consumer_task = tokio::spawn(async move {
        consume_messages(consumer_state, consumer).await;
    });

    sleep(Duration::from_secs(4)).await;

    // Check if keypair exists
    if !check_and_read_keypair(state.clone()).unwrap() {
        println!("Node {}: No keys found - initiating DKG", node_id);
        start_keygen(state.clone()).await;
        // sleep(Duration::from_secs(10)).await;
        // finalize_keygen(state.clone()).await;
    }

    // preprocess nonces
    if mode == "one_round" {
        sleep(Duration::from_secs(10)).await;
        preprocess_nonces_commitments(state.clone()).await;
        println!("Node {}: Preprocessing done", node_id);
        sleep(Duration::from_secs(2)).await;
    }

    println!("Node {}: Starting HTTP server", node_id);
    let http_state = state.clone();
    let http_task = tokio::spawn(async move {
        start_http_server(http_state).await;
    });
        
    http_task.await?;
    consumer_task.await?;

    Ok(())
}