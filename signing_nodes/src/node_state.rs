use crate::frost_lib::keygen::{KeyGenDKGPropsedCommitment, KeyPair, Share};
use crate::frost_lib::sign::{SigningCommitment, SigningResponse};
use rdkafka::producer::FutureProducer;
use scc::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::oneshot;

pub type Db<T> = Arc<HashMap<u32, T>>;

#[derive(Clone)]
pub struct SigningSession {
    pub selected_signers: Arc<HashMap<u32, ()>>, // Set of selected signers for this session
    pub signing_commitments_db: Db<SigningCommitment>,
    pub signing_responses_db: Db<SigningResponse>,
    pub signers_pubkeys_db: Db<curve25519_dalek::ristretto::RistrettoPoint>,
}

#[derive(Clone)]
pub struct NodeState {
    pub node_id: u32,
    pub total_nodes: u32,
    pub threshold: u32,
    // In mem Databases
    pub commitments_db: Db<KeyGenDKGPropsedCommitment>,
    pub shares_db: Db<Vec<Share>>,
    pub keypair_db: Db<KeyPair>,
    // Signing session per request
    pub signing_requests: Arc<Mutex<std::collections::HashMap<String, oneshot::Sender<String>>>>,
    pub signing_sessions: Arc<HashMap<String, SigningSession>>,
    // Leader Election
    pub is_master: Arc<Mutex<bool>>,
    pub master_id: Arc<Mutex<u32>>,
    pub last_heartbeat: Arc<HashMap<u32, Instant>>,
    // Kafka
    pub producer: FutureProducer,
}
