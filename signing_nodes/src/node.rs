use crate::constants::CONTEXT;
use crate::frost_lib::keygen::{
    keygen_begin, keygen_finalize, keygen_receive_commitments_and_validate_peers,
    KeyGenDKGPropsedCommitment, Share,
};
use crate::frost_lib::sign::{
    aggregate, preprocess, sign, validate, SigningCommitment, SigningResponse,
};
use crate::messages::*;
use crate::node_state::{NodeState, SigningSession};
use crate::utils::{group_pubkey_to_pem, verify_jwt, VerifyPayload};
use actix_web::http::StatusCode;
use base64::{encode_config, URL_SAFE_NO_PAD};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::prelude::SliceRandom;
use rand::rngs::OsRng;
use rdkafka::message::OwnedMessage;
use rdkafka::producer::FutureRecord;
use rdkafka::Message;
use scc::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::time::sleep;
use uuid::Uuid;
use warp::Filter;

pub async fn process_message(state: &NodeState, msg: OwnedMessage) {
    let payload = match msg.payload_view::<str>() {
        Some(Ok(s)) => s,
        Some(Err(e)) => {
            println!("Error while deserializing message payload: {:?}", e);
            return;
        }
        None => return,
    };
    match msg.topic() {
        "commitments" => {
            let data: BroadcastCommitmentData = serde_json::from_str(payload).unwrap();
            receive_commitment(state, data).await;
        }
        topic if topic.starts_with("shares-") => {
            let data: ShareData = serde_json::from_str(payload).unwrap();
            receive_share(state, data).await;
        }
        "signing_commitments" => {
            let data: SigningCommitmentData = serde_json::from_str(payload).unwrap();
            receive_signing_commitment(state, data).await;
        }
        "signing_responses" => {
            let data: SigningResponseData = serde_json::from_str(payload).unwrap();
            receive_signing_response(state, data).await;
        }
        "heartbeats" => {
            let data: Heartbeat = serde_json::from_str(payload).unwrap();
            handle_heartbeat(state, data).await;
        }
        "master_announcements" => {
            let data: MasterAnnouncement = serde_json::from_str(payload).unwrap();
            handle_master_announcement(state, data).await;
        }
        "signing_requests" => {
            let data: SigningRequest = serde_json::from_str(payload).unwrap();
            handle_signing_request(state, data).await;
        }
        "signing_results" => {
            let data: SigningResult = serde_json::from_str(payload).unwrap();
            handle_signing_result(state, data).await;
        }

        _ => {}
    }
}

pub async fn start_keygen(state: NodeState) {
    let mut rng = OsRng;
    let node_id = state.node_id;
    let total_nodes = state.total_nodes;
    let threshold = state.threshold;
    let context = CONTEXT;

    // Begin the key generation protocol
    let (commitment, shares) =
        keygen_begin(total_nodes, threshold, node_id, context, &mut rng).unwrap();

    // Broadcast the commitment to other nodes via Kafka
    broadcast_commitment(&state, commitment.clone()).await;

    // Send shares to corresponding nodes via Kafka
    send_shares(&state, shares.clone()).await;
}

pub async fn broadcast_commitment(state: &NodeState, commitment: KeyGenDKGPropsedCommitment) {
    let data = BroadcastCommitmentData {
        sender: state.node_id,
        commitment,
    };

    let payload = serde_json::to_string(&data).unwrap();
    let key_str = state.node_id.to_string();

    let record: FutureRecord<String, String> = FutureRecord::to("commitments")
        .payload(&payload)
        .key(&key_str);

    let _ = state
        .producer
        .send(record, Duration::from_secs(0))
        .await
        .unwrap();
}

pub async fn send_shares(state: &NodeState, shares: Vec<Share>) {
    for share in shares {
        let receiver = share.receiver_index;
        // Send share via Kafka regardless of receiver
        let data = ShareData {
            sender: state.node_id,
            receiver,
            share: share.clone(),
        };

        let payload = serde_json::to_string(&data).unwrap();
        let topic = format!("shares-{}", receiver);
        let key_str = state.node_id.to_string();

        let record: FutureRecord<String, String> =
            FutureRecord::to(&topic).payload(&payload).key(&key_str);

        let _ = state
            .producer
            .send(record, Duration::from_secs(0))
            .await
            .unwrap();
    }
}

pub async fn receive_commitment(state: &NodeState, data: BroadcastCommitmentData) {
    let db = &state.commitments_db;
    let sender = data.sender;
    let _ = db.insert(sender, data.commitment.clone());
}

pub async fn receive_share(state: &NodeState, data: ShareData) {
    let db: &Arc<HashMap<u32, Vec<Share>>> = &state.shares_db;

    if data.receiver != state.node_id {
        println!("Received share for incorrect receiver: {}", data.receiver);
        return;
    }

    db.entry(data.receiver)
        .and_modify(|shares| shares.push(data.share.clone()))
        .or_insert_with(|| vec![data.share.clone()]);
}

pub async fn finalize_keygen(state: NodeState) {
    let context = CONTEXT;

    // Wait until all commitments are received
    loop {
        let ready = {
            let db = &state.commitments_db;
            db.len() >= state.total_nodes as usize
        };
        if ready {
            break;
        } else {
            sleep(Duration::from_secs(1)).await;
        }
    }

    // Wait until all shares are received
    loop {
        let ready = {
            let db = &state.shares_db;
            match db.read(&state.node_id, |_, v| v.clone()) {
                Some(shares) => {
                    if shares.len() >= (state.total_nodes - 1) as usize {
                        true
                    } else {
                        println!("Node {} shares_len: {}", state.node_id, shares.len());
                        false
                    }
                }
                _ => false,
            }
        };
        if ready {
            break;
        } else {
            sleep(Duration::from_secs(1)).await;
        }
    }

    // Validate commitments
    let peer_commitments: Vec<KeyGenDKGPropsedCommitment> = {
        let db = &state.commitments_db;
        let mut commitments = Vec::new();

        db.scan(|_key, value| {
            commitments.push(value.clone());
        });
        commitments
    };

    let (invalid_peers, valid_commitments) =
        match keygen_receive_commitments_and_validate_peers(peer_commitments, context) {
            Ok(result) => result,
            Err(e) => {
                println!("Validation error: {:?}", e);
                return;
            }
        };

    if !invalid_peers.is_empty() {
        println!("Invalid peers detected: {:?}", invalid_peers);
        return;
    }

    // Finalize key generation
    let keypair: crate::frost_lib::keygen::KeyPair = {
        let db = &state.shares_db;
        let shares = db.read(&state.node_id, |_, v| v.clone()).unwrap();
        match keygen_finalize(state.node_id, state.threshold, &shares, &valid_commitments) {
            Ok(kp) => kp,
            Err(e) => {
                println!("Keygen error: {:?}", e);
                return;
            }
        }
    };

    {
        // Store our keypair
        let db = &state.keypair_db;
        let _ = db.insert(state.node_id, keypair.clone());
    }

    let mut file = File::create(format!("keys/{}_key.txt", state.node_id)).expect(&format!(
        "Cannot create key file for node {}",
        state.node_id
    ));
    let _ = file.write_all(serde_json::to_string(&keypair).unwrap().as_bytes());

    if *state.is_master.lock().unwrap() {
        let mut file = File::create("keys/group_key.pem").expect(&format!(
            "Cannot create group_key.pem file for node {}",
            state.node_id
        ));
        let _ = file.write_all(group_pubkey_to_pem(&keypair.group_public).as_bytes());
    }

    println!("Node {}: Key generation finalized", state.node_id);
}

pub async fn leader_election(state: NodeState) {
    // Simple leader election: Node with the lowest ID becomes the master
    {
        let mut master_id = state.master_id.lock().unwrap();
        *master_id = 1;
    }

    if state.node_id == 1 {
        {
            let mut is_master = state.is_master.lock().unwrap();
            *is_master = true;
        }

        println!("Node {} is elected as the master", state.node_id);

        // Broadcast master announcement
        broadcast_master_announcement(state.clone()).await;
    } else {
        println!("Node {} recognizes Node {} as the master", state.node_id, 1);
    }
}

pub async fn broadcast_master_announcement(state: NodeState) {
    let data = MasterAnnouncement {
        master_id: state.node_id,
    };

    let payload = serde_json::to_string(&data).unwrap();
    let key_str = state.node_id.to_string();

    let record: FutureRecord<String, String> = FutureRecord::to("master_announcements")
        .payload(&payload)
        .key(&key_str);

    let _ = state
        .producer
        .send(record, Duration::from_secs(0))
        .await
        .unwrap();
}

pub async fn handle_master_announcement(state: &NodeState, data: MasterAnnouncement) {
    let mut master_id = state.master_id.lock().unwrap();
    *master_id = data.master_id;

    let mut is_master = state.is_master.lock().unwrap();
    *is_master = state.node_id == data.master_id;
}

pub async fn send_heartbeat(state: NodeState) {
    loop {
        let data = Heartbeat {
            sender: state.node_id,
        };

        let payload = serde_json::to_string(&data).unwrap();
        let key_str = state.node_id.to_string();

        let record: FutureRecord<String, String> = FutureRecord::to("heartbeats")
            .payload(&payload)
            .key(&key_str);

        let _ = state
            .producer
            .send(record, Duration::from_secs(0))
            .await
            .unwrap();

        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn handle_heartbeat(state: &NodeState, data: Heartbeat) {
    println!("{}: heartbeat from {}", state.node_id, data.sender);
    let db = &state.last_heartbeat;
    let _ = db.insert(data.sender, Instant::now());
}

pub async fn detect_failure(state: NodeState) {
    loop {
        sleep(Duration::from_secs(2)).await;

        let master_id = {
            let master_id = state.master_id.lock().unwrap();
            *master_id
        };

        if master_id == state.node_id {
            // I'm the master; no need to check
            continue;
        }

        let last_heartbeat_time = {
            let db = &state.last_heartbeat;
            db.read(&master_id, |_, v| *v)
        };

        if let Some(last_heartbeat_time) = last_heartbeat_time {
            if last_heartbeat_time.elapsed() > Duration::from_secs(20) {
                println!(
                    "Node {}: Master {} failed. Initiating leader election.",
                    state.node_id, master_id
                );
                leader_election(state.clone()).await;
            }
        } else {
            // No heartbeat received yet
            println!(
                "Node {}: No heartbeat from master {}. Initiating leader election.",
                state.node_id, master_id
            );
            leader_election(state.clone()).await;
        }
    }
}

pub async fn initiate_signing(state: NodeState, payload: String, request_id: String) {
    // Master selects signers
    let mut rng = OsRng;
    let mut nodes: Vec<u32> = (1..=state.total_nodes).collect();
    nodes.shuffle(&mut rng);

    let selected_signers: Vec<u32> = nodes.into_iter().take(state.threshold as usize).collect();

    // println!(
    //     "Req: {} selected signers: {:?}",
    //     request_id, selected_signers
    // );

    // Broadcast signing request
    let data = SigningRequest {
        payload,
        selected_signers: selected_signers.clone(),
        request_id: request_id.to_string(),
    };

    let payload = serde_json::to_string(&data).unwrap();
    let key_str = state.node_id.to_string();

    let record: FutureRecord<String, String> = FutureRecord::to("signing_requests")
        .payload(&payload)
        .key(&key_str);

    let _ = state
        .producer
        .send(record, Duration::from_secs(0))
        .await
        .unwrap();
}

pub async fn handle_signing_request(state: &NodeState, data: SigningRequest) {
    let is_selected = data.selected_signers.contains(&state.node_id);

    // Create a new SigningSession
    let signing_session = SigningSession {
        selected_signers: Arc::new(HashMap::default()),
        signing_commitments_db: Arc::new(HashMap::default()),
        signing_responses_db: Arc::new(HashMap::default()),
        signers_pubkeys_db: Arc::new(HashMap::default()),
    };

    {
        let signers = &signing_session.selected_signers;
        for signer in &data.selected_signers {
            let _ = signers.insert(*signer, ());
        }
    }

    // Insert the session into the state's signing_sessions
    let _ = state
        .signing_sessions
        .insert(data.request_id.clone(), signing_session);

    if is_selected {
        // Retrieve the session
        let session = state
            .signing_sessions
            .read(&data.request_id, |_, v| v.clone())
            .unwrap();

        let keypair = {
            let db = &state.keypair_db;
            match db.read(&state.node_id, |_, v| v.clone()) {
                Some(kp) => kp.clone(),
                None => {
                    println!("Keypair not generated yet");
                    return;
                }
            }
        };

        let mut rng = OsRng;
        let (commitments, mut nonces) = match preprocess(1, state.node_id, &mut rng) {
            Ok(result) => result,
            Err(e) => {
                println!("Preprocess error: {:?}", e);
                return;
            }
        };

        // Broadcast signing commitment via Kafka
        broadcast_signing_commitment(&state, commitments[0].clone(), data.request_id.clone()).await;

        let mut selected_signers_sorted = data.selected_signers.clone();
        selected_signers_sorted.sort();

        // Wait until all signing commitments are received
        loop {
            let ready = {
                let db = &session.signing_commitments_db;
                db.len() >= state.threshold as usize
            };
            if ready {
                break;
            } else {
                sleep(Duration::from_secs(1)).await;
            }
        }

        // Collect all signing commitments
        let signing_commitments: Vec<SigningCommitment> = {
            let db = &session.signing_commitments_db;
            selected_signers_sorted
                .iter()
                .map(|key| db.get(key).unwrap().clone())
                .collect()
        };

        // Sign the message
        //let msg = generate_jwt_header_and_payload(&data.payload);

        let response = match sign(&keypair, &signing_commitments, &mut nonces, &data.payload) {
            Ok(resp) => resp,
            Err(e) => {
                println!("Signing error: {:?}", e);
                return;
            }
        };

        // Broadcast signing response via Kafka
        broadcast_signing_response(&state, response.clone(), data.request_id.clone()).await;

        // Wait until all signing responses are received
        loop {
            let ready = {
                let db = &session.signing_responses_db;
                db.len() >= state.threshold as usize
            };
            if ready {
                break;
            } else {
                sleep(Duration::from_secs(1)).await;
            }
        }

        // Collect all signing responses
        let signing_responses: Vec<SigningResponse> = {
            let db = &session.signing_responses_db;
            selected_signers_sorted
                .iter()
                .map(|key| db.get(key).unwrap().clone())
                .collect()
        };

        // Collect signer public keys
        let signer_pubkeys: std::collections::HashMap<u32, RistrettoPoint> = {
            let db = &session.signers_pubkeys_db;
            let mut pubkeys = std::collections::HashMap::new();

            db.scan(|key, value| {
                if data.selected_signers.contains(key) {
                    pubkeys.insert(*key, value.clone());
                }
            });

            pubkeys
        };

        let group_sig = match aggregate(
            &data.payload,
            &signing_commitments,
            &signing_responses,
            &signer_pubkeys,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                println!("Aggregation error: {:?}", e);
                return;
            }
        };

        // Verify the signature
        let group_public_key = keypair.group_public;
        if let Err(e) = validate(&data.payload, &group_sig, group_public_key) {
            println!("Signature validation failed: {:?}", e);
            return;
        }

        // Return the signed JWT
        let r_bytes = group_sig.r.compress().to_bytes(); // [u8; 32]
        let z_bytes = group_sig.z.to_bytes(); // [u8; 32]

        let mut signature_bytes = Vec::with_capacity(64);
        signature_bytes.extend_from_slice(&r_bytes);
        signature_bytes.extend_from_slice(&z_bytes);

        let signature_b64 = encode_config(&signature_bytes, URL_SAFE_NO_PAD);
        //let signed_jwt = format!("{}.{}", msg, signature_b64);

        if selected_signers_sorted[0] == state.node_id {
            // println!(
            //     "Node {} req: {} -> Signed JWT: {}",
            //     state.node_id, data.request_id, signed_jwt
            // );

            let response_data = SigningResult {
                request_id: data.request_id.clone(),
                signature: signature_b64.clone(),
            };

            let payload = serde_json::to_string(&response_data).unwrap();
            let key_str = state.node_id.to_string();

            let record: FutureRecord<String, String> = FutureRecord::to("signing_results")
                .payload(&payload)
                .key(&key_str);

            let _ = state
                .producer
                .send(record, Duration::from_secs(0))
                .await
                .unwrap();
        }
        // Clean up the session
        state.signing_sessions.remove(&data.request_id);
        // println!(
        //     "Node {} : signing completed for request id: {} ",
        //     state.node_id, data.request_id
        // );
        // state
        //     .signing_requests
        //     .lock()
        //     .unwrap()
        //     .remove(&data.request_id);
    }
}

pub async fn broadcast_signing_commitment(
    state: &NodeState,
    commitment: SigningCommitment,
    request_id: String,
) {
    let data = SigningCommitmentData {
        sender: state.node_id,
        commitment,
        request_id,
    };

    let payload = serde_json::to_string(&data).unwrap();
    let key_str = state.node_id.to_string();

    let record: FutureRecord<String, String> = FutureRecord::to("signing_commitments")
        .payload(&payload)
        .key(&key_str);

    let _ = state
        .producer
        .send(record, Duration::from_secs(0))
        .await
        .unwrap();
}

pub async fn broadcast_signing_response(
    state: &NodeState,
    response: SigningResponse,
    request_id: String,
) {
    let signer_pubkey = {
        let db = &state.keypair_db;
        db.get(&state.node_id).unwrap().public.clone()
    };

    let data = SigningResponseData {
        sender: state.node_id,
        signer_pubkey,
        response,
        request_id,
    };

    let payload = serde_json::to_string(&data).unwrap();
    let key_str = state.node_id.to_string();

    let record: FutureRecord<String, String> = FutureRecord::to("signing_responses")
        .payload(&payload)
        .key(&key_str);

    let _ = state
        .producer
        .send(record, Duration::from_secs(0))
        .await
        .unwrap();
}

pub async fn receive_signing_commitment(state: &NodeState, data: SigningCommitmentData) {
    let max_retries = 3;
    let retry_delay = Duration::from_millis(500);
    let mut attempts = 0;

    let session = loop {
        match state
            .signing_sessions
            .read(&data.request_id, |_, v| v.clone())
        {
            Some(session) => {
                // If session is found, break the loop and return the session
                break session;
            }
            None => {
                // If session is not found
                attempts += 1;
                if attempts >= max_retries {
                    println!(
                        "Node {} --> sign_com: No signing session found for request ID {} after {} attempts",
                        state.node_id, data.request_id, attempts
                    );
                    return;
                } else {
                    println!(
                        "Node {} --> sign_com: No signing session found for request ID {}, retrying... (attempt {}/{})",
                        state.node_id, data.request_id, attempts, max_retries
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    };

    let is_selected = {
        let signers = &session.selected_signers;
        let node_id_selected = signers.any(|k, _| *k == state.node_id);
        let sender_selected = signers.any(|k, _| *k == data.sender);

        node_id_selected && sender_selected
    };

    if is_selected {
        let db = &session.signing_commitments_db;
        let _ = db.insert(data.sender, data.commitment.clone());
    }
}

pub async fn receive_signing_response(state: &NodeState, data: SigningResponseData) {
    let session = match state
        .signing_sessions
        .read(&data.request_id, |_, v| v.clone())
    {
        Some(session) => session,
        None => {
            println!(
                " Node {} --> sign_res : No signing session found for request ID {}",
                state.node_id, data.request_id
            );
            return;
        }
    };

    let is_selected = {
        let signers = &session.selected_signers;
        let node_id_selected = signers.any(|k, _| *k == state.node_id);
        let sender_selected = signers.any(|k, _| *k == data.sender);

        node_id_selected && sender_selected
    };

    if is_selected {
        let db = &session.signing_responses_db;
        let _ = db.insert(data.sender, data.response.clone());

        let signers_pubkeys_db = &session.signers_pubkeys_db;
        let _ = signers_pubkeys_db.insert(data.sender, data.signer_pubkey);
    }
}

pub async fn start_http_server(state: NodeState) {
    let state_filter = warp::any().map(move || state.clone());

    let sign_route = warp::post()
        .and(warp::path("sign"))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|payload: HeaderPayloadHash, state: NodeState| async move {
            let request_id: Uuid = Uuid::new_v4();
            println!("Received signing request with request_id {}", request_id);

            let (tx, rx) = oneshot::channel();

            // Store the sender in the state's signing_requests
            {
                let mut signing_requests = state.signing_requests.lock().unwrap();
                let _ = signing_requests.insert(request_id.to_string(), tx);
            }

            tokio::spawn(async move {
                initiate_signing(state, payload.msg, request_id.to_string()).await;
            });

            //Wait for the signature
            match rx.await {
                Ok(signature) => Ok::<_, warp::Rejection>(warp::reply::json(&signature)),
                Err(_) => Err(warp::reject::not_found()),
            }
        });

    let verify_route = warp::post()
        .and(warp::path("verify"))
        .and(warp::body::json())
        .and_then(|payload: VerifyPayload| async move {
            match verify_jwt(&payload.jwt, &payload.public_pem) {
                Ok(_) => Ok::<_, warp::Rejection>(warp::reply::with_status(
                    "JWT is valid".to_string(),
                    StatusCode::OK,
                )),
                Err(err) => Ok::<_, warp::Rejection>(warp::reply::with_status(
                    format!("JWT verification failed: {}", err),
                    StatusCode::UNAUTHORIZED,
                )),
            }
        });

    // Combine the routes
    let routes = sign_route.or(verify_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

pub async fn handle_signing_result(state: &NodeState, data: SigningResult) {
    // Retrieve the oneshot sender from the state's signing_requests
    let is_master = {
        let is_master_lock = state.is_master.lock().unwrap();
        *is_master_lock
    };

    let sender = {
        let mut signing_requests = state.signing_requests.lock().unwrap();
        signing_requests.remove(&data.request_id)
    };

    if is_master {
        if let Some(tx) = sender {
            if tx.send(data.signature).is_err() {
                eprintln!(
                    "Failed to send signing result for request {}",
                    data.request_id
                );
            }
            println!("Responded with signed jwt: {}", data.request_id);
        } else {
            eprintln!(
                "No sender found for request {} {}",
                state.node_id, data.request_id
            );
        }
        // println!(
        //     "Node {} req_id {} : res {}",
        //     state.node_id, data.request_id, data.signed_jwt
        // );
    }
}
