use crate::frost_lib::keygen::{KeyGenDKGPropsedCommitment, Share};
use crate::frost_lib::sign::{SigningCommitment, SigningResponse};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct BroadcastCommitmentData {
    pub sender: u32,
    pub commitment: KeyGenDKGPropsedCommitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShareData {
    pub sender: u32,
    pub receiver: u32,
    pub share: Share,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningCommitmentData {
    pub sender: u32,
    pub commitment: SigningCommitment,
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningResponseData {
    pub sender: u32,
    pub signer_pubkey: RistrettoPoint,
    pub response: SigningResponse,
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Heartbeat {
    pub sender: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MasterAnnouncement {
    pub master_id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningRequest {
    pub payload: String, //serde_json::Value,
    pub selected_signers: Vec<u32>,
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningResult {
    pub request_id: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderPayloadHash {
    pub msg: String,
}