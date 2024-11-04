use std::io::Read;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Serialize, Deserialize)]
pub struct JWTHeader {
    pub alg: String,
    pub typ: String,
    pub hash_alg: String,
}

pub fn generate_jwt_header_and_payload(payload: &serde_json::Value) -> String {
    let header = JWTHeader {
        alg: "SCHNORR".to_string(),
        typ: "JWT".to_string(),
        hash_alg: "SHA256".to_string(),
    };

    let header_json: String = serde_json::to_string(&header).unwrap();
    let payload_json = serde_json::to_string(&payload).unwrap();

    let header_b64 = encode_config(header_json, URL_SAFE_NO_PAD);
    let payload_b64 = encode_config(payload_json, URL_SAFE_NO_PAD);

    let message = format!("{}.{}", header_b64, payload_b64);

    return message;
}



pub fn hash_to_scalar(message: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];  
    hash_bytes.copy_from_slice(&hash); 
    Scalar::from_bytes_mod_order(hash_bytes) 
}

pub struct BlindedMessage {
    pub blinded_message: Scalar,
    pub blinding_factor: Scalar,
}

pub fn blind_message(message:&[u8]) -> BlindedMessage {
    let blinding_factor = Scalar::random(&mut OsRng);
    let message_hash = hash_to_scalar(message);
    let blinded_message = message_hash * blinding_factor;
    BlindedMessage {
        blinded_message,
        blinding_factor
    }
}