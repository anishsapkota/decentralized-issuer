use std::{
    fs::File,
    io::{Error, Read},
    path::Path,
};

use base64::{decode_config, encode_config, STANDARD, URL_SAFE_NO_PAD};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    frost_lib::{
        keygen::KeyPair,
        sign::{validate, Signature},
    },
    NodeState,
};

#[derive(Serialize, Deserialize)]
pub struct JWTHeader {
    pub alg: String,
    pub typ: String,
}

#[derive(Deserialize)]
pub struct VerifyPayload {
    pub jwt: String,
    pub public_pem: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JWTPayload {
    pub message: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

pub fn group_pubkey_to_pem(pubkey: &RistrettoPoint) -> String {
    let pubkey_bytes = pubkey.compress().to_bytes();
    let pubkey_b64 = encode_config(&pubkey_bytes, STANDARD);

    // Split the base64 string into lines of 64 characters
    let lines = pubkey_b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("\n");

    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        lines
    );
    pem
}

pub fn pubkey_from_pem(pem: &str) -> Result<RistrettoPoint, &'static str> {
    let pem_lines: Vec<&str> = pem.lines().collect();
    if pem_lines.len() < 3 {
        return Err("Invalid PEM format");
    }

    let content_lines = &pem_lines[1..pem_lines.len() - 1]; // Exclude header and footer

    let content = content_lines.join("");
    let pubkey_bytes = decode_config(&content, STANDARD).map_err(|_| "Invalid base64 in PEM")?;

    if pubkey_bytes.len() != 32 {
        return Err("Invalid public key length");
    }

    let compressed = CompressedRistretto::from_slice(&pubkey_bytes);
    let pubkey = compressed.decompress().ok_or("Invalid public key data")?;
    Ok(pubkey)
}

pub fn check_and_read_keypair(state: NodeState) -> Result<bool, Error> {
    let file_path = format!("keys/{}_key.txt", state.node_id);

    if Path::new(&file_path).exists() {
        // If the file exists, open it and read the contents
        let mut file = File::open(&file_path)?;
        let mut file_content = String::new();
        file.read_to_string(&mut file_content)?;

        // Deserialize the content into a KeyPair struct and return it
        let keypair: KeyPair = serde_json::from_str(&file_content)?;
        let db = &state.keypair_db;
        let _ = db.insert(state.node_id, keypair.clone());
        return Ok(true);
    }
    Ok(false)
}

pub fn verify_jwt(jwt_str: &str, pubkey_pem: &str) -> Result<(), &'static str> {
    // Split JWT into header, payload, signature
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format");
    }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Reconstruct the message (header.payload) and hash it
    let mut hasher = Sha256::new();
    hasher.update(format!("{}.{}", header_b64, payload_b64).as_bytes());
    let result = hasher.finalize();

    let msg = hex::encode(result);

    // Decode the signature
    let signature_bytes =
        decode_config(signature_b64, URL_SAFE_NO_PAD).map_err(|_| "Failed to decode signature")?;

    if signature_bytes.len() != 64 {
        return Err("Invalid signature length");
    }

    let r_bytes = &signature_bytes[0..32];
    let z_bytes = &signature_bytes[32..64];

    let compressed_r = CompressedRistretto::from_slice(r_bytes);
    let r_point = compressed_r.decompress().ok_or("Invalid R point")?;

    let z_scalar =
        Scalar::from_canonical_bytes(z_bytes.try_into().unwrap()).ok_or("Invalid z scalar")?;

    let sig = Signature {
        r: r_point,
        z: z_scalar,
    };

    // Get the public key from PEM
    let pubkey = pubkey_from_pem(pubkey_pem)?;

    // Use validate function
    validate(&msg, &sig, pubkey)
}
