use base64::{decode_config, encode_config, STANDARD, URL_SAFE_NO_PAD};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};

use crate::frost_lib::keygen::{self, KeyGenDKGCommitment};

#[derive(Serialize, Deserialize)]
pub struct JWTHeader {
    pub alg: String,
    pub typ: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JWTPayload {
    pub message: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

/// generates the langrange coefficient for the ith participant. This allows
/// for performing Lagrange interpolation, which underpins threshold secret
/// sharing schemes based on Shamir secret sharing.
pub fn get_lagrange_coeff(
    x_coord: u32,
    signer_index: u32,
    all_signer_indices: &Vec<u32>,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in all_signer_indices {
        if *j == signer_index {
            continue;
        }
        num *= Scalar::from(*j) - Scalar::from(x_coord);
        den *= Scalar::from(*j) - Scalar::from(signer_index);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

pub fn get_ith_pubkey(index: u32, commitments: &Vec<KeyGenDKGCommitment>) -> RistrettoPoint {
    let mut ith_pubkey = RistrettoPoint::identity();
    let term = Scalar::from(index);

    // iterate over each commitment
    for commitment in commitments {
        let mut result = RistrettoPoint::identity();
        let t = commitment.shares_commitment.commitment.len() as u32;
        // iterate  over each element in the commitment
        for (inner_index, comm_i) in commitment
            .shares_commitment
            .commitment
            .iter()
            .rev()
            .enumerate()
        {
            result += comm_i;

            // handle constant term
            if inner_index as u32 != t - 1 {
                result *= term;
            }
        }

        ith_pubkey += result;
    }

    ith_pubkey
}
//    let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &share.value;
//
//    let term = Scalar::from(share.receiver_index);
//    let mut result = RistrettoPoint::identity();
//
//    // Thanks to isis lovecruft for their simplification to Horner's method;
//    // including it here for readability. Their implementation of FROST can
//    // be found here: github.com/isislovecruft/frost-dalek
//    for (index, comm_i) in com.commitment.iter().rev().enumerate() {
//        result += comm_i;
//
//        if index != com.commitment.len() - 1 {
//            result *= term;
//        }
//    }
//
//    if !(f_result == result) {
//        return Err("Share is invalid.");
//    }

pub fn generate_jwt_header_and_payload(payload: &serde_json::Value) -> String {
    let header = JWTHeader {
        alg: "SCHNORR".to_string(),
        typ: "JWT".to_string(),
    };

    let header_json: String = serde_json::to_string(&header).unwrap();
    let payload_json = serde_json::to_string(&payload).unwrap();

    let header_b64 = encode_config(header_json, URL_SAFE_NO_PAD);
    let payload_b64 = encode_config(payload_json, URL_SAFE_NO_PAD);

    let message = format!("{}.{}", header_b64, payload_b64);

    return message;
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

// fn generate_JWT_with_signature(message: &String) -> String {
//     let (r, s) = sign(message.as_bytes(), keypair);

//     let signature_b64 = encode_config(
//         format!("{}:{}", r.to_str_radix(16), s.to_str_radix(16)),
//         URL_SAFE_NO_PAD,
//     );

//     format!("{}.{}.{}", header_b64, payload_b64, signature_b64)
// }
