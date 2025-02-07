
use base64::{encode_config, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

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

