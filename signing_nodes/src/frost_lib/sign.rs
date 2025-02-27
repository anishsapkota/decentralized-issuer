use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::frost_lib::helpers::*;
use crate::frost_lib::keygen::KeyPair;

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct SigningResponse {
    pub response: Scalar,
    pub index: u32,
}

impl SigningResponse {
    pub fn is_valid(
        &self,
        pubkey: &RistrettoPoint,
        lambda_i: Scalar,
        commitment: &RistrettoPoint,
        challenge: Scalar,
    ) -> bool {
        (&constants::RISTRETTO_BASEPOINT_TABLE * &self.response)
            == (commitment + (pubkey * (challenge * lambda_i)))
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct SigningCommitment {
    pub index: u32,
    d: RistrettoPoint,
    e: RistrettoPoint,
}

impl SigningCommitment {
    pub fn new(
        index: u32,
        d: RistrettoPoint,
        e: RistrettoPoint,
    ) -> Result<SigningCommitment, &'static str> {
        if d == RistrettoPoint::identity() || e == RistrettoPoint::identity() {
            return Err("Invalid signing commitment");
        }

        Ok(SigningCommitment { d, e, index })
    }
}

#[derive(Copy, Clone, Debug)]
pub struct NoncePair {
    d: Nonce,
    e: Nonce,
}

impl NoncePair {
    pub fn new(rng: &mut OsRng) -> Result<NoncePair, &'static str> {
        let d = Scalar::random(rng);
        let e = Scalar::random(rng);
        let d_pub = &constants::RISTRETTO_BASEPOINT_TABLE * &d;
        let e_pub = &constants::RISTRETTO_BASEPOINT_TABLE * &e;

        if d_pub == RistrettoPoint::identity() || e_pub == RistrettoPoint::identity() {
            return Err("Invalid nonce commitment");
        }

        Ok(NoncePair {
            d: Nonce {
                secret: d,
                public: d_pub,
            },
            e: Nonce {
                secret: e,
                public: e_pub,
            },
        })
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Nonce {
    secret: Scalar,
    pub public: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Signature {
    pub r: RistrettoPoint,
    pub z: Scalar,
}

/// preprocess is performed by each participant; their commitments are published
/// and stored in an external location for later use in signing, while their
/// signing nonces are stored locally.
pub fn preprocess(
    number_commitments: usize,
    participant_index: u32,
    rng: &mut OsRng,
) -> Result<(Vec<SigningCommitment>, Vec<NoncePair>), &'static str> {
    let mut nonces: Vec<NoncePair> = Vec::with_capacity(number_commitments);
    let mut commitments = Vec::with_capacity(number_commitments);

    for _ in 0..number_commitments {
        let nonce_pair = NoncePair::new(rng)?;
        nonces.push(nonce_pair);

        let commitment =
            SigningCommitment::new(participant_index, nonce_pair.d.public, nonce_pair.e.public)?;

        commitments.push(commitment);
    }

    Ok((commitments, nonces))
}

/// sign is performed by each participant selected for the signing
/// operation; these responses are then aggregated into the final FROST
/// signature by the signature aggregator performing the aggregate function
/// with each response.
pub fn sign(
    keypair: &KeyPair,
    signing_commitments: &Vec<SigningCommitment>,
    signing_nonces: &mut Vec<NoncePair>,
    msg: &str,
) -> Result<SigningResponse, &'static str> {
    let mut bindings: HashMap<u32, Scalar> = HashMap::with_capacity(signing_commitments.len());

    for comm in signing_commitments {
        let rho_i = gen_rho_i(comm.index, msg, signing_commitments);
        bindings.insert(comm.index, rho_i);
    }

    let group_commitment = gen_group_commitment(&signing_commitments, &bindings)?;

    let indices = signing_commitments.iter().map(|item| item.index).collect();

    let lambda_i = get_lagrange_coeff(0, keypair.index, &indices)?;

    // find the corresponding nonces for this participant
    let my_comm = signing_commitments
        .iter()
        .find(|item| item.index == keypair.index)
        .ok_or("No signing commitment for signer")?;

    let signing_nonce_position = signing_nonces
        .iter_mut()
        .position(|item| item.d.public == my_comm.d && item.e.public == my_comm.e)
        .ok_or("No matching signing nonce for signer")?;

    let signing_nonce = signing_nonces
        .get(signing_nonce_position)
        .ok_or("cannot retrieve nonce from position~")?;

    let my_rho_i = bindings[&keypair.index];

    let c = generate_challenge(msg, group_commitment);

    let response = signing_nonce.d.secret
        + (signing_nonce.e.secret * my_rho_i)
        + (lambda_i * keypair.secret * c);

    // Now that this nonce has been used, delete it
    signing_nonces.remove(signing_nonce_position);

    Ok(SigningResponse {
        response: response,
        index: keypair.index,
    })
}

/// aggregate collects all responses from participants. It first performs a
/// validity check for each participant's response, and will return an error in the
/// case the response is invalid. If all responses are valid, it aggregates these
/// into a single signature that is published. This function is executed
/// by the entity performing the signature aggregator role.
pub fn aggregate(
    msg: &str,
    signing_commitments: &Vec<SigningCommitment>,
    signing_responses: &Vec<SigningResponse>,
    signer_pubkeys: &HashMap<u32, RistrettoPoint>,
) -> Result<Signature, &'static str> {
    if signing_commitments.len() != signing_responses.len() {
        return Err("Mismatched number of commitments and responses");
    }
    // first, make sure that each commitment corresponds to exactly one response
    let mut commitment_indices = signing_commitments
        .iter()
        .map(|com| com.index)
        .collect::<Vec<u32>>();
    let mut response_indices = signing_responses
        .iter()
        .map(|com| com.index)
        .collect::<Vec<u32>>();

    commitment_indices.sort();
    response_indices.sort();

    if commitment_indices != response_indices {
        return Err("Mismatched commitment without corresponding response");
    }

    let mut bindings: HashMap<u32, Scalar> = HashMap::with_capacity(signing_commitments.len());

    for counter in 0..signing_commitments.len() {
        let comm: SigningCommitment = signing_commitments[counter];
        let rho_i: Scalar = gen_rho_i(comm.index, msg, signing_commitments);
        bindings.insert(comm.index, rho_i);
    }

    let group_commitment = gen_group_commitment(&signing_commitments, &bindings)?;
    let challenge = generate_challenge(msg, group_commitment);

    // check the validity of each participant's response
    for resp in signing_responses {
        let matching_rho_i: Scalar = bindings[&resp.index];

        let indices: Vec<u32> = signing_commitments
            .iter()
            .map(|item: &SigningCommitment| item.index)
            .collect();

        let lambda_i: Scalar = get_lagrange_coeff(0, resp.index, &indices)?;

        let matching_commitment: &SigningCommitment = signing_commitments
            .iter()
            .find(|x: &&SigningCommitment| x.index == resp.index)
            .ok_or("No matching commitment for response")?;

        let commitment_i: RistrettoPoint =
            matching_commitment.d + (matching_commitment.e * matching_rho_i);
        let signer_pubkey: &RistrettoPoint = signer_pubkeys
            .get(&matching_commitment.index)
            .ok_or("commitment does not have a matching signer public key!")?;

        if !resp.is_valid(&signer_pubkey, lambda_i, &commitment_i, challenge) {
            return Err("Invalid signer response");
        }
    }

    let group_resp = signing_responses
        .iter()
        .fold(Scalar::zero(), |acc, x| acc + x.response);

    Ok(Signature {
        r: group_commitment,
        z: group_resp,
    })
}

/// validate performs a plain Schnorr validation operation; this is identical
/// to performing validation of a Schnorr signature that has been signed by a
/// single party.
pub fn validate(msg: &str, sig: &Signature, pubkey: RistrettoPoint) -> Result<(), &'static str> {
    let challenge = generate_challenge(msg, sig.r);
    if sig.r != (&constants::RISTRETTO_BASEPOINT_TABLE * &sig.z) - (pubkey * challenge) {
        return Err("Signature is invalid");
    }

    Ok(())
}

/// generates the challenge value H(m, R) used for both signing and verification.
/// ed25519_ph hashes the message first, and derives the challenge as H(H(m), R),
/// this would be a better optimization but incompatibility with other
/// implementations may be undesirable.
pub fn generate_challenge(msg: &str, group_commitment: RistrettoPoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(group_commitment.compress().to_bytes());
    hasher.update(msg);
    let result = hasher.finalize();

    let x = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(x)
}

fn gen_rho_i(index: u32, msg: &str, signing_commitments: &Vec<SigningCommitment>) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update("I".as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(msg.as_bytes());
    for item in signing_commitments {
        hasher.update(item.index.to_be_bytes());
        hasher.update(item.d.compress().as_bytes());
        hasher.update(item.e.compress().as_bytes());
    }
    let result = hasher.finalize();

    let x = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(x)
}

fn gen_group_commitment(
    signing_commitments: &Vec<SigningCommitment>,
    bindings: &HashMap<u32, Scalar>,
) -> Result<RistrettoPoint, &'static str> {
    let mut accumulator = RistrettoPoint::identity();

    for commitment in signing_commitments {
        let rho_i = bindings[&commitment.index];

        accumulator += commitment.d + (commitment.e * rho_i)
    }

    Ok(accumulator)
}

#[cfg(test)]
mod tests {
    use crate::frost_lib::keygen::*;
    use crate::frost_lib::sign::*;
    use base64::decode_config;
    use base64::encode_config;
    use base64::STANDARD;
    use base64::URL_SAFE_NO_PAD;
    use core::str;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use rand::rngs::OsRng;
    use serde_json::Number;
    use sha2::digest::generic_array::typenum::Integer;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Error;
    use std::io::Read;
    use std::io::Write;
    use std::path::Path;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    #[test]
    fn preprocess_generates_values() {
        let mut rng: OsRng = OsRng;
        let (signing_commitments, signing_nonces) = preprocess(5, 1, &mut rng).unwrap();
        assert!(signing_commitments.len() == 5);
        assert!(signing_nonces.len() == 5);

        let expected_length = signing_nonces.len() * 2;
        let mut seen_nonces = Vec::with_capacity(expected_length);
        for nonce in signing_nonces {
            seen_nonces.push(nonce.d.secret);
            seen_nonces.push(nonce.e.secret);
        }
        seen_nonces.dedup();

        // ensure that each secret is unique
        assert!(seen_nonces.len() == expected_length);
    }

    fn gen_signing_helper(
        num_signers: u32,
        keypairs: &Vec<KeyPair>,
        rng: &mut OsRng,
    ) -> (Vec<SigningCommitment>, HashMap<u32, Vec<NoncePair>>) {
        let mut nonces: HashMap<u32, Vec<NoncePair>> = HashMap::with_capacity(num_signers as usize);
        let mut signing_commitments: Vec<SigningCommitment> =
            Vec::with_capacity(num_signers as usize);
        let number_nonces_to_generate = 1;

        for counter in 0..num_signers {
            let signing_keypair = &keypairs[counter as usize];
            let (participant_commitments, participant_nonces) =
                preprocess(number_nonces_to_generate, signing_keypair.index, rng).unwrap();

            signing_commitments.push(participant_commitments[0]);
            nonces.insert(counter, participant_nonces);
        }
        assert!(nonces.len() == (num_signers as usize));
        (signing_commitments, nonces)
    }

    fn get_signer_pubkeys(keypairs: &Vec<KeyPair>) -> HashMap<u32, RistrettoPoint> {
        let mut signer_pubkeys: HashMap<u32, RistrettoPoint> =
            HashMap::with_capacity(keypairs.len());

        for keypair in keypairs {
            signer_pubkeys.insert(keypair.index, keypair.public);
        }

        signer_pubkeys
    }

    fn gen_keypairs_dkg_helper(num_shares: u32, threshold: u32) -> Vec<KeyPair> {
        let mut rng: OsRng = OsRng;

        let mut participant_shares: HashMap<u32, Vec<Share>> =
            HashMap::with_capacity(num_shares as usize);
        let mut participant_commitments: Vec<KeyGenDKGPropsedCommitment> =
            Vec::with_capacity(num_shares as usize);
        let mut participant_keypairs: Vec<KeyPair> = Vec::with_capacity(num_shares as usize);

        // use some unpredictable string that everyone can derive, to protect
        // against replay attacks.
        let context = format!("{:?}", SystemTime::now());

        for counter in 0..num_shares {
            let participant_index = counter + 1;
            let (com, shares) =
                keygen_begin(num_shares, threshold, participant_index, &context, &mut rng).unwrap();

            for share in shares {
                match participant_shares.get_mut(&share.receiver_index) {
                    Some(list) => list.push(share),
                    None => {
                        let mut list = Vec::with_capacity(num_shares as usize);
                        list.push(share);
                        participant_shares.insert(share.receiver_index, list);
                    }
                }
            }
            participant_commitments.push(com);
        }

        let (invalid_peer_ids, valid_commitments) =
            keygen_receive_commitments_and_validate_peers(participant_commitments, &context)
                .unwrap();
        assert!(invalid_peer_ids.len() == 0);

        // now, finalize the protocol
        for counter in 0..num_shares {
            let participant_index = counter + 1;
            let res = match keygen_finalize(
                participant_index, // participant indices should start at 1
                threshold,
                &participant_shares[&participant_index],
                &valid_commitments,
            ) {
                Ok(x) => x,
                Err(err) => panic!("{}", err),
            };

            participant_keypairs.push(res);
        }

        participant_keypairs
    }

    #[test]
    fn valid_sign_with_single_dealer() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let (_, keypairs) = keygen_with_dealer(num_signers, threshold, &mut rng).unwrap();

        let msg = "testing sign";

        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg
            )
            .unwrap();

            all_responses.push(res);
        }

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let group_sig = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    fn check_and_read_keypair(
        node_id: u32,
        keypairs: &mut Vec<KeyPair>,
    ) -> Result<&Vec<KeyPair>, Error> {
        // Define the file path based on the node id
        let file_path = format!("keys/{}_key.txt", node_id + 1);
        println!("reading {}", file_path);
        // Check if the file exists
        if Path::new(&file_path).exists() {
            // If the file exists, open it and read the contents
            let mut file = File::open(&file_path)?;
            let mut file_content = String::new();
            file.read_to_string(&mut file_content)?;

            // Deserialize the content into a KeyPair struct and return it
            let keypair: KeyPair = serde_json::from_str(&file_content)?;

            keypairs.push(keypair);
        }
        Ok(keypairs)
    }

    fn verify_jwt(jwt_str: &str, pubkey_pem: &str) -> Result<(), &'static str> {
        // Split JWT into header, payload, signature
        let parts: Vec<&str> = jwt_str.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format");
        }
        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // Reconstruct the message (header.payload)
        let msg = format!("{}.{}", header_b64, payload_b64);

        // Decode the signature
        let signature_bytes = decode_config(signature_b64, URL_SAFE_NO_PAD)
            .map_err(|_| "Failed to decode signature")?;

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
    #[test]
    fn valid_sign_with_dkg_threshold_signers() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let mut keypairs: Vec<KeyPair> = Vec::new();
        for node_id in 0..num_signers {
            let _ = check_and_read_keypair(node_id, &mut keypairs);
        }

        // let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);
        // for (idx, keypair) in keypairs.iter().enumerate() {
        //     let mut file = File::create(format!("keys/{}_key.txt", idx + 1))
        //         .expect(&format!("Cannot create key file for node {}", idx + 1));
        //     let _ = file.write_all(serde_json::to_string(&keypair).unwrap().as_bytes());
        // }
        let payload = serde_json::json!( {
            "message": "HI".to_string(),
            "sub": "1234567890".to_string(),
            "iat": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600, // 1 hour from now
        });
        let binding: String = generate_jwt_header_and_payload(&payload);
        let msg: &str = binding.as_str();
        println!("{}", msg);
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let signer_pubkeys: HashMap<u32, RistrettoPoint> = get_signer_pubkeys(&keypairs);
        let group_sig: Signature =
            aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();

        println!("{:?}{:?}", group_sig.r.compress().as_bytes(), group_sig.z);
        let r_bytes = group_sig.r.compress().to_bytes(); // [u8; 32]
        let z_bytes = group_sig.z.to_bytes(); // [u8; 32]

        let mut signature_bytes = Vec::with_capacity(64);
        signature_bytes.extend_from_slice(&r_bytes);
        signature_bytes.extend_from_slice(&z_bytes);

        let signature_b64 = encode_config(&signature_bytes, URL_SAFE_NO_PAD);
        let signed_jwt = format!("{}.{}", binding, signature_b64);

        let group_pubkey: RistrettoPoint = keypairs[1].group_public;
        let pem: String = group_pubkey_to_pem(&group_pubkey);
        println!("{:?}", group_pubkey.compress().as_bytes());
        //assert!(validate(msg, &group_sig, group_pubkey).is_ok());
        assert!(verify_jwt(&signed_jwt, &pem).is_ok());
    }

    #[test]
    fn valid_sign_with_dkg_larger_than_threshold_signers() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let number_signers = threshold + 1;
        let (signing_package, signing_nonces) =
            gen_signing_helper(number_signers, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(number_signers as usize);

        for counter in 0..number_signers {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let group_sig = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    #[test]
    fn valid_sign_with_dkg_larger_params() {
        let num_signers = 10;
        let threshold = 6;
        let mut rng: OsRng = OsRng;

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "{}";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let group_sig = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    #[test]
    fn invalid_sign_too_few_responses_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..(threshold - 1) {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        // duplicate a share
        all_responses.push(all_responses[0]);

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let res = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys);
        assert!(!res.is_ok());
    }

    #[test]
    fn invalid_sign_invalid_response_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        // create a totally invalid response
        all_responses[0].response = Scalar::from(42u32);

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let res = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys);
        assert!(!res.is_ok());
    }

    #[test]
    fn invalid_sign_bad_group_public_key_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing different message sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let group_sig = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();
        // use one of the participant's public keys instead
        let invalid_group_pubkey = keypairs[0 as usize].public;
        assert!(!validate(msg, &group_sig, invalid_group_pubkey).is_ok());
    }

    #[test]
    fn invalid_sign_used_nonce_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut my_signing_nonces = signing_nonces[&0].clone();

        my_signing_nonces.remove(0);

        let res = sign(&keypairs[0], &signing_package, &mut my_signing_nonces, msg);

        assert!(!res.is_ok());
    }

    #[test]
    fn invalid_sign_with_dealer() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: OsRng = OsRng;

        let (_, keypairs) = keygen_with_dealer(num_signers, threshold, &mut rng).unwrap();

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        {
            // test duplicated participants
            for counter in 0..threshold {
                let mut my_signing_nonces = signing_nonces[&counter].clone();
                assert!(my_signing_nonces.len() == 1);
                let res = sign(
                    &keypairs[counter as usize],
                    &signing_package,
                    &mut my_signing_nonces,
                    msg,
                )
                .unwrap();

                all_responses.push(res);
            }

            let signer_pubkeys = get_signer_pubkeys(&keypairs);
            let group_sig =
                aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();
            let invalid_group_pubkey = RistrettoPoint::identity();
            assert!(!validate(msg, &group_sig, invalid_group_pubkey).is_ok());
        }
    }

    #[test]
    fn valid_validate_single_party() {
        let privkey = Scalar::from(42u32);
        let pubkey = &constants::RISTRETTO_BASEPOINT_TABLE * &privkey;

        let msg = "testing sign";
        let nonce = Scalar::from(5u32); // random nonce
        let commitment = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let c = generate_challenge(msg, commitment);

        let z = nonce + privkey * c;

        let sig = Signature {
            r: commitment,
            z: z,
        };
        assert!(validate(msg, &sig, pubkey).is_ok());
    }

    #[test]
    fn invalid_validate_single_party() {
        let privkey = Scalar::from(42u32);
        let pubkey = &constants::RISTRETTO_BASEPOINT_TABLE * &privkey;

        let msg = "testing sign";
        let nonce = Scalar::from(5u32); // random nonce
        let commitment = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let c = generate_challenge(msg, commitment);

        let invalid_nonce = Scalar::from(100u32); // random nonce
        let z = invalid_nonce + privkey * c;

        let sig = Signature {
            r: commitment,
            z: z,
        };
        assert!(!validate(msg, &sig, pubkey).is_ok());
    }
}
