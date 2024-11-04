use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{constants, scalar};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{char, u32};

use crate::frost_lib::sign::Signature;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharesCommitment {
    pub commitment: Vec<RistrettoPoint>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenDKGPropsedCommitment {
    pub index: u32,
    pub shares_commitment: SharesCommitment,
    pub zkp: Signature,
}

impl KeyGenDKGPropsedCommitment {
    pub fn get_commitment_to_secret(&self) -> RistrettoPoint {
        self.shares_commitment.commitment[0]
    }
}

pub struct KeyGenDKGCommitment {
    pub index: u32,
    pub shares_commitment: SharesCommitment,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Share {
    pub generator_index: u32,
    pub receiver_index: u32,
    value: Scalar,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyPair {
    pub index: u32,
    pub secret: Scalar,
    pub public: RistrettoPoint,
    pub group_public: RistrettoPoint,
}

pub fn keygen_with_dealer(
    numshares: u32,
    threshold: u32,
    rng: &mut OsRng,
) -> Result<(SharesCommitment, Vec<KeyPair>), &'static str> {
    let secret = Scalar::random(rng);
    let group_public = &constants::RISTRETTO_BASEPOINT_TABLE * &secret;
    let (shares_com, shares) = generate_shares(secret, numshares, threshold, 0, rng)?;

    let keypairs = shares
        .iter()
        .map(|share| KeyPair {
            secret: share.value,
            public: &constants::RISTRETTO_BASEPOINT_TABLE * &share.value,
            group_public: group_public,
            index: share.receiver_index,
        })
        .collect();

    Ok((shares_com, keypairs))
}

pub fn keygen_begin(
    numshares: u32,
    threshold: u32,
    generator_index: u32,
    context: &str,
    rng: &mut OsRng,
) -> Result<(KeyGenDKGPropsedCommitment, Vec<Share>), &'static str> {
    let secret = Scalar::random(rng);
    let (shares_com, shares) = generate_shares(secret, numshares, threshold, generator_index, rng)?;
    let r = Scalar::random(rng);

    let r_pub = &constants::RISTRETTO_BASEPOINT_TABLE * &r;
    let s_pub = &constants::RISTRETTO_BASEPOINT_TABLE * &secret;
    let challenge = generate_dkg_challenge(generator_index, context, s_pub, r_pub)?;
    let z = r + secret * challenge;

    let dkg_commitment = KeyGenDKGPropsedCommitment {
        index: generator_index,
        shares_commitment: shares_com,
        zkp: Signature { r: r_pub, z: z },
    };
    Ok((dkg_commitment, shares))
}

pub fn generate_dkg_challenge(
    index: u32,
    context: &str,
    public: RistrettoPoint,
    commitment: RistrettoPoint,
) -> Result<Scalar, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(commitment.compress().to_bytes());
    hasher.update(public.compress().to_bytes());
    hasher.update(index.to_string());
    hasher.update(context);
    let result = hasher.finalize();

    let a: [u8; 32] = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment");
    Ok(Scalar::from_bytes_mod_order(a))
}

pub fn keygen_receive_commitments_and_validate_peers(
    peer_commitments: Vec<KeyGenDKGPropsedCommitment>,
    context: &str,
) -> Result<(Vec<u32>, Vec<KeyGenDKGCommitment>), &'static str> {
    let mut invalid_peer_ids = Vec::new();
    let mut valid_peer_commitments: Vec<KeyGenDKGCommitment> =
        Vec::with_capacity(peer_commitments.len());

    for commitment in peer_commitments {
        let challenge = generate_dkg_challenge(
            commitment.index,
            context,
            commitment.get_commitment_to_secret(),
            commitment.zkp.r,
        )?;

        if !is_valid_zkp(challenge, &commitment).is_ok() {
            invalid_peer_ids.push(commitment.index);
        } else {
            valid_peer_commitments.push(KeyGenDKGCommitment {
                index: commitment.index,
                shares_commitment: commitment.shares_commitment,
            })
        }
    }

    Ok((invalid_peer_ids, valid_peer_commitments))
}

pub fn is_valid_zkp(
    challenge: Scalar,
    comm: &KeyGenDKGPropsedCommitment,
) -> Result<(), &'static str> {
    if comm.zkp.r
        != (&constants::RISTRETTO_BASEPOINT_TABLE * &comm.zkp.z)
            - (comm.get_commitment_to_secret() * challenge)
    {
        return Err("Signature is invalid");
    }
    Ok(())
}

pub fn keygen_finalize(
    index: u32,
    threshold: u32,
    shares: &Vec<Share>,
    commitments: &Vec<KeyGenDKGCommitment>,
) -> Result<KeyPair, &'static str> {
    // first, verify the integrity of the shares
    for share in shares {
        let commitment = commitments
            .iter()
            .find(|comm| comm.index == share.generator_index)
            .ok_or("Received share with no corresponding commitment")?;

        verify_share(threshold, share, &commitment.shares_commitment)?;
    }

    let secret = shares.iter().fold(Scalar::zero(), |acc, x| acc + x.value);

    let public = &constants::RISTRETTO_BASEPOINT_TABLE * &secret;

    let group_public = commitments
        .iter()
        .map(|c| c.shares_commitment.commitment[0])
        .fold(RistrettoPoint::identity(), |acc, x| acc + x);

    Ok(KeyPair {
        index,
        secret,
        public,
        group_public,
    })
}

fn generate_shares(
    secret: Scalar,
    numshares: u32,
    threshold: u32,
    generator_index: u32,
    rng: &mut OsRng,
) -> Result<(SharesCommitment, Vec<Share>), &'static str> {
    if threshold < 1 {
        return Err("Threshold cannot be 0");
    }
    if numshares < 1 {
        return Err("Number of shares cannot be 0");
    }
    if threshold > numshares {
        return Err("Threshold cannot exceed numshares");
    }

    let numcoeffs = threshold - 1;
    let mut coefficients: Vec<Scalar> = Vec::with_capacity(numcoeffs as usize);
    let mut shares: Vec<Share> = Vec::with_capacity(numshares as usize);
    let mut commitment: Vec<RistrettoPoint> = Vec::with_capacity(threshold as usize);

    for _ in 0..numcoeffs {
        coefficients.push(Scalar::random(rng));
    }

    commitment.push(&constants::RISTRETTO_BASEPOINT_TABLE * &secret);
    for c in &coefficients {
        commitment.push(&constants::RISTRETTO_BASEPOINT_TABLE * &c)
    }

    for index in 1..numshares + 1 {
        let scalar_index = Scalar::from(index);
        let mut value: Scalar = Scalar::zero();
        for i in (0..numcoeffs).rev() {
            value += &coefficients[i as usize];
            value *= scalar_index;
        }

        value += secret;
        shares.push(Share {
            generator_index: generator_index,
            receiver_index: index,
            value: value,
        })
    }
    Ok((SharesCommitment { commitment }, shares))
}

fn verify_share(threshold: u32, share: &Share, com: &SharesCommitment) -> Result<(), &'static str> {
    let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &share.value;

    let term = Scalar::from(share.receiver_index);
    let mut result = RistrettoPoint::identity();

    if com.commitment.len() != threshold as usize {
        return Err("Commitment is invalid");
    }

    for (index, comm_i) in com.commitment.iter().rev().enumerate() {
        result += comm_i;
        if index != com.commitment.len() - 1 {
            result *= term;
        }
    }
    if !(f_result == result) {
        return Err("Share is invalid. ");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::frost_lib::helpers::*;
    use crate::frost_lib::keygen::*;
    use std::collections::HashMap;
    use std::time::SystemTime;

    #[test]
    fn keygen_with_dkg_simple() {
        let mut rng = OsRng;
        let num_shares = 10;
        let threshold = 5;

        let mut participant_shares: HashMap<u32, Vec<Share>> =
            HashMap::with_capacity(num_shares as usize);
        let mut participant_commitments: Vec<KeyGenDKGPropsedCommitment> =
            Vec::with_capacity(num_shares as usize);

        // use some unpredictable string that everyone can derive, to protect
        // against replay attacks.
        let context = format!("{:?}", SystemTime::now());

        for index in 1..num_shares + 1 {
            let (shares_com, shares) =
                keygen_begin(num_shares, threshold, index, &context, &mut rng).unwrap();
            assert!(shares.len() == (num_shares as usize));

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
            participant_commitments.push(shares_com);
        }

        let (invalid_peer_ids, valid_commitments) =
            keygen_receive_commitments_and_validate_peers(participant_commitments, &context)
                .unwrap();
        assert!(invalid_peer_ids.len() == 0);

        // now, finalize the protocol
        for index in 1..num_shares + 1 {
            let res = keygen_finalize(
                index,
                threshold,
                &participant_shares[&index],
                &valid_commitments,
            );
            assert!(res.is_ok());
        }
    }

    #[test]
    fn valid_keypair_from_dkg() {
        let mut rng: OsRng = OsRng;

        let num_shares = 3;
        let threshold = 2;

        let mut participant_shares: HashMap<u32, Vec<Share>> =
            HashMap::with_capacity(num_shares as usize);
        let mut participant_commitments: Vec<KeyGenDKGPropsedCommitment> =
            Vec::with_capacity(num_shares as usize);

        // use some unpredictable string that everyone can derive, to protect
        // against replay attacks.
        let context = format!("{:?}", SystemTime::now());

        for index in 1..num_shares + 1 {
            let (shares_com, shares) =
                keygen_begin(num_shares, threshold, index, &context, &mut rng).unwrap();
            assert!(shares.len() == (num_shares as usize));

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
            participant_commitments.push(shares_com);
        }

        let (invalid_peer_ids, valid_commitments) =
            keygen_receive_commitments_and_validate_peers(participant_commitments, &context)
                .unwrap();
        assert!(invalid_peer_ids.len() == 0);

        // now, finalize the protocol
        let mut final_keypairs: Vec<KeyPair> = Vec::with_capacity(num_shares as usize);
        for index in 1..num_shares + 1 {
            let res = keygen_finalize(
                index,
                threshold,
                &participant_shares[&index],
                &valid_commitments,
            )
            .unwrap();

            // test our helper function, first.
            let expected = get_ith_pubkey(index as u32, &valid_commitments);
            assert_eq!(expected, res.public);
            final_keypairs.push(res);
        }

        // now ensure that we can reconstruct the secret, given all the secret keys
        let indices = final_keypairs.iter().map(|keypair| keypair.index).collect();
        let mut output = Scalar::zero();
        for keypair in &final_keypairs {
            let zero_coeff = get_lagrange_coeff(0, keypair.index, &indices).unwrap();
            output += keypair.secret * zero_coeff;
        }

        let received_public = &constants::RISTRETTO_BASEPOINT_TABLE * &output;

        // ensure that the secret terms interpolate to the correct public key
        assert_eq!(received_public, final_keypairs[0].group_public);
    }

    #[test]
    fn keygen_with_dkg_invalid_secret_commitment() {
        let mut rng: OsRng = OsRng;

        let num_shares = 5;
        let threshold = 3;

        let mut participant_commitments: Vec<KeyGenDKGPropsedCommitment> =
            Vec::with_capacity(num_shares as usize);

        // use some unpredictable string that everyone can derive, to protect
        // against replay attacks.
        let context = format!("{:?}", SystemTime::now());

        for index in 1..num_shares + 1 {
            let (com, _) = keygen_begin(num_shares, threshold, index, &context, &mut rng).unwrap();

            participant_commitments.push(com);
        }

        // now, set the first commitments to be invalid
        participant_commitments[0].shares_commitment.commitment[0] = RistrettoPoint::identity();
        let invalid_participant_id = participant_commitments[0].index;

        // now, ensure that this participant is marked as invalid
        let (invalid_ids, valid_coms) =
            keygen_receive_commitments_and_validate_peers(participant_commitments, &context)
                .unwrap();
        assert!(invalid_ids.len() == 1);
        assert!(invalid_ids[0] == invalid_participant_id);
        assert!(valid_coms.len() == ((num_shares - 1) as usize));
    }

    /// Reconstruct the secret from enough (at least the threshold) already-verified shares.
    pub fn reconstruct_secret(shares: &Vec<Share>) -> Result<Scalar, &'static str> {
        let numshares = shares.len();

        if numshares < 1 {
            return Err("No shares provided");
        }

        let mut lagrange_coeffs: Vec<Scalar> = Vec::with_capacity(numshares);

        for i in 0..numshares {
            let mut num = Scalar::one();
            let mut den = Scalar::one();
            for j in 0..numshares {
                if j == i {
                    continue;
                }
                num *= Scalar::from(shares[j].receiver_index);
                den *=
                    Scalar::from(shares[j].receiver_index) - Scalar::from(shares[i].receiver_index);
            }
            if den == Scalar::zero() {
                return Err("Duplicate shares provided");
            }
            lagrange_coeffs.push(num * den.invert());
        }

        let mut secret = Scalar::zero();

        for i in 0..numshares {
            secret += lagrange_coeffs[i] * shares[i].value;
        }

        Ok(secret)
    }
    #[test]
    fn share_simple() {
        let s = Scalar::from(42u32);
        let mut rng: OsRng = OsRng;

        let (com, shares) = generate_shares(s, 5, 2, 0, &mut rng).unwrap();
        assert!(shares.len() == 5);
        assert!(com.commitment.len() == 2);

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        recshares.push(shares[3]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
        assert_eq!(recres.unwrap(), s);
    }

    #[test]
    fn share_not_enough() {
        let s = Scalar::from(42u32);
        let mut rng: OsRng = OsRng;

        let (_, shares) = generate_shares(s, 5, 2, 0, &mut rng).unwrap();

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
        assert_ne!(recres.unwrap(), s);
    }

    #[test]
    fn share_dup() {
        let s = Scalar::from(42u32);
        let mut rng: OsRng = OsRng;

        let (_, shares) = generate_shares(s, 5, 2, 0, &mut rng).unwrap();

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        recshares.push(shares[1]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_err());
        assert_eq!(recres.err(), Some("Duplicate shares provided"));
    }

    #[test]
    fn share_badparams() {
        let s = Scalar::from(42u32);
        let mut rng: OsRng = OsRng;

        {
            let res = generate_shares(s, 5, 0, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Threshold cannot be 0"));
        }
        {
            let res = generate_shares(s, 0, 3, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Number of shares cannot be 0"));
        }
        {
            let res = generate_shares(s, 1, 3, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Threshold cannot exceed numshares"));
        }
    }

    #[test]
    fn share_commitment_valid() {
        let s = Scalar::from(42u32);
        let mut rng: OsRng = OsRng;

        let (com, shares) = generate_shares(s, 8, 3, 0, &mut rng).unwrap();

        for share in shares {
            let is_valid = verify_share(3, &share, &com);
            assert!(is_valid.is_ok());
        }
    }

    #[test]
    fn share_commitment_invalid() {
        let s1 = Scalar::from(42u32);
        let s2 = Scalar::from(42u32);
        let mut rng: OsRng = OsRng;

        let (_, shares1) = generate_shares(s1, 8, 3, 0, &mut rng).unwrap();

        let (com2, _) = generate_shares(s2, 8, 3, 0, &mut rng).unwrap();

        for share in shares1 {
            // test that commitments to a different set of shares fails
            let is_valid = verify_share(3, &share, &com2);
            assert!(!is_valid.is_ok());
        }
    }
}
