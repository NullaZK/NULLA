#![no_std]
#![cfg_attr(test, allow(unused_imports))]

extern crate alloc;

use alloc::vec::Vec;
use parity_scale_codec::Decode;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use merlin::Transcript;
use sha2::{Digest, Sha512};

// Mirror of pallet's public inputs; keep field order/types identical.
#[derive(Decode, Clone, PartialEq, Eq, Debug)]
pub struct ProofPublicInputs {
    pub merkle_root: [u8; 32],
    pub new_merkle_root: [u8; 32],
    pub input_commitments: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
    pub new_commitments: Vec<[u8; 32]>,
    pub fee_commitment: [u8; 32],
    pub fee_nullifier: [u8; 32],
    pub tx_id: [u8; 16],
}

// Domain-separated secondary generator H derived via hash-to-group.
fn generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"VERIFIER_H_GENERATOR");
    let out = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

// Deserialize a commitment from 32-byte compressed encoding.
fn decompress_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

// Compute Fiat–Shamir challenge c = H( transcript || R || agg )
fn challenge(transcript_label: &'static [u8], r: &RistrettoPoint, agg: &RistrettoPoint) -> Scalar {
    let mut t = Transcript::new(b"NULLA_SCHNORR_BALANCE");
    t.append_message(b"label", transcript_label);
    t.append_message(b"R", &r.compress().to_bytes());
    t.append_message(b"AGG", &agg.compress().to_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Verify Schnorr balance proof over Ristretto.
/// Proof format (proof bytes): [R (32 bytes)] || [s (32 bytes)]
/// The statement is that agg = sum(inputs) - sum(outputs) - fee_commitment
/// has zero G-component, i.e. agg = w * H, and the prover knows w.
/// Check: s*H == R + c*agg
pub fn verify_bytes(proof: &[u8], public_inputs: &[u8]) -> bool {
    // Parse public inputs
    let inputs = match ProofPublicInputs::decode(&mut &public_inputs[..]) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Parse proof
    if proof.len() != 64 { return false; }
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&proof[0..32]);
    let r_pt = match CompressedRistretto(r_bytes).decompress() { Some(p) => p, None => return false };
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&proof[32..64]);
    let s = Scalar::from_canonical_bytes(s_bytes)
        .unwrap_or(Scalar::from_bytes_mod_order(s_bytes));

    // Reconstruct aggregate commitment: agg = sum(inputs) - sum(outputs) - fee
    let mut agg = RistrettoPoint::default();
    for c in inputs.input_commitments.iter() {
        let p = match decompress_point(c) { Some(p) => p, None => return false };
        agg += p;
    }
    for c in inputs.new_commitments.iter() {
        let p = match decompress_point(c) { Some(p) => p, None => return false };
        agg -= p;
    }
    let fee_p = match decompress_point(&inputs.fee_commitment) { Some(p) => p, None => return false };
    agg -= fee_p;

    // Generators
    let h = generator_h();

    // Fiat–Shamir challenge
    let c = challenge(b"balance", &r_pt, &agg);

    // Verify s*H == R + c*agg
    let lhs = s * h;
    let rhs = r_pt + c * agg;
    lhs == rhs
}

/// Verify a Pedersen opening: does `commitment` equal `value*G + blinding*H`?
/// - value: 64-bit amount mapped into Scalar
/// - blinding: 32-byte scalar encoding (little endian)
/// - commitment: 32-byte compressed Ristretto point
pub fn pedersen_check_u64(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool {
    // Deserialize inputs
    let c_pt = match CompressedRistretto(commitment).decompress() { Some(p) => p, None => return false };
    let r = Scalar::from_canonical_bytes(blinding).unwrap_or(Scalar::from_bytes_mod_order(blinding));
    let v = Scalar::from(value);
    // Compute v*G + r*H
    let h = generator_h();
    let expected = v * G + r * h;
    expected == c_pt
}
