use parity_scale_codec::{Encode, Decode};
use sha2::{Digest, Sha256, Sha512};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
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

fn generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    // Must match verifier's generator derivation exactly
    hasher.update(b"VERIFIER_H_GENERATOR");
    let out = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

/// Deterministically derive a note blinding from a stealth address and an optional tag.
pub fn derive_note_blinding(address: &[u8; 32], tag: Option<&[u8]>) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"NULLA_NOTE_BLINDING");
    hasher.update(address);
    if let Some(t) = tag { hasher.update(t); }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive a note blinding bound to a stealth address and a transaction id (16 bytes),
/// matching the faucet's derivation for recipient outputs.
pub fn derive_note_blinding_with_txid(address: &[u8; 32], tx_id: &[u8; 16]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"R_USER");
    hasher.update(address);
    hasher.update(tx_id);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Pedersen commitment C = v*G + r*H. Returns compressed 32-byte encoding.
pub fn pedersen_commit(value: u64, blinding: Scalar) -> [u8; 32] {
    let h = generator_h();
    let c = Scalar::from(value) * G + blinding * h;
    c.compress().to_bytes()
}

/// Derive a deterministic stealth address from keys
pub fn derive_stealth_address(viewing_key: &[u8; 32], spending_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nulla_stealth_address");
    hasher.update(viewing_key);
    hasher.update(spending_key);
    hasher.finalize().into()
}

/// Generate a fresh keypair for a new wallet
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    
    let viewing_scalar = Scalar::random(&mut rng);
    let spending_scalar = Scalar::random(&mut rng);
    
    let viewing_key = viewing_scalar.to_bytes();
    let spending_key = spending_scalar.to_bytes();
    
    (viewing_key, spending_key)
}

/// Off-chain placeholder for new merkle root: XOR aggregation to keep deterministic tests.
pub fn compute_new_merkle_root(old: [u8; 32], adds: &[[u8; 32]]) -> [u8; 32] {
    let mut root = old;
    for c in adds {
        for i in 0..32 { root[i] ^= c[i]; }
    }
    root
}

/// Schnorr balance proof: shows that sum(inputs) - sum(outputs) - fee has zero G-component.
/// Provide witness w such that agg = w*H. Returns proof bytes: R(32) || s(32)
pub fn prove_balance_with_w(input_commitments: &[[u8;32]], output_commitments: &[[u8;32]], fee_commitment: &[u8;32], w: Scalar) -> Vec<u8> {
    // Aggregate commitment agg = sum(inputs) - sum(outputs) - fee
    let mut agg = RistrettoPoint::default();
    for c in input_commitments {
        let p = CompressedRistretto(*c).decompress().expect("valid point");
        agg += p;
    }
    for c in output_commitments {
        let p = CompressedRistretto(*c).decompress().expect("valid point");
        agg -= p;
    }
    let fee_p = CompressedRistretto(*fee_commitment).decompress().expect("valid point");
    agg -= fee_p;

    let h = generator_h();
    let mut rng = OsRng;
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    let r = Scalar::from_bytes_mod_order_wide(&wide);
    let r_pt = r * h;
    // FS challenge
    let mut t = Transcript::new(b"NULLA_SCHNORR_BALANCE");
    t.append_message(b"label", b"balance");
    t.append_message(b"R", &r_pt.compress().to_bytes());
    t.append_message(b"AGG", &agg.compress().to_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    let c = Scalar::from_bytes_mod_order_wide(&buf);

    // s = r + c*w
    let s = r + c * w;

    // Output proof bytes
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r_pt.compress().to_bytes());
    out.extend_from_slice(&s.to_bytes());
    out
}

/// Produce proof bytes expected by the runtime verifier.
pub fn make_proof_bytes_with_w(public_inputs: &ProofPublicInputs, w: Scalar) -> Vec<u8> {
    prove_balance_with_w(&public_inputs.input_commitments, &public_inputs.new_commitments, &public_inputs.fee_commitment, w)
}

/// Example: derive a nullifier from commitment
pub fn derive_nullifier(commitment: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nullifier");
    hasher.update(commitment);
    hasher.update(secret);
    hasher.finalize().into()
}
