use parity_scale_codec::{Encode, Decode};
use sha2::{Digest, Sha256, Sha512};
use blake2::Blake2b512;
// Use curve25519-dalek v4 for wallet's public API types
use curve25519_dalek_v4::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_v4::scalar::Scalar;
use curve25519_dalek_v4::constants::RISTRETTO_BASEPOINT_POINT as G;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;

#[cfg(feature = "typed-scan")]
pub mod runtime; // dynamic event decoding path used instead

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct ProofPublicInputs {
    pub merkle_root: [u8; 32],
    pub new_merkle_root: [u8; 32],
    pub input_commitments: Vec<[u8; 32]>,
    // Ownership removed from public inputs; spend authorization must be proven in-circuit.
    pub input_indices: Vec<u32>,
    pub input_paths: Vec<Vec<[u8; 32]>>, // optional for now
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

// A curve25519-dalek-ng compatible H generator for Bulletproofs v4 internals (same derivation bytes)
fn generator_h_ng() -> curve25519_dalek_ng::ristretto::RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"VERIFIER_H_GENERATOR");
    let out = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    curve25519_dalek_ng::ristretto::RistrettoPoint::from_uniform_bytes(&bytes)
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
/// Derive a recipient note blinding from the ECDH shared secret and tx_id.
/// Only the sender (who chose eph_sk) and the recipient (who knows viewing key) can compute `shared`.
pub fn derive_note_blinding_from_shared(shared: &[u8; 32], tx_id: &[u8; 16]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"R_USER_SHARED");
    hasher.update(shared);
    hasher.update(tx_id);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive a change note blinding bound to a stealth address and a transaction id (16 bytes),
/// matching the wallet's change output derivation used during transfers.
/// Derive a change note blinding from the spender's private spending key and tx_id.
/// This keeps change blinding secret and unlinkable.
pub fn derive_change_blinding_with_sk(spend_key: &[u8; 32], tx_id: &[u8; 16]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"R_CHANGE_SK");
    hasher.update(spend_key);
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
pub fn derive_stealth_address(viewing_key: &[u8; 32], _spending_key: &[u8; 32]) -> [u8; 32] {
    // Publish the viewing public key (compressed Ristretto point) as the stealth address.
    // This enables ECDH-based memo discovery without revealing any spend key.
    let v = Scalar::from_bytes_mod_order(*viewing_key);
    let vp = (v * G).compress().to_bytes();
    vp
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
    // FS challenge with transcript binding to public inputs provided at a higher level (caller should prepend pi_hash)
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
    // Compute pi_hash = H(SCALE(public_inputs)) for transcript binding
    let encoded = public_inputs.encode();
    // blake2_256 over SCALE(public_inputs)
    let mut h = Blake2b512::new();
    h.update(&encoded);
    let out = h.finalize();
    let pi_hash = &out[..32];

    // Aggregate commitment agg and build Schnorr proof with transcript including pi_hash
    // Reuse internal helper but inject pi_hash via a temporary transcript wrapper
    // Here we reconstruct the same logic as in prove_balance_with_w but with binding

    // Aggregate commitment agg = sum(inputs) - sum(outputs) - fee
    let mut agg = RistrettoPoint::default();
    for c in public_inputs.input_commitments.iter() {
        let p = CompressedRistretto(*c).decompress().expect("valid point");
        agg += p;
    }
    for c in public_inputs.new_commitments.iter() {
        let p = CompressedRistretto(*c).decompress().expect("valid point");
        agg -= p;
    }
    let fee_p = CompressedRistretto(public_inputs.fee_commitment).decompress().expect("valid point");
    agg -= fee_p;

    let hgen = generator_h();
    let mut rng = OsRng;
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    let r = Scalar::from_bytes_mod_order_wide(&wide);
    let r_pt = r * hgen;
    // FS challenge bound to public inputs hash
    let mut t = Transcript::new(b"NULLA_SCHNORR_BALANCE");
    t.append_message(b"label", b"balance");
    t.append_message(b"pi_hash", pi_hash);
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

/// Example: derive a nullifier from commitment
pub fn derive_nullifier(commitment: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nullifier");
    hasher.update(commitment);
    hasher.update(secret);
    hasher.finalize().into()
}

// =============================
// Bulletproofs range proof APIs
// =============================
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

/// Create an aggregated Bulletproofs range proof over outputs and fee values.
/// - values: amounts for outputs followed by fee value (M+1 elements)
/// - blindings: scalar blindings corresponding to the same order
/// - nbits: range bits (64 recommended)
/// - public_inputs: used to bind the proof transcript (H(SCALE(public_inputs)))
pub fn make_aggregated_range_proof(values: &[u64], blindings: &[Scalar], nbits: u32, public_inputs: &ProofPublicInputs) -> Vec<u8> {
    assert_eq!(values.len(), blindings.len());
    assert!(values.len() >= 1);
    assert!(nbits <= 64);

    // Generators consistent with verifier (G, H), using curve25519-dalek-ng types expected by bulletproofs v4
    let h_ng = generator_h_ng();
    let pc_gens = PedersenGens { B: curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT, B_blinding: h_ng };
    // Bulletproofs aggregated proofs require party capacity to be a power of two >= m
    let mut m = values.len();
    let mut party_capacity = m.next_power_of_two();
    let mut values_vec = values.to_vec();
    // Dev debug: print party sizing
    #[cfg(debug_assertions)]
    {
        println!("[wallet] range-proof parties m={}, capacity={}, nbits={}", m, party_capacity, nbits);
    }

    // Bind transcript to public inputs digest
    let pi_enc = public_inputs.encode();
    let mut hasher = Blake2b512::new();
    hasher.update(&pi_enc);
    let out = hasher.finalize();
    let pi_hash = &out[..32];
    let mut t = Transcript::new(b"NULLA_BULLETPROOF_RANGE");
    t.append_message(b"pi_hash", pi_hash);

    // If m is not a power of two, pad with zero-value parties using deterministic blindings derived from pi_hash
    if party_capacity > m {
        let pad = party_capacity - m;
        // helper: derive pad blinding in dalek-ng space from pi_hash and index
        fn pad_blind_ng(pi_hash: &[u8], idx: u32) -> curve25519_dalek_ng::scalar::Scalar {
            let mut h = Sha512::new();
            h.update(b"PAD_R");
            h.update(pi_hash);
            h.update(&idx.to_le_bytes());
            let wide = h.finalize();
            let mut w = [0u8;64];
            w.copy_from_slice(&wide);
            curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order_wide(&w)
        }
        for i in 0..pad {
            values_vec.push(0u64);
        }
        m = values_vec.len();
        party_capacity = m.next_power_of_two();
    }
    let bp_gens = BulletproofGens::new(nbits as usize, party_capacity);

    // Convert blindings (v4 Scalars) to dalek-ng Scalars expected by bulletproofs v4
    let mut blind_scalars: Vec<curve25519_dalek_ng::scalar::Scalar> = blindings
        .iter()
        .map(|s| curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order(s.to_bytes()))
        .collect();
    // Append padding blindings if we padded values
    if blind_scalars.len() < values_vec.len() {
        let pad_needed = values_vec.len() - blind_scalars.len();
        for i_u in 0u32..(pad_needed as u32) {
            // Use the same derivation as above
            let mut h = Sha512::new();
            h.update(b"PAD_R");
            h.update(pi_hash);
            h.update(&i_u.to_le_bytes());
            let wide = h.finalize();
            let mut w = [0u8;64];
            w.copy_from_slice(&wide);
            blind_scalars.push(curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order_wide(&w));
        }
    }
    // Prove
    let (proof, _commits) = RangeProof::prove_multiple(&bp_gens, &pc_gens, &mut t, &values_vec, &blind_scalars, nbits as usize).expect("range proof");
    proof.to_bytes()
}
