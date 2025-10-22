use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar};
use hex::ToHex;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use wallet::{compute_new_merkle_root, pedersen_commit};

fn main() -> anyhow::Result<()> {
    // Amount from env or default 100
    let amount: u64 = std::env::var("AMOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    // Old root from env or zero
    let old_root_hex = std::env::var("OLD_ROOT").unwrap_or_else(|_| "0x".to_string());
    let mut old_root = [0u8;32];
    if old_root_hex.len() > 2 {
        let bytes = hex::decode(old_root_hex.trim_start_matches("0x"))?;
        old_root.copy_from_slice(&bytes[..32]);
    }

    // Use deterministic blinding for demo consistency
    let r = Scalar::from(0u64);  // Deterministic for demo
    let rb = r.to_bytes();
    let commitment = pedersen_commit(amount, r);

    // Ephemeral key: epk = a*G (deterministic for demo)
    let a = Scalar::from(1u64);  // Deterministic
    let epk = (a * G).compress().to_bytes();

    // Memo hash: empty memo for now
    let memo_hash: [u8;32] = Sha256::digest(&[]).into();

    // New root after adding the commitment (placeholder XOR aggregator)
    let new_root = compute_new_merkle_root(old_root, &[commitment]);

    println!("amount: {}", amount);
    println!("blinding: 0x{}", rb.encode_hex::<String>());
    println!("commitment: 0x{}", commitment.encode_hex::<String>());
    println!("epk: 0x{}", epk.encode_hex::<String>());
    println!("memo_hash: 0x{}", memo_hash.encode_hex::<String>());
    println!("new_merkle_root: 0x{}", new_root.encode_hex::<String>());
    Ok(())
}
