use curve25519_dalek::scalar::Scalar;
use hex::ToHex;
use parity_scale_codec::Encode;
use subxt::{dynamic::{self, Value}, OnlineClient, PolkadotConfig};
use wallet::{ProofPublicInputs, pedersen_commit, compute_new_merkle_root, make_proof_bytes_with_w, derive_nullifier};

/// Submit a proof that spends the note created by shield.
/// This version uses deterministic values that match the shield operation.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;

    // The shield creates a note with:
    // - amount: 100
    // - blinding: 0 (deterministic for demo)
    // So the input_commitment = pedersen_commit(100, Scalar::from(0))
    let input_commitment = pedersen_commit(100, Scalar::from(0u64));
    println!("Expected input commitment from shield: 0x{}", input_commitment.encode_hex::<String>());
    
    // The shield sets merkle_root to compute_new_merkle_root([0;32], [input_commitment])
    let merkle_root_after_shield = compute_new_merkle_root([0u8; 32], &[input_commitment]);
    println!("MerkleRoot after shield: 0x{}", merkle_root_after_shield.encode_hex::<String>());
    
    // Now we spend this note
    let input_secret = [1u8; 32];
    let nullifier = derive_nullifier(&input_secret, &[0u8; 32]);
    
    // Create two outputs: 60 + 40 = 100 (balance preserved)
    let out1 = pedersen_commit(60, Scalar::from(2u64));
    let out2 = pedersen_commit(40, Scalar::from(3u64));
    let outputs = vec![out1, out2];
    
    // Fee: 0 value
    let fee_nullifier = derive_nullifier(&[9u8; 32], &[0u8; 32]);
    let fee_commitment = pedersen_commit(0, Scalar::from(5u64));
    
    // New root after spending
    let new_merkle_root = compute_new_merkle_root(merkle_root_after_shield, &outputs);
    
    let public_inputs = ProofPublicInputs {
        merkle_root: merkle_root_after_shield,
        new_merkle_root,
        input_commitments: vec![input_commitment],
        nullifiers: vec![nullifier],
        new_commitments: outputs.clone(),
        fee_commitment,
        fee_nullifier,
        tx_id: [7u8; 16],
    };
    
    // Witness: w = r_in - r_out1 - r_out2 - r_fee = 0 - 2 - 3 - 5 = -10
    let w = Scalar::from(0u64) - Scalar::from(2u64) - Scalar::from(3u64) - Scalar::from(5u64);
    let proof = make_proof_bytes_with_w(&public_inputs, w);
    let encoded = public_inputs.encode();
    
    println!("Spending note with nullifier: 0x{}", hex::encode(nullifier));
    println!("Outputs:");
    for (i, c) in outputs.iter().enumerate() {
        println!("  out[{i}]: 0x{}", hex::encode(c));
    }
    
    let call = dynamic::tx(
        "Proofs",
        "submit_proof",
        vec![Value::from_bytes(&proof), Value::from_bytes(&encoded)],
    );
    
    let progress = api.tx().create_unsigned(&call)?.submit_and_watch().await?;
    let _events = progress.wait_for_finalized_success().await?;
    println!("Successfully spent the shielded note!");
    println!("New MerkleRoot: 0x{}", new_merkle_root.encode_hex::<String>());
    
    Ok(())
}
