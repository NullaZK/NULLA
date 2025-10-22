use parity_scale_codec::Encode;
use subxt::dynamic::{self, Value};
use subxt::{OnlineClient, PolkadotConfig};
use wallet::{ProofPublicInputs, pedersen_commit, compute_new_merkle_root, make_proof_bytes_with_w, derive_nullifier};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect to local node (assumes default websocket)
    let api = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;

    // Read current MerkleRoot from env var or use zero default
    let old_root: [u8; 32] = if let Ok(root_hex) = std::env::var("MERKLE_ROOT") {
        let bytes = hex::decode(root_hex.trim_start_matches("0x"))?;
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[..32]);
        root
    } else {
        println!("Warning: Using zero MerkleRoot. Set MERKLE_ROOT=<hex> env var for non-fresh chains.");
        [0u8; 32]
    };

    // Construct a sample transaction using hidden-value commitments
    // Input note of value 100 with blinding 7 (this should match a shield operation)
    use curve25519_dalek::scalar::Scalar;
    let r_in = Scalar::from(7u64);
    let input_commitment = pedersen_commit(100, r_in);
    let input_secret = [1u8; 32];
    let nullifier = derive_nullifier(&input_secret, &[0u8; 32]);

    // Two outputs 60 and 40 with blindings 2 and 3
    let r_out1 = Scalar::from(2u64);
    let r_out2 = Scalar::from(3u64);
    let out1 = pedersen_commit(60, r_out1);
    let out2 = pedersen_commit(40, r_out2);
    let outputs = vec![out1, out2];

    // Fee nullifier (demo) and fee commitment with zero value, blinding 5
    let fee_nullifier = derive_nullifier(&[9u8; 32], &[0u8; 32]);
    let r_fee = Scalar::from(5u64);
    let fee_commitment = pedersen_commit(0, r_fee);

    // For demo: if old_root is zero, simulate as if we have the commitment from shield in the tree
    let effective_old_root = if old_root == [0u8; 32] {
        // Simulate that input_commitment was already in the tree via shield
        compute_new_merkle_root([0u8; 32], &[input_commitment])
    } else {
        old_root
    };
    let new_root = compute_new_merkle_root(effective_old_root, &outputs);

    let public_inputs = ProofPublicInputs {
        merkle_root: effective_old_root,
        new_merkle_root: new_root,
        input_commitments: vec![input_commitment],
        nullifiers: vec![nullifier],
        new_commitments: outputs,
        fee_commitment,
        fee_nullifier,
        tx_id: [7u8; 16],
    };

    // Encode public inputs and make proof
    let encoded = public_inputs.encode();
    // Witness for H component: w = r_in - r_out1 - r_out2 - r_fee
    let w = r_in - r_out1 - r_out2 - r_fee;
    let proof = make_proof_bytes_with_w(&public_inputs, w);

    // Build dynamic call by name
    let call = dynamic::tx(
        "Proofs",
        "submit_proof",
        vec![Value::from_bytes(&proof), Value::from_bytes(&encoded)],
    );

    // Log some context for visual correlation
    println!("Submitting tx with nullifier: 0x{}", hex::encode(nullifier));
    println!("Outputs:");
    for (i, c) in public_inputs.new_commitments.iter().enumerate() {
        println!("  out[{i}]: 0x{}", hex::encode(c));
    }

    // Submit unsigned extrinsic and wait for finalization
    let progress = api.tx().create_unsigned(&call)?.submit_and_watch().await?;
    let _events = progress.wait_for_finalized_success().await?;
    println!("Submitted unsigned submit_proof and finalized successfully");

    // Re-read MerkleRoot to show it changed
    println!("Old root (effective): 0x{}", hex::encode(effective_old_root));
    println!("New root (from public_inputs): 0x{}", hex::encode(new_root));
    Ok(())
}
