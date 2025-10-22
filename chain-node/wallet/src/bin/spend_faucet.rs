use curve25519_dalek::scalar::Scalar;
use parity_scale_codec::Encode;
use std::fs;
use std::path::Path;
use subxt::{dynamic::{self, Value}, OnlineClient, PolkadotConfig};
use wallet::{ProofPublicInputs, pedersen_commit, compute_new_merkle_root, make_proof_bytes_with_w, derive_nullifier, derive_note_blinding_with_txid};

/// Spend a faucet note saved by the wallet faucet command.
/// Usage env:
///   NAME=alice MERKLE_ROOT=<hex32> cargo run -p wallet --bin spend_faucet
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let name = std::env::var("NAME").unwrap_or_else(|_| "default".into());
    let wallet_dir = format!(".nulla/wallets/{}", name);
    anyhow::ensure!(Path::new(&wallet_dir).exists(), "wallet '{}' not found", name);

    // Load last note from received_notes.json
    let notes_path = format!("{}/received_notes.json", wallet_dir);
    let notes_str = fs::read_to_string(&notes_path)?;
    let notes_json: serde_json::Value = serde_json::from_str(&notes_str)?;
    let arr = notes_json.as_array().ok_or_else(|| anyhow::anyhow!("notes not an array"))?;
    let note = arr.last().ok_or_else(|| anyhow::anyhow!("no notes to spend"))?;
    let stealth_hex = note["stealth_address"].as_str().ok_or_else(|| anyhow::anyhow!("missing stealth_address"))?;
    let tx_id_hex = note["tx_id"].as_str().ok_or_else(|| anyhow::anyhow!("missing tx_id"))?;
    let amount = note["amount"].as_u64().ok_or_else(|| anyhow::anyhow!("missing amount"))?;

    // Decode params
    let mut addr = [0u8; 32];
    let sbytes = hex::decode(stealth_hex.trim_start_matches("0x"))?;
    addr.copy_from_slice(&sbytes[..32]);
    let mut txid = [0u8; 16];
    let tbytes = hex::decode(tx_id_hex.trim_start_matches("0x"))?;
    txid.copy_from_slice(&tbytes[..16]);

    // Connect
    let api = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;
    // Load the merkle root that was current after the faucet credit
    let merkle_hex = note["merkle_root"].as_str().ok_or_else(|| anyhow::anyhow!("missing merkle_root in note; request faucet again with updated server"))?;
    let mut onchain_root = [0u8; 32];
    let mr_bytes = hex::decode(merkle_hex.trim_start_matches("0x"))?;
    onchain_root.copy_from_slice(&mr_bytes[..32]);

    // Recreate input note commitment and nullifier
    let r_in = derive_note_blinding_with_txid(&addr, &txid);
    let input_commitment = pedersen_commit(amount, r_in);
    let input_secret = r_in.to_bytes();
    let nullifier = derive_nullifier(&input_commitment, &input_secret);

    // Spend: split into two fixed outputs for demo
    let r_out1 = Scalar::from(21u64);
    let r_out2 = Scalar::from(22u64);
    let half = amount / 2;
    let out1 = pedersen_commit(half, r_out1);
    let out2 = pedersen_commit(amount - half, r_out2);

    // Fee 0
    let r_fee = Scalar::from(23u64);
    let fee_commitment = pedersen_commit(0, r_fee);
    let fee_nullifier = derive_nullifier(&fee_commitment, &r_fee.to_bytes());

    let new_root = compute_new_merkle_root(onchain_root, &[out1, out2]);

    let public_inputs = ProofPublicInputs {
        merkle_root: onchain_root,
        new_merkle_root: new_root,
        input_commitments: vec![input_commitment],
        nullifiers: vec![nullifier],
        new_commitments: vec![out1, out2],
        fee_commitment,
        fee_nullifier,
        tx_id: txid,
    };

    let w = r_in - r_out1 - r_out2 - r_fee;
    let proof = make_proof_bytes_with_w(&public_inputs, w);
    let encoded = public_inputs.encode();

    let call = dynamic::tx(
        "Proofs",
        "submit_proof",
        vec![Value::from_bytes(&proof), Value::from_bytes(&encoded)],
    );
    let progress = api.tx().create_unsigned(&call)?.submit_and_watch().await?;
    let _ = progress.wait_for_finalized_success().await?;

    println!("Spent faucet note for wallet {name}. New root set in public inputs.");
    Ok(())
}
