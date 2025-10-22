use anyhow::Context;
use hex::ToHex;
use subxt::{OnlineClient, PolkadotConfig};

/// Read current MerkleRoot from chain storage.
/// Use this to get the correct old_root for submit_proof.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("WS").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let api = OnlineClient::<PolkadotConfig>::from_url(&url).await.context("connect ws")?;

    // Try to read MerkleRoot using raw storage approach
    let storage_key = format!("0x{}", hex::encode(b"Proofs"));
    let root_key = format!("{}:{}", storage_key, hex::encode(b"MerkleRoot"));
    
    // For now, print instructions to get MerkleRoot from polkadot.js Apps
    println!("To get current MerkleRoot:");
    println!("1. Open https://polkadot.js.org/apps");
    println!("2. Connect to ws://127.0.0.1:9944");
    println!("3. Go to Developer → Chain state");
    println!("4. Select 'proofs' pallet and 'merkleRoot' storage");
    println!("5. Copy the hex value (without 0x prefix)");
    println!("");
    println!("Then run: MERKLE_ROOT=<hex_value> cargo run -p wallet --bin submit_proof");
    
    Ok(())
}
