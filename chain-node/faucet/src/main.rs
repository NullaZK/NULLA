use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::Filter;

use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::dynamic::{self, Value};
use parity_scale_codec::Encode;
use sha2::{Digest, Sha512};

use wallet::{ProofPublicInputs, pedersen_commit, compute_new_merkle_root, make_proof_bytes_with_w, derive_nullifier};

#[derive(Debug, Deserialize)]
struct FaucetRequest {
    stealth_address: String,
    amount: Option<u64>,
}

#[derive(Debug, Serialize)]
struct FaucetResponse {
    success: bool,
    transaction_hash: Option<String>,
    message: String,
    tx_id: Option<String>,
    output_commitment: Option<String>,
    amount: Option<u64>,
    new_merkle_root: Option<String>,
}

/// Genesis faucet state containing pre-funded commitments
struct FaucetState {
    /// Map from commitment bytes to (value, blinding_factor)
    /// These correspond to the genesis commitments in the runtime
    genesis_pool: HashMap<[u8; 32], (u64, [u8; 32])>,
    /// Track which commitments have been spent
    spent_commitments: HashMap<[u8; 32], bool>,
    /// Track the latest known merkle root (starts at zero)
    current_merkle_root: [u8; 32],
}

impl FaucetState {
    pub fn new() -> Self {
        let mut genesis_pool = HashMap::new();
        // Create 20 valid Pedersen commitments of 10_000 NULLA each
        for i in 0u32..20 {
            let blinding_scalar = Scalar::from((i + 1) as u64);
            let commitment = pedersen_commit(10_000, blinding_scalar);
            let blinding = blinding_scalar.to_bytes();
            genesis_pool.insert(commitment, (10_000, blinding));
        }

        FaucetState {
            genesis_pool,
            spent_commitments: HashMap::new(),
            current_merkle_root: [0u8; 32],
        }
    }

    /// Get an available genesis commitment for spending
    pub fn get_available_commitment(&mut self) -> Option<([u8; 32], u64, [u8; 32])> {
        for (commitment, (value, blinding)) in &self.genesis_pool {
            if !self.spent_commitments.contains_key(commitment) {
                self.spent_commitments.insert(*commitment, true);
                return Some((*commitment, *value, *blinding));
            }
        }
        None
    }
}

#[tokio::main]
async fn main() {
    println!("🌟 Nulla Network Faucet Service starting...");
    println!("Privacy-native L1 blockchain faucet");
    println!("No public balances - only private commitments");

    let faucet_state = Arc::new(Mutex::new(FaucetState::new()));

    // Health check endpoint
    let health = warp::path("health")
        .and(warp::get())
        .map(|| {
            warp::reply::with_status(
                "Nulla Faucet: Ready to distribute private commitments",
                warp::http::StatusCode::OK,
            )
        });

    // Faucet request endpoint
    let faucet_state_filter = warp::any().map(move || faucet_state.clone());
    
    let faucet = warp::path("faucet")
        .and(warp::post())
        .and(warp::body::json())
        .and(faucet_state_filter)
        .and_then(handle_faucet_request);

    // Info endpoint
    let info = warp::path("info")
        .and(warp::get())
        .map(|| {
            let info = serde_json::json!({
                "name": "Nulla Network Faucet",
                "description": "Privacy-native blockchain faucet service",
                "version": "0.1.0",
                "network": "nulla-testnet",
                "distribution": {
                    "amount": "1000 NULLA per request",
                    "method": "Private commitments via ZK proofs",
                    "frequency": "Once per stealth address"
                },
                "privacy": {
                    "no_public_balances": true,
                    "stealth_addresses_only": true,
                    "anonymous_transactions": true
                }
            });
            warp::reply::json(&info)
        });

    let routes = health
        .or(faucet)
        .or(info)
        .with(warp::cors().allow_any_origin().allow_headers(vec!["content-type"]).allow_methods(vec!["GET", "POST"]));

    println!("📡 Faucet server listening on http://localhost:3030");
    println!("📋 Endpoints:");
    println!("   GET  /health - Health check");
    println!("   GET  /info   - Service information");
    println!("   POST /faucet - Request private tokens");
    println!();
    println!("💧 Ready to distribute genesis commitments!");

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

async fn handle_faucet_request(
    request: FaucetRequest,
    faucet_state: Arc<Mutex<FaucetState>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("🔄 Faucet request for stealth address: {}", request.stealth_address);

    // Parse stealth address hex (32 bytes)
    let stealth_bytes = match hex::decode(request.stealth_address.trim_start_matches("0x")) {
        Ok(b) if b.len() == 32 => {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&b);
            tmp
        }
        _ => {
            let response = FaucetResponse {
                success: false,
                transaction_hash: None,
                message: "Invalid stealth address (expect 32-byte hex)".into(),
                tx_id: None,
                output_commitment: None,
                amount: None,
                new_merkle_root: None,
            };
            return Ok(warp::reply::json(&response));
        }
    };

    // Amount requested or default (clamp later to available note)
    let req_amount = request.amount.unwrap_or(1_000);

    // Connect to node
    let ws = std::env::var("WS").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let api = match OnlineClient::<PolkadotConfig>::from_url(&ws).await {
        Ok(api) => api,
        Err(e) => {
            let response = FaucetResponse {
                success: false,
                transaction_hash: None,
                message: format!("Node connection failed: {}", e),
                tx_id: None,
                output_commitment: None,
                amount: None,
                new_merkle_root: None,
            };
            return Ok(warp::reply::json(&response));
        }
    };

    // Use locally tracked MerkleRoot to avoid decoding complexity; this matches our own sequence
    let old_root = {
        let state = faucet_state.lock().await;
        state.current_merkle_root
    };

    // Select an available genesis commitment
    let (input_commitment, input_value, input_blinding_bytes) = {
        let mut state = faucet_state.lock().await;
        match state.get_available_commitment() {
            Some(t) => t,
            None => {
                let response = FaucetResponse {
                    success: false,
                    transaction_hash: None,
                    message: "Faucet empty: no genesis commitments available".to_string(),
                    tx_id: None,
                    output_commitment: None,
                    amount: None,
                    new_merkle_root: None,
                };
                return Ok(warp::reply::json(&response));
            }
        }
    };

    let amount = req_amount.min(input_value);
    let change = input_value.saturating_sub(amount);

    // Build outputs: user note + optional change back to faucet
    let mut rng = OsRng;
    let r_in = Scalar::from_bytes_mod_order(input_blinding_bytes);

    // Create a tx_id and derive r_user deterministically from stealth + tx_id
    let tx_id: [u8; 16] = Scalar::random(&mut rng).to_bytes()[..16].try_into().unwrap();
    let mut hasher = Sha512::new();
    hasher.update(b"R_USER");
    hasher.update(&stealth_bytes);
    hasher.update(&tx_id);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    let r_user = Scalar::from_bytes_mod_order_wide(&wide);

    let r_change = if change > 0 { Some(Scalar::random(&mut rng)) } else { None };
    let out_user = pedersen_commit(amount, r_user);
    let outputs = if let Some(rch) = r_change {
        let out_change = pedersen_commit(change, rch);
        vec![out_user, out_change]
    } else {
        vec![out_user]
    };

    // Fee: 0 for now, unique fee_nullifier per tx
    let r_fee = Scalar::random(&mut rng);
    let fee_commitment = pedersen_commit(0, r_fee);
    let fee_secret: [u8; 32] = Scalar::random(&mut rng).to_bytes();
    let fee_nullifier = derive_nullifier(&fee_commitment, &fee_secret);

    // Nullifier for the input note (use blinding as secret for demo)
    let input_secret = input_blinding_bytes;
    let nullifier = derive_nullifier(&input_commitment, &input_secret);

    // Compute new merkle root off-chain (placeholder aggregator)
    let new_root = compute_new_merkle_root(old_root, &outputs);

    let public_inputs = ProofPublicInputs {
        merkle_root: old_root,
        new_merkle_root: new_root,
        input_commitments: vec![input_commitment],
        nullifiers: vec![nullifier],
        new_commitments: outputs.clone(),
        fee_commitment,
        fee_nullifier,
        tx_id,
    };

    // Witness for Schnorr balance: w = r_in - r_user - r_change - r_fee
    let mut w = r_in - r_fee;
    w -= r_user;
    if let Some(rch) = r_change { w -= rch; }
    let proof = make_proof_bytes_with_w(&public_inputs, w);
    let encoded = public_inputs.encode();

    // Submit unsigned extrinsic
    let call = dynamic::tx(
        "Proofs",
        "submit_proof",
        vec![Value::from_bytes(&proof), Value::from_bytes(&encoded)],
    );

    let submit_res = match api.tx().create_unsigned(&call) {
        Ok(tx) => tx.submit_and_watch().await,
        Err(e) => Err(e),
    };

    match submit_res {
        Ok(mut progress) => {
            let events = progress.wait_for_finalized_success().await;
            match events {
                Ok(_) => {
                    // Update local merkle root tracker
                    {
                        let mut state = faucet_state.lock().await;
                        state.current_merkle_root = new_root;
                    }
                    let response = FaucetResponse {
                        success: true,
                        transaction_hash: None,
                        message: format!("Faucet sent {} NULLA (change: {}) to stealth address.", amount, change),
                        tx_id: Some(format!("0x{}", hex::encode(tx_id))),
                        output_commitment: Some(format!("0x{}", hex::encode(out_user))),
                        amount: Some(amount),
                        new_merkle_root: Some(format!("0x{}", hex::encode(new_root))),
                    };
                    println!("🎉 Faucet transaction finalized.");
                    Ok(warp::reply::json(&response))
                }
                Err(e) => {
                    let response = FaucetResponse {
                        success: false,
                        transaction_hash: None,
                        message: format!("Tx submitted but failed to finalize: {}", e),
                        tx_id: None,
                        output_commitment: None,
                        amount: None,
                        new_merkle_root: None,
                    };
                    Ok(warp::reply::json(&response))
                }
            }
        }
        Err(e) => {
            let response = FaucetResponse {
                success: false,
                transaction_hash: None,
                message: format!("Submit failed: {}", e),
                tx_id: None,
                output_commitment: None,
                amount: None,
                new_merkle_root: None,
            };
            Ok(warp::reply::json(&response))
        }
    }
}
