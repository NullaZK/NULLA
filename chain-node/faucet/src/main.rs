use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::Filter;

use curve25519_dalek_v4::scalar::Scalar;
use rand::rngs::OsRng;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::dynamic::{self, Value};
use parity_scale_codec::{Decode, Encode};
use sha2::{Digest, Sha512};

use wallet::{ProofPublicInputs, pedersen_commit, make_proof_bytes_with_w, make_aggregated_range_proof, derive_note_blinding_from_shared};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

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

    /// Generate a new faucet commitment when we run out of genesis ones
    pub fn generate_new_commitment(&mut self, value: u64) -> ([u8; 32], [u8; 32]) {
        // Use a deterministic but unique blinding factor
        let count = self.genesis_pool.len() as u64;
        let blinding_scalar = Scalar::from(1000 + count); // Start from 1000 to avoid genesis range
        let commitment = pedersen_commit(value, blinding_scalar);
        let blinding = blinding_scalar.to_bytes();
        self.genesis_pool.insert(commitment, (value, blinding));
        (commitment, blinding)
    }

    /// Get an available commitment for spending, or generate a new one
    /// Reset spent commitments to make them available again (infinite faucet mode)
    pub fn reset_spent_commitments(&mut self) {
        println!("🔄 Resetting faucet commitments for infinite mode");
        self.spent_commitments.clear();
    }

    /// Get an available commitment for spending, with infinite reset capability
    pub fn get_available_commitment(&mut self) -> ([u8; 32], u64, [u8; 32]) {
        // First, try to find an available existing commitment
        for (commitment, (value, blinding)) in &self.genesis_pool {
            if !self.spent_commitments.contains_key(commitment) {
                return (*commitment, *value, *blinding);
            }
        }
        // If no existing commitments available, reset spent commitments for infinite mode
        self.reset_spent_commitments();
        
        // Now get the first available commitment (should work after reset)
        for (commitment, (value, blinding)) in &self.genesis_pool {
            return (*commitment, *value, *blinding);
        }
        
        // This should never happen with 20 genesis commitments
        panic!("No genesis commitments available even after reset");
    }

    /// Mark a genesis commitment as spent after successful finalization
    pub fn mark_spent(&mut self, commitment: [u8; 32]) {
        self.spent_commitments.insert(commitment, true);
    }
}

#[tokio::main]
async fn main() {
    println!("🌟 Nulla Network Faucet Service starting...");
    println!("Privacy-native L1 blockchain faucet");
    println!("No public balances - only private commitments");

    // Show which node WS endpoint this faucet will use (prefer NULLA_WS, fallback WS)
    let ws_env = std::env::var("NULLA_WS").or_else(|_| std::env::var("WS")).unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    println!("🔗 Connecting to node WS endpoint: {}", ws_env);

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

    // Amount requested or default (we'll compute change if less than input value)
    let req_amount = request.amount.unwrap_or(1_000);

    // Connect to node with a short timeout so HTTP clients don't hang forever
    // Prefer NULLA_WS, fallback to WS (legacy), else default to 9944
    let ws = std::env::var("NULLA_WS").or_else(|_| std::env::var("WS")).unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    println!("[faucet] connecting to node: {}", ws);
    let api = match tokio::time::timeout(std::time::Duration::from_secs(5), OnlineClient::<PolkadotConfig>::from_url(&ws)).await {
        Ok(Ok(api)) => api,
        Ok(Err(e)) => {
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
        Err(_) => {
            let response = FaucetResponse {
                success: false,
                transaction_hash: None,
                message: format!("Node connection timeout when dialing {} (check WS port)", ws),
                tx_id: None,
                output_commitment: None,
                amount: None,
                new_merkle_root: None,
            };
            return Ok(warp::reply::json(&response));
        }
    };

    // Try to read current root from chain; fallback to locally tracked root
    let fetch_current_root = async {
        let addr = dynamic::storage("Proofs", "CurrentRoot", vec![]);
        match api.storage().at_latest().await {
            Ok(storage) => match storage.fetch(&addr).await {
                Ok(Some(val)) => {
                    let bytes = val.encoded().to_vec();
                    if bytes.len() >= 32 {
                        let mut root = [0u8; 32];
                        root.copy_from_slice(&bytes[..32]);
                        Some(root)
                    } else { None }
                }
                _ => None,
            },
            _ => None,
        }
    };
    let old_root = if let Some(r) = fetch_current_root.await {
        r
    } else {
        let state = faucet_state.lock().await;
        state.current_merkle_root
    };

    // Select an available commitment or generate a new one
    let (input_commitment, input_value, input_blinding_bytes) = {
        let mut state = faucet_state.lock().await;
        state.get_available_commitment()
    };

    // Support change: amount is clamped to available note value
    let amount = req_amount.min(input_value);
    let change = input_value.saturating_sub(amount);

    // Build outputs: user note + optional change back to faucet
    let mut rng = OsRng;
    let r_in = Scalar::from_bytes_mod_order(input_blinding_bytes);

    // Create a tx_id
    let tx_id: [u8; 16] = Scalar::random(&mut rng).to_bytes()[..16].try_into().unwrap();

    // Prepare ECDH for recipient to derive r_user and construct hints consistently
    let to_point: curve25519_dalek_v4::ristretto::RistrettoPoint = match curve25519_dalek_v4::ristretto::CompressedRistretto(stealth_bytes).decompress() {
        Some(p) => p,
        None => {
            let response = FaucetResponse {
                success: false,
                transaction_hash: None,
                message: "Invalid recipient stealth address (not a valid point)".into(),
                tx_id: None,
                output_commitment: None,
                amount: None,
                new_merkle_root: None,
            };
            return Ok(warp::reply::json(&response));
        }
    };
    let eph_sk = Scalar::random(&mut rng);
    let eph_pk = (eph_sk * curve25519_dalek_v4::constants::RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let shared = (eph_sk * to_point).compress().to_bytes();
    let mut shared_arr=[0u8;32]; shared_arr.copy_from_slice(&shared);

    // r_user from shared and tx_id; change optional random (faucet-owned)
    let r_user = derive_note_blinding_from_shared(&shared_arr, &tx_id);
    let r_change = if change > 0 { Some(Scalar::random(&mut rng)) } else { None };
    let out_user = pedersen_commit(amount, r_user);
    let (outputs, out_change_opt, rch_bytes_opt) = if let Some(rch) = r_change {
        let out_change = pedersen_commit(change, rch);
        (vec![out_user, out_change], Some(out_change), Some(rch.to_bytes()))
    } else {
        (vec![out_user], None, None)
    };

    // Fee: 0 for now, unique fee_nullifier per tx
    let r_fee = Scalar::random(&mut rng);
    let fee_commitment = pedersen_commit(0, r_fee);
    let fee_secret: [u8; 32] = Scalar::random(&mut rng).to_bytes();
    let fee_nullifier = sp_core::blake2_256(&[fee_commitment, fee_secret].concat());

    // Nullifier for the input note.
    // In dev "infinite faucet" mode we must ensure this is UNIQUE per request to avoid mempool bans (1012)
    // and on-chain NullifierUsed conflicts. Since faucet genesis inputs skip ownership/nullifier formula checks
    // in the runtime, we can derive a per-tx nullifier using commitment, tx_id and a fresh nonce.
    let nonce: [u8; 32] = Scalar::random(&mut rng).to_bytes();
    let mut nulldata = [0u8; 32 + 16 + 32];
    nulldata[..32].copy_from_slice(&input_commitment);
    nulldata[32..48].copy_from_slice(&tx_id);
    nulldata[48..].copy_from_slice(&nonce);
    let nullifier = sp_core::blake2_256(&nulldata);

    // Compute expected new_merkle_root off-chain to satisfy runtime equality check
    // Fetch current Leaves (already hashed as leaves) and append new output leaves
    let new_root = {
        let leaves_addr = dynamic::storage("Proofs", "Leaves", vec![]);
        let cur_leaves: Vec<[u8;32]> = match api.storage().at_latest().await {
            Ok(storage) => match storage.fetch(&leaves_addr).await {
                Ok(Some(val)) => {
                    let mut bytes = &val.encoded()[..];
                    Decode::decode(&mut bytes).unwrap_or_default()
                }
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        // Build new leaves vector by appending hashes of new commitments
        let mut leaves2 = cur_leaves.clone();
        for c in outputs.iter() {
            leaves2.push(leaf_hash(*c));
        }
        compute_merkle_root(&leaves2)
    };

    let public_inputs = ProofPublicInputs {
        merkle_root: old_root,
        new_merkle_root: new_root,
        input_commitments: vec![input_commitment],
        input_indices: vec![0],
        input_paths: vec![Vec::new()],
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
    // Build aggregated range proof for outputs and fee (values >=0, 64-bit)
    let mut values: Vec<u64> = vec![amount];
    let mut blinds: Vec<curve25519_dalek_v4::scalar::Scalar> = vec![r_user];
    if change > 0 {
        values.push(change);
        blinds.push(r_change.expect("change blinding"));
    }
    values.push(0u64); blinds.push(r_fee);
    // Debug: print party sizing for aggregated proof
    let m = values.len();
    let party_capacity = m.next_power_of_two();
    println!("[faucet] range-proof parties m={m}, capacity={party_capacity}, nbits=64");
    let range_proof = make_aggregated_range_proof(&values, &blinds, 64, &public_inputs);
    let encoded = public_inputs.encode();

    // Submit with light retry on anchor races
    let mut last_err: Option<String> = None;
    for attempt in 1..=3 {
        // Use the same ECDH values for hints to match r_user derivation above
        // Derive AEAD key and nonce (shared-based)
        let key_bytes = {
            let mut h = sha2::Sha256::new(); h.update(b"NULLA_ECDH"); h.update(&shared); h.finalize()
        };
        let mut key = [0u8;32]; key.copy_from_slice(&key_bytes);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key.into());
        let nonce = {
            let mut h = sha2::Sha256::new(); h.update(b"NULLA_NONCE"); h.update(&shared); h.update([0u8]); // output index 0
            let out = h.finalize(); let mut n=[0u8;12]; n.copy_from_slice(&out[..12]); n
        };
        // Build memo JSON
        let memo_plain = serde_json::json!({
            "amount": amount,
            "tx_id": format!("0x{}", hex::encode(tx_id)),
        }).to_string().into_bytes();
        let memo_cipher = match cipher.encrypt(&nonce.into(), memo_plain.as_ref()) { Ok(ct) => ct, Err(_) => Vec::new() };
        let tag4 = {
            let mut h = sha2::Sha256::new(); h.update(b"TAG"); h.update(&shared); let d=h.finalize(); let mut t=[0u8;4]; t.copy_from_slice(&d[..4]); t
        };
        let mut hint_blob = Vec::with_capacity(32 + 4 + 2 + memo_cipher.len());
        hint_blob.extend_from_slice(&eph_pk);
        hint_blob.extend_from_slice(&tag4);
        let memo_len: u16 = memo_cipher.len() as u16;
        hint_blob.extend_from_slice(&memo_len.to_le_bytes());
        hint_blob.extend_from_slice(&memo_cipher);
    let hints_vec: Vec<Vec<u8>> = vec![hint_blob];
        let hints_bytes = hints_vec.encode();
        let call = dynamic::tx(
            "Proofs",
            "submit_proof",
            vec![Value::from_bytes(&proof), Value::from_bytes(&range_proof), Value::from_bytes(&encoded), Value::from_bytes(&hints_bytes)],
        );
        let submit_res = match api.tx().create_unsigned(&call) {
            Ok(tx) => tx.submit_and_watch().await,
            Err(e) => Err(e),
        };
        match submit_res {
            Ok(mut progress) => {
                match progress.wait_for_finalized_success().await {
                    Ok(_) => {
                        // Update local state: mark input as spent, ignore change complexity for infinite faucet
                        // Fetch canonical on-chain root after finalization and update local state
                        let new_root_onchain = {
                            let addr = dynamic::storage("Proofs", "CurrentRoot", vec![]);
                            match api.storage().at_latest().await {
                                Ok(storage) => match storage.fetch(&addr).await { Ok(Some(val)) => {
                                    let bytes = val.encoded().to_vec();
                                    let mut root=[0u8;32]; root.copy_from_slice(&bytes[..32]); root
                                }, _ => [0u8;32] },
                                _ => [0u8;32],
                            }
                        };
                        {
                            let mut state = faucet_state.lock().await;
                            state.current_merkle_root = new_root_onchain;
                            state.mark_spent(input_commitment);
                        }
                        let response = FaucetResponse {
                            success: true,
                            transaction_hash: None,
                            message: format!("Faucet sent {} NULLA (change: {}) to stealth address.", amount, change),
                            tx_id: Some(format!("0x{}", hex::encode(tx_id))),
                            output_commitment: Some(format!("0x{}", hex::encode(out_user))),
                            amount: Some(amount),
                            new_merkle_root: Some(format!("0x{}", hex::encode(new_root_onchain))),
                        };
                        println!("🎉 Faucet transaction finalized (attempt {attempt}).");
                        return Ok(warp::reply::json(&response));
                    }
                    Err(e) => {
                        last_err = Some(format!("finalize error: {}", e));
                    }
                }
            }
            Err(e) => { last_err = Some(format!("submit error: {}", e)); }
        }
        // Brief backoff between retries
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    let response = FaucetResponse {
        success: false,
        transaction_hash: None,
        message: format!("Faucet failed after retries: {}", last_err.unwrap_or_else(|| "unknown".into())),
        tx_id: None,
        output_commitment: None,
        amount: None,
        new_merkle_root: None,
    };
    Ok(warp::reply::json(&response))
}

/// Fetch the full list of leaves from the runtime and compute the Merkle root.
async fn fetch_and_compute_merkle_root(api: &OnlineClient<PolkadotConfig>) -> Result<[u8; 32], String> {
    let addr = dynamic::storage("Proofs", "Leaves", vec![]);
    let leaves: Vec<[u8; 32]> = match api.storage().at_latest().await {
        Ok(storage) => match storage.fetch(&addr).await {
            Ok(Some(val)) => {
                let mut bytes = &val.encoded()[..];
                Decode::decode(&mut bytes).unwrap_or_default()
            }
            _ => return Err("Failed to fetch leaves from runtime".into()),
        },
        Err(_) => return Err("Failed to connect to runtime".into()),
    };

    // Compute the Merkle root using the runtime's logic
    Ok(compute_merkle_root(&leaves))
}

/// Compute full binary Merkle root by padding leaves to next power-of-two with zero hash.
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() { return [0u8; 32]; }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let zero = [0u8; 32];
    while level.len() & (level.len() - 1) != 0 { level.push(zero); }
    let mut cur = level;
    while cur.len() > 1 {
        let mut next = Vec::with_capacity((cur.len() + 1) / 2);
        for pair in cur.chunks(2) {
            let a = pair[0];
            let b = if pair.len() == 2 { pair[1] } else { zero };
            next.push(hash2(a, b));
        }
        cur = next;
    }
    cur[0]
}

/// leaf hash from commitment (matches runtime logic)
fn leaf_hash(commitment: [u8; 32]) -> [u8; 32] {
    // For now, leaf = blake2_256(commitment || zeros)
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&commitment);
    // trailing zeros
    sp_core::hashing::blake2_256(&data)
}

/// blake2_256(left || right)
fn hash2(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&left);
    data[32..].copy_from_slice(&right);
    sp_core::hashing::blake2_256(&data)
}