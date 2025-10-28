use clap::{Parser, Subcommand};
use std::fs;
use std::env;
use std::path::Path;
// use serde::{Serialize, Deserialize};
use curve25519_dalek_v4::scalar::Scalar;
use curve25519_dalek_v4::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_v4::constants::RISTRETTO_BASEPOINT_POINT as G;
use parity_scale_codec::{Encode, Decode};
use subxt::{dynamic::{self, Value}, OnlineClient, PolkadotConfig};
use sha2::{Digest, Sha512};
use wallet::{ProofPublicInputs, pedersen_commit, /* compute_new_merkle_root, */ make_proof_bytes_with_w, make_aggregated_range_proof, derive_note_blinding_from_shared, derive_change_blinding_with_sk};
use ed25519_dalek::{SigningKey, Signer};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use rand::rngs::OsRng;
// use wallet::runtime; // removed typed subxt bindings

#[derive(Parser)]
#[command(name = "nulla-wallet")]
#[command(about = "Nulla Network Privacy-Native Wallet")]
struct Cli {
    /// Node WebSocket endpoint (overrides env). Example: ws://127.0.0.1:9944
    #[arg(long, global = true)]
    ws: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new wallet with a fresh stealth address
    Init {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    /// Import a received note from a JSON receipt file
    Import {
        /// Wallet name to import into
        #[arg(short, long, default_value = "default")]
        name: String,
        /// Path to receipt JSON file
        #[arg(short, long)]
        file: String,
    },
    /// Show wallet address and information
    Address {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    /// Scan blockchain for incoming transactions
    Scan {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    /// Check wallet balance
    Balance {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    /// Transfer tokens to another stealth address
    Transfer {
        /// Recipient stealth address
        #[arg(short, long)]
        to: String,
        /// Amount to transfer
        #[arg(short, long)]
        amount: u64,
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    /// Request tokens from the faucet
    Faucet {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
        /// Faucet URL
        #[arg(short, long, default_value = "http://localhost:3030")]
        url: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // If provided via CLI, export to env so all call sites see it
    if let Some(ws) = &cli.ws { env::set_var("NULLA_WS", ws); }

    // Helper: pick node WS URL from env (prefer NULLA_WS, fallback WS) or default to 9944
    fn node_ws_url() -> String {
        env::var("NULLA_WS")
            .or_else(|_| env::var("WS"))
            .unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string())
    }

    // Dispatch CLI subcommands
    match cli.command {
        Commands::Init { name } => {
            // Generate stealth address
            let (viewing_key, spending_key) = wallet::generate_keypair();
            let stealth_address = wallet::derive_stealth_address(&viewing_key, &spending_key);
            
            // Create wallet directory
            let wallet_dir = format!(".nulla/wallets/{}", name);
            fs::create_dir_all(&wallet_dir)?;
            
            // Save keys (in production, use proper encryption)
            fs::write(format!("{}/viewing_key", wallet_dir), viewing_key)?;
            fs::write(format!("{}/spending_key", wallet_dir), spending_key)?;
            fs::write(format!("{}/stealth_address", wallet_dir), stealth_address)?;
            
            println!("✅ Wallet initialized successfully!");
            println!("📍 Stealth address: {}", hex::encode(stealth_address));
            println!("📁 Wallet data stored in: {}", wallet_dir);
            println!();
            println!("🚰 To get testnet tokens, run:");
            println!("   nulla-wallet faucet --name {}", name);
        },
        
        Commands::Address { name } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found. Run 'nulla-wallet init --name {}' first.", name, name);
                return Ok(());
            }
            
            let stealth_address = fs::read(format!("{}/stealth_address", wallet_dir))?;
            
            println!("👤 Wallet: {}", name);
            println!("📍 Stealth Address: {}", hex::encode(stealth_address));
            println!("🔐 Privacy-native L1 address (no public balances)");
        },
        
        Commands::Scan { name } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }
            
            println!("🔍 Scanning blockchain for wallet: {}", name);
            println!("📡 Connecting to Nulla Network...");
            let ws = node_ws_url();
            println!("🔗 WS: {}", ws);
            let rt = tokio::runtime::Runtime::new()?;
            let api = rt.block_on(OnlineClient::<PolkadotConfig>::from_url(&ws))?;

            // Load viewing key and address
            let viewing_key_bytes = fs::read(format!("{}/viewing_key", wallet_dir))?;
            if viewing_key_bytes.len() != 32 { println!("❌ Bad viewing_key length"); return Ok(()); }
            let mut vk_arr=[0u8;32]; vk_arr.copy_from_slice(&viewing_key_bytes);
            let v_scalar = Scalar::from_bytes_mod_order(vk_arr);
            let my_addr_bytes = fs::read(format!("{}/stealth_address", wallet_dir))?;
            let my_addr_hex = hex::encode(&my_addr_bytes);

            // Scan state
            let scan_state_path = format!("{}/scan_state.json", wallet_dir);
            let last_scanned: u64 = if Path::new(&scan_state_path).exists() {
                serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&scan_state_path)?)
                    .ok()
                    .and_then(|v| v.get("last_block").and_then(|n| n.as_u64()))
                    .unwrap_or(0)
            } else { 0 };

            // Latest finalized block number
            // Determine latest finalized block number
            let latest_num: u64 = rt.block_on(async {
                match api.blocks().at_latest().await {
                    Ok(block) => block.number() as u64,
                    Err(_) => 0,
                }
            });

            let start = if last_scanned == 0 { latest_num.saturating_sub(128) } else { last_scanned + 1 };
            let mut total_events = 0u32;
            let mut total_hints = 0u32;
            let mut tag_mismatches = 0u32;
            let mut decrypt_failures = 0u32;
            let mut memo_failures = 0u32;
            let mut imported = 0u32;
            let mut matched_for_me = 0u32;
            let mut already_present = 0u32;
            let mut updated_existing = 0u32;
            println!("⏳ Scanning blocks {}..={} for Proofs::ProofAccepted", start, latest_num);

            // Walk backwards from latest to start by following parent hashes, then process in ascending order
            let mut to_process: Vec<(u64, subxt::utils::H256)> = Vec::new();
            {
                let mut cur = match rt.block_on(api.blocks().at_latest()) { Ok(b) => b, Err(_) => { println!("❌ Failed to access latest block"); return Ok(()); } };
                loop {
                    let n = cur.number() as u64;
                    if n < start { break; }
                    to_process.push((n, cur.hash()));
                    if n == 0 { break; }
                    let parent = cur.header().parent_hash;
                    cur = match rt.block_on(api.blocks().at(parent)) { Ok(b) => b, Err(_) => break };
                }
            }
            to_process.sort_by_key(|(n, _)| *n);

            for (n, hash) in to_process.into_iter() {
                let events = match rt.block_on(api.events().at(hash)) { Ok(e) => e, Err(_) => continue };
                let mut proofs_events = 0u32;
                for ev in events.iter() {
                    let Ok(details) = ev else { continue };
                    if details.pallet_name() != "Proofs" || details.variant_name() != "ProofAccepted" { continue; }
                    proofs_events += 1;
                    total_events += 1;

                    // Decode event fields as SCALE tuple: (tx_id, new_root, outputs, hints)
                    let hints_vec: Vec<Vec<u8>> = {
                        let mut all_fields = details.field_bytes();
                        // 1) Preferred encoding: last field is a blob Vec<u8> containing SCALE Vec<Vec<u8>>
                        type TupleBlob = ([u8;16], [u8;32], Vec<[u8;32]>, Vec<u8>);
                        if let Ok((_tx_id, _new_root, _outputs, blob)) = <TupleBlob as Decode>::decode(&mut all_fields) {
                            let mut blob_ref = &blob[..];
                            Decode::decode(&mut blob_ref).unwrap_or_default()
                        } else {
                            // 2) Fallback: last field is directly Vec<Vec<u8>>
                            let mut all_fields2 = details.field_bytes();
                            type TupleNested = ([u8;16], [u8;32], Vec<[u8;32]>, Vec<Vec<u8>>);
                            match <TupleNested as Decode>::decode(&mut all_fields2) {
                                Ok((_tx_id, _new_root, _outputs, hints)) => hints,
                                Err(_) => Vec::new(),
                            }
                        }
                    };
                    if hints_vec.is_empty() { continue; }

                    total_hints += hints_vec.len() as u32;

                    // For each hint, verify tag and decrypt memo
                    for (i, hint) in hints_vec.iter().enumerate() {
                        if hint.len() < 38 { continue; }
                        let eph_pk_bytes: [u8;32] = match hint.get(0..32).and_then(|s| s.try_into().ok()) { Some(a) => a, None => continue };
                        let tag4: [u8;4] = match hint.get(32..36).and_then(|s| s.try_into().ok()) { Some(a) => a, None => continue };
                        let memo_len = match hint.get(36..38).and_then(|s| s.try_into().ok()) { Some(a) => u16::from_le_bytes(a) as usize, None => continue };
                        if hint.len() < 38 + memo_len { continue; }
                        let memo_ct = &hint[38..38+memo_len];
                        let eph_pt = match CompressedRistretto(eph_pk_bytes).decompress() { Some(p) => p, None => continue };
                        let shared = (v_scalar * eph_pt).compress().to_bytes();
                        // Verify tag
                        let mut th = sha2::Sha256::new(); th.update(b"TAG"); th.update(&shared);
                        let tag_chk = th.finalize();
                        if &tag_chk[..4] != &tag4 { tag_mismatches += 1; continue; }
                        // AEAD key & nonce
                        let key_bytes = { let mut h = sha2::Sha256::new(); h.update(b"NULLA_ECDH"); h.update(&shared); h.finalize() };
                        let mut key=[0u8;32]; key.copy_from_slice(&key_bytes);
                        let cipher = ChaCha20Poly1305::new(&key.into());
                        let nonce = { let mut h = sha2::Sha256::new(); h.update(b"NULLA_NONCE"); h.update(&shared); h.update([i as u8]); let out=h.finalize(); let mut n=[0u8;12]; n.copy_from_slice(&out[..12]); n };
                        let memo_plain = match cipher.decrypt(&nonce.into(), memo_ct) { Ok(p) => p, Err(_) => { decrypt_failures += 1; continue } };
                        let memo: serde_json::Value = match serde_json::from_slice(&memo_plain) { Ok(v) => v, Err(_) => continue };
                        let amount = memo.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                        let tx_id_str = memo.get("tx_id").and_then(|v| v.as_str()).unwrap_or("");
                        if amount == 0 || tx_id_str.is_empty() { continue; }
                        matched_for_me += 1;

                        // Reconstruct output commitment deterministically
                        // tx_id is carried in the memo JSON; parse from tx_id_str
                        let mut tx_id_arr = [0u8;16];
                        if let Ok(txb) = hex::decode(tx_id_str.trim_start_matches("0x")) {
                            if txb.len() >= 16 { tx_id_arr.copy_from_slice(&txb[..16]); }
                        }
                        // r_user is derived from ECDH shared secret and tx_id (recipient can compute shared)
                        let shared_arr: [u8;32] = shared;
                        let r_user = derive_note_blinding_from_shared(&shared_arr, &tx_id_arr);
                        let out_cmt = pedersen_commit(amount, r_user);

                        // Fetch canonical on-chain root at this block
                        let new_root_hex = {
                            let addr = dynamic::storage("Proofs", "CurrentRoot", vec![]);
                            let storage = api.storage().at(hash);
                            let fetched = rt.block_on(storage.fetch(&addr)).ok().flatten();
                            fetched.map(|v| format!("0x{}", hex::encode(v.encoded()))).unwrap_or_else(|| "0x".into())
                        };

                        // Persist note
                        let notes_path = format!("{}/received_notes.json", wallet_dir);
                        let mut notes: serde_json::Value = if Path::new(&notes_path).exists() {
                            serde_json::from_str(&fs::read_to_string(&notes_path)?) .unwrap_or_else(|_| serde_json::json!([]))
                        } else { serde_json::json!([]) };
                        let note = serde_json::json!({
                            "stealth_address": format!("0x{}", my_addr_hex),
                            "tx_id": tx_id_str,
                            "output_commitment": format!("0x{}", hex::encode(out_cmt)),
                            "amount": amount,
                            "merkle_root": new_root_hex,
                            "source": "scan",
                            // persist blinding for spend auth w/o revealing identity
                            "blinding": format!("0x{}", hex::encode(r_user.to_bytes())),
                            "spent": false,
                            "ts": chrono::Utc::now().to_rfc3339(),
                        });
                        if let Some(arr) = notes.as_array_mut() {
                            if let Some(pos) = arr.iter().position(|e| e.get("tx_id").and_then(|v| v.as_str()) == note.get("tx_id").and_then(|v| v.as_str())) {
                                already_present += 1;
                                // Update merkle_root if different or missing and inject blinding if missing
                                if let Some(obj) = arr[pos].as_object_mut() {
                                    let old_root = obj.get("merkle_root").and_then(|v| v.as_str()).unwrap_or("");
                                    let mut changed = false;
                                    if old_root.is_empty() || old_root != new_root_hex {
                                        obj.insert("merkle_root".to_string(), serde_json::Value::String(new_root_hex.clone()));
                                        changed = true;
                                    }
                                    let has_blinding = obj.get("blinding").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                                    if !has_blinding {
                                        obj.insert("blinding".to_string(), serde_json::Value::String(format!("0x{}", hex::encode(r_user.to_bytes()))));
                                        changed = true;
                                    }
                                    if changed { updated_existing += 1; }
                                }
                            } else {
                                arr.push(note); imported += 1;
                            }
                        }
                        fs::write(&notes_path, serde_json::to_string_pretty(&notes)?)?;
                    }
                }
                if proofs_events > 0 { println!("📦 Block {n}: processed {proofs_events} ProofAccepted events"); }
                // Update scan state per block to be resilient
                fs::write(&scan_state_path, serde_json::json!({"last_block": n}).to_string())?;
            }
            println!("✅ Scan complete. Imported {} notes.", imported);
            if total_events > 0 {
                println!("ℹ️  Scan saw {} ProofAccepted event(s), {} hint(s). Tag mismatches: {}, decrypt failures: {}, memo failures: {}.", total_events, total_hints, tag_mismatches, decrypt_failures, memo_failures);
                println!("ℹ️  Matched {} note(s) for this wallet ({} new, {} already saved; {} updated).",
                    matched_for_me, imported, already_present, updated_existing);
            }
        },
        
        Commands::Balance { name } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }
            
            println!("💰 Balance for wallet: {}", name);
            
            // Read local received notes and compute balance from unspent entries
            let notes_path = format!("{}/received_notes.json", wallet_dir);
            if !Path::new(&notes_path).exists() {
                println!("📊 Total Balance: 0 NULLA");
                println!("📝 Unspent Notes: 0");
                println!("ℹ️  No notes found yet. Run 'nulla-wallet faucet --name {}' or 'nulla-wallet scan --name {}'", name, name);
                return Ok(());
            }
            let notes_str = match fs::read_to_string(&notes_path) { Ok(s) => s, Err(_) => String::new() };
            let notes_json: serde_json::Value = serde_json::from_str(&notes_str).unwrap_or_else(|_| serde_json::json!([]));
            let mut total: u128 = 0;
            let mut count: u32 = 0;
            if let Some(arr) = notes_json.as_array() {
                for n in arr {
                    let spent = n.get("spent").and_then(|v| v.as_bool()).unwrap_or(false);
                    let amt = n.get("amount").and_then(|v| v.as_u64()).unwrap_or(0) as u128;
                    if !spent {
                        total = total.saturating_add(amt);
                        count += 1;
                    }
                }
            }
            println!("📊 Total Balance: {} NULLA", total);
            println!("📝 Unspent Notes: {}", count);
            println!("🔒 All balances are private on Nulla Network");
        },
        
    Commands::Transfer { to, amount, name } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }

            // Decode recipient stealth address (compressed Ristretto viewing pubkey)
            let to_bytes = match hex::decode(to.trim_start_matches("0x")) {
                Ok(b) if b.len() == 32 => {
                    let mut tmp = [0u8; 32];
                    tmp.copy_from_slice(&b);
                    tmp
                }
                _ => {
                    println!("❌ Invalid recipient stealth address (expect 32-byte compressed Ristretto pubkey in hex)");
                    return Ok(());
                }
            };
            let to_point: RistrettoPoint = match CompressedRistretto(to_bytes).decompress() {
                Some(p) => p,
                None => { println!("❌ Recipient address not a valid Ristretto point"); return Ok(()); }
            };

            // Load notes and select an unspent one with sufficient amount
            let notes_path = format!("{}/received_notes.json", wallet_dir);
            if !Path::new(&notes_path).exists() {
                println!("❌ No received notes found. Faucet first.");
                return Ok(());
            }
            let notes_str = fs::read_to_string(&notes_path)?;
            let notes_json: serde_json::Value = serde_json::from_str(&notes_str)?;
            let arr: Vec<serde_json::Value> = notes_json.as_array().cloned().unwrap_or_default();
            if arr.is_empty() { println!("❌ No notes to spend. Faucet first."); return Ok(()); }
            // Prefer newest first
            let mut selected: Option<serde_json::Value> = None;
            for n in arr.iter().rev() {
                let spent = n.get("spent").and_then(|v| v.as_bool()).unwrap_or(false);
                let amt = n.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                if !spent && amt >= amount { selected = Some(n.clone()); break; }
            }
            let note = match selected { Some(n) => n, None => { println!("❌ No unspent note with sufficient amount."); return Ok(()); } };
            let stealth_hex = note["stealth_address"].as_str().ok_or("missing stealth_address")?;
            let tx_id_hex = note["tx_id"].as_str().ok_or("missing tx_id")?;
            let in_amount = note["amount"].as_u64().ok_or("missing amount")?;
            let source = note["source"].as_str().unwrap_or("faucet");

            // Partial spends are allowed; change will be returned back to sender.

            // Decode our own stealth + tx_id
            let mut my_addr = [0u8; 32];
            let sbytes = hex::decode(stealth_hex.trim_start_matches("0x"))?;
            my_addr.copy_from_slice(&sbytes[..32]);
            let mut in_txid = [0u8; 16];
            let tbytes = hex::decode(tx_id_hex.trim_start_matches("0x"))?;
            in_txid.copy_from_slice(&tbytes[..16]);

            // Connect to node
            let rt = tokio::runtime::Runtime::new()?;
            let ws = node_ws_url();
            println!("🔗 WS: {}", ws);
            let api = rt.block_on(OnlineClient::<PolkadotConfig>::from_url(&ws))?;
            
            // Fetch current root (fallback to note's root)
            let onchain_root = {
                let addr = dynamic::storage("Proofs", "CurrentRoot", vec![]);
                let fetched = rt.block_on(async {
                    match api.storage().at_latest().await {
                        Ok(storage) => storage.fetch(&addr).await.ok().flatten(),
                        Err(_) => None,
                    }
                });
                if let Some(val) = fetched {
                    let bytes = val.encoded().to_vec();
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&bytes[..32]);
                    root
                } else {
                    let mut r = [0u8; 32];
                    if let Some(hexr) = note["merkle_root"].as_str() {
                        let b = hex::decode(hexr.trim_start_matches("0x")).unwrap_or_default();
                        if b.len() >= 32 { r.copy_from_slice(&b[..32]); }
                    }
                    r
                }
            };

            // Recreate input commitment blinding r_in
            // - For change notes: derive from our private spending key and tx_id
            // - For received notes: require persisted blinding (from a prior scan decoding ECDH hint)
            let r_in = if source == "change" {
                let sk_vec = fs::read(format!("{}/spending_key", wallet_dir))?;
                if sk_vec.len() != 32 { println!("❌ Bad spending_key length"); return Ok(()); }
                let mut sk_array_tmp = [0u8;32]; sk_array_tmp.copy_from_slice(&sk_vec);
                derive_change_blinding_with_sk(&sk_array_tmp, &in_txid)
            } else {
                let blind_hex = note.get("blinding").and_then(|v| v.as_str()).unwrap_or("");
                if blind_hex.is_empty() {
                    println!("❌ Missing blinding for this note. Run 'nulla-wallet scan --name {}' first to import it via on-chain hints.", name);
                    return Ok(());
                }
                let bh = hex::decode(blind_hex.trim_start_matches("0x")).unwrap_or_default();
                if bh.len() < 32 { println!("❌ Bad blinding length in note"); return Ok(()); }
                let mut rbytes=[0u8;32]; rbytes.copy_from_slice(&bh[..32]);
                Scalar::from_bytes_mod_order(rbytes)
            };
            let input_commitment = pedersen_commit(in_amount, r_in);
            let _input_secret = r_in.to_bytes();

            // Create a new tx_id for this send
            let new_txid: [u8; 16] = {
                let mut h = Sha512::new();
                h.update(b"TX"); h.update(&input_commitment); let mut w=[0u8;64]; w.copy_from_slice(&h.finalize());
                let s = Scalar::from_bytes_mod_order_wide(&w).to_bytes();
                let mut t=[0u8;16]; t.copy_from_slice(&s[..16]); t
            };

            // Ownership keypair derived from spending_key (ed25519)
            let sk_vec = fs::read(format!("{}/spending_key", wallet_dir))?;
            if sk_vec.len() != 32 { println!("❌ Bad spending_key length"); return Ok(()); }
            let mut sk_array = [0u8;32]; sk_array.copy_from_slice(&sk_vec);
            let ed_sk = SigningKey::from_bytes(&sk_array);
            let ed_pk_bytes: [u8;32] = ed_sk.verifying_key().to_bytes();
            // Sign message: tx_id || input_commitment
            let mut msg = Vec::with_capacity(48);
            msg.extend_from_slice(&new_txid);
            msg.extend_from_slice(&input_commitment);
            let sig_bytes: [u8;64] = ed_sk.sign(&msg).to_bytes();
            // Nullifier redesigned: PRF(spend_secret, note_id) proved in-circuit (TODO).
            // Transitional implementation: derive nf from spending key and note id (tx_id of the note),
            // while still verifying ed25519 signature on-chain for authorization.
            // nf = blake2_256(b"NF" || in_txid || spending_key)
            let mut nf_data = [0u8; 16 + 32 + 2]; // allocate extra to avoid stack reallocation
            // Build in a Vec for clarity
            let mut nf_vec = Vec::with_capacity(16 + 32 + 2);
            nf_vec.extend_from_slice(b"NF");
            nf_vec.extend_from_slice(&in_txid);
            nf_vec.extend_from_slice(&sk_array);
            let nullifier = sp_core::blake2_256(&nf_vec);

            // Fetch on-chain index and leaves to build Merkle path
            let (leaf_index, merkle_path): (u32, Vec<[u8;32]>) = {
                let idx_addr = dynamic::storage("Proofs", "CommitmentIndex", vec![Value::from_bytes(&input_commitment)]);
                let leaves_addr = dynamic::storage("Proofs", "Leaves", vec![]);
                let (idx_val, leaves_val) = rt.block_on(async {
                    match api.storage().at_latest().await {
                        Ok(storage) => {
                            let i = storage.fetch(&idx_addr).await.ok().flatten();
                            let l = storage.fetch(&leaves_addr).await.ok().flatten();
                            (i, l)
                        }
                        Err(_) => (None, None),
                    }
                });
                let idx_opt: Option<u32> = idx_val.and_then(|v| {
                    let mut bytes = &v.encoded()[..];
                    Decode::decode(&mut bytes).ok()
                });
                let leaves: Vec<[u8;32]> = leaves_val.map(|v| {
                    let mut bytes = &v.encoded()[..];
                    Decode::decode(&mut bytes).unwrap_or_default()
                }).unwrap_or_default();
                let idx = match idx_opt {
                    Some(v) => v,
                    None => { println!("❌ Input commitment index not found on-chain"); return Ok(()); }
                };
                // Build Merkle path from leaf hashes
                fn hash2(a: [u8;32], b: [u8;32]) -> [u8;32] {
                    let mut buf = [0u8;64];
                    buf[..32].copy_from_slice(&a);
                    buf[32..].copy_from_slice(&b);
                    sp_core::blake2_256(&buf)
                }
                let zero = [0u8;32];
                if leaves.is_empty() { (idx, Vec::new()) } else {
                    let mut level = leaves;
                    while level.len() & (level.len() - 1) != 0 { level.push(zero); }
                    let mut path = Vec::new();
                    let mut i = idx as usize;
                    let mut cur = level;
                    while cur.len() > 1 {
                        let sib_i = if i % 2 == 0 { i + 1 } else { i - 1 };
                        let sib = if sib_i < cur.len() { cur[sib_i] } else { zero };
                        path.push(sib);
                        let mut next = Vec::with_capacity((cur.len()+1)/2);
                        for chunk in cur.chunks(2) {
                            let a = chunk[0];
                            let b = if chunk.len() == 2 { chunk[1] } else { zero };
                            next.push(hash2(a, b));
                        }
                        cur = next;
                        i >>= 1;
                    }
                    (idx, path)
                }
            };

            // Prepare ephemeral for ECDH (reused in hints) and compute shared
            let eph_sk = Scalar::random(&mut OsRng);
            let eph_pk = (eph_sk * G).compress().to_bytes();
            let shared = (eph_sk * to_point).compress().to_bytes();

            // Outputs: recipient and change
            // r_recipient from ECDH shared secret with recipient and tx_id; r_change from our private spending key.
            let r_recipient = {
                let mut shared_arr=[0u8;32]; shared_arr.copy_from_slice(&shared);
                derive_note_blinding_from_shared(&shared_arr, &new_txid)
            };
            let r_change = derive_change_blinding_with_sk(&sk_array, &new_txid);
            let out_recipient = pedersen_commit(amount, r_recipient);
            let change = in_amount.saturating_sub(amount);
            let outputs = if change > 0 { vec![out_recipient, pedersen_commit(change, r_change)] } else { vec![out_recipient] };

            // Fee 0 with unique fee nullifier from new_txid
            let r_fee = {
                let mut h = Sha512::new(); h.update(b"R_FEE"); h.update(&new_txid);
                let mut w=[0u8;64]; w.copy_from_slice(&h.finalize()); Scalar::from_bytes_mod_order_wide(&w)
            };
            let fee_commitment = pedersen_commit(0, r_fee);
            let fee_nullifier = {
                let mut buf = [0u8;64]; buf[..32].copy_from_slice(&fee_commitment); buf[32..].copy_from_slice(&r_fee.to_bytes());
                sp_core::blake2_256(&buf)
            };

            let public_inputs = ProofPublicInputs {
                merkle_root: onchain_root,
                // Do not predict the new root off-chain; runtime computes it.
                new_merkle_root: [0u8; 32],
                input_commitments: vec![input_commitment],
                input_indices: vec![leaf_index],
                input_paths: vec![merkle_path],
                nullifiers: vec![nullifier],
                new_commitments: outputs.clone(),
                fee_commitment,
                fee_nullifier,
                tx_id: new_txid,
            };
            let w = if change > 0 { r_in - r_recipient - r_change - r_fee } else { r_in - r_recipient - r_fee };
            let proof = make_proof_bytes_with_w(&public_inputs, w);
            // Build aggregated range proof for outputs and fee
            let mut values: Vec<u64> = vec![amount];
            let mut blinds: Vec<curve25519_dalek_v4::scalar::Scalar> = vec![r_recipient];
            if change > 0 { values.push(change); blinds.push(r_change); }
            values.push(0u64); blinds.push(r_fee);
            let range_proof = make_aggregated_range_proof(&values, &blinds, 64, &public_inputs);
            let encoded = public_inputs.encode();

            // Build on-chain receiver hint for the recipient output only (index 0)
            // Reuse eph_pk and shared computed above
            // Derive AEAD key and nonce (shared-based nonce enables receiver-side scanning without tx_id)
            let key_bytes = {
                let mut h = sha2::Sha256::new(); h.update(b"NULLA_ECDH"); h.update(&shared); h.finalize()
            };
            let mut key = [0u8;32]; key.copy_from_slice(&key_bytes);
            let cipher = ChaCha20Poly1305::new(&key.into());
            let nonce = {
                let mut h = sha2::Sha256::new(); h.update(b"NULLA_NONCE"); h.update(&shared); h.update([0u8]); // output index 0
                let out = h.finalize(); let mut n=[0u8;12]; n.copy_from_slice(&out[..12]); n
            };
            let memo_plain = serde_json::json!({
                "amount": amount,
                "tx_id": format!("0x{}", hex::encode(new_txid)),
            }).to_string().into_bytes();
            let memo_cipher = match cipher.encrypt(&nonce.into(), memo_plain.as_ref()) { Ok(ct) => ct, Err(_) => { println!("❌ Failed to encrypt memo"); return Ok(()); } };
            let tag4 = {
                let mut h = sha2::Sha256::new(); h.update(b"TAG"); h.update(&shared); let d=h.finalize(); let mut t=[0u8;4]; t.copy_from_slice(&d[..4]); t
            };
            // Pack as bytes: eph_pk(32) || tag(4) || memo_len(2 LE) || memo
            let mut hint_blob = Vec::with_capacity(32 + 4 + 2 + memo_cipher.len());
            hint_blob.extend_from_slice(&eph_pk);
            hint_blob.extend_from_slice(&tag4);
            let memo_len: u16 = memo_cipher.len() as u16;
            hint_blob.extend_from_slice(&memo_len.to_le_bytes());
            hint_blob.extend_from_slice(&memo_cipher);
            let hints_vec: Vec<Vec<u8>> = vec![hint_blob];
            let hints_bytes = hints_vec.encode();

            // Submit unsigned (proof, range_proof, public_inputs, hints)
            let call = dynamic::tx("Proofs","submit_proof", vec![Value::from_bytes(&proof), Value::from_bytes(&range_proof), Value::from_bytes(&encoded), Value::from_bytes(&hints_bytes)]);
            let mut attempts = 0u8;
            let mut finalized_ok = false;
            loop {
                attempts += 1;
                match api.tx().create_unsigned(&call) {
                    Ok(tx) => match rt.block_on(tx.submit_and_watch()) {
                        Ok(mut progress) => match rt.block_on(progress.wait_for_finalized_success()) {
                            Ok(_) => { finalized_ok = true; break },
                            Err(e) => { if attempts>=3 { println!("❌ Finalize failed: {e}"); return Ok(()); } }
                        },
                        Err(e) => { if attempts>=3 { println!("❌ Submit failed: {e}"); return Ok(()); } }
                    },
                    Err(e) => { if attempts>=3 { println!("❌ Create tx failed: {e}"); return Ok(()); } }
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }

            // Fetch the canonical on-chain root after finalization
            let new_root_onchain = if finalized_ok {
                let addr = dynamic::storage("Proofs", "CurrentRoot", vec![]);
                let fetched = rt.block_on(async {
                    match api.storage().at_latest().await {
                        Ok(storage) => storage.fetch(&addr).await.ok().flatten(),
                        Err(_) => None,
                    }
                });
                fetched.map(|val| {
                    let bytes = val.encoded().to_vec();
                    let mut r=[0u8;32]; r.copy_from_slice(&bytes[..32]); r
                }).unwrap_or_default()
            } else { [0u8;32] };

            // Persist our change note locally (if any) and mark input as spent
            if change > 0 {
                let change_note = serde_json::json!({
                    "stealth_address": hex::encode(my_addr),
                    "tx_id": format!("0x{}", hex::encode(new_txid)),
                    "output_commitment": format!("0x{}", hex::encode(pedersen_commit(change, r_change))),
                    "amount": change,
                    // Persist the canonical on-chain root
                    "merkle_root": format!("0x{}", hex::encode(new_root_onchain)),
                    "source": "change",
                    "spent": false,
                    "ts": chrono::Utc::now().to_rfc3339(),
                });
                let mut notes: serde_json::Value = if Path::new(&notes_path).exists() { serde_json::from_str(&fs::read_to_string(&notes_path)?) .unwrap_or_else(|_| serde_json::json!([])) } else { serde_json::json!([]) };
                if let Some(arr) = notes.as_array_mut() {
                    // dedupe by tx_id if exists
                    let exists = arr.iter().any(|e| e.get("tx_id").and_then(|v| v.as_str()) == change_note.get("tx_id").and_then(|v| v.as_str()));
                    if !exists { arr.push(change_note); }
                }
                fs::write(&notes_path, serde_json::to_string_pretty(&notes)?)?;
            }
            // Mark the spent input note in the file by tx_id
            {
                let mut notes: serde_json::Value = if Path::new(&notes_path).exists() { serde_json::from_str(&fs::read_to_string(&notes_path)?) .unwrap_or_else(|_| serde_json::json!([])) } else { serde_json::json!([]) };
                if let Some(arr) = notes.as_array_mut() {
                    for e in arr.iter_mut() {
                        if e.get("tx_id").and_then(|v| v.as_str()) == Some(tx_id_hex) {
                            if let Some(obj) = e.as_object_mut() {
                                obj.insert("spent".to_string(), serde_json::Value::Bool(true));
                            }
                        }
                    }
                }
                fs::write(&notes_path, serde_json::to_string_pretty(&notes)?)?;
            }
            // Export a receipt for the recipient to import (off-chain delivery)
            let outbox_dir = format!("{}/outbox", wallet_dir);
            fs::create_dir_all(&outbox_dir)?;
            let receipt = serde_json::json!({
                "to": hex::encode(to_bytes),
                "tx_id": format!("0x{}", hex::encode(new_txid)),
                "output_commitment": format!("0x{}", hex::encode(out_recipient)),
                "amount": amount,
                // Use the canonical on-chain root in receipts
                "merkle_root": format!("0x{}", hex::encode(new_root_onchain)),
                "source": "transfer",
                "ts": chrono::Utc::now().to_rfc3339(),
            });
            let receipt_path = format!("{}/receipt-{}.json", outbox_dir, hex::encode(new_txid));
            fs::write(&receipt_path, serde_json::to_string_pretty(&receipt)?)?;
            println!("🎉 Private transfer complete!");
            println!("🧾 Saved receipt: {}", receipt_path);
        },
        
        Commands::Import { name, file } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }
            let data = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => { println!("❌ Failed to read receipt: {}", e); return Ok(()); }
            };
            let val: serde_json::Value = match serde_json::from_str(&data) {
                Ok(v) => v,
                Err(e) => { println!("❌ Invalid receipt JSON: {}", e); return Ok(()); }
            };
            // Expect required fields
            let to = val.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let tx_id = val.get("tx_id").and_then(|v| v.as_str()).unwrap_or("");
            let output_commitment = val.get("output_commitment").and_then(|v| v.as_str()).unwrap_or("");
            let amount = val.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
            let merkle_root = val.get("merkle_root").and_then(|v| v.as_str());
            if to.is_empty() || tx_id.is_empty() || output_commitment.is_empty() || amount == 0 {
                println!("❌ Missing required fields in receipt");
                return Ok(());
            }
            // Verify that receipt is intended for this wallet
            let my_addr_hex = hex::encode(fs::read(format!("{}/stealth_address", wallet_dir))?);
            if to.trim_start_matches("0x").to_lowercase() != my_addr_hex.to_lowercase() {
                println!("❌ Receipt not intended for this wallet (to != my address)");
                return Ok(());
            }
            // Append to received_notes.json
            let notes_path = format!("{}/received_notes.json", wallet_dir);
            let mut notes: serde_json::Value = if Path::new(&notes_path).exists() {
                serde_json::from_str(&fs::read_to_string(&notes_path)?) .unwrap_or_else(|_| serde_json::json!([]))
            } else { serde_json::json!([]) };
            let note = serde_json::json!({
                "stealth_address": to,
                "tx_id": tx_id,
                "output_commitment": output_commitment,
                "amount": amount,
                "merkle_root": merkle_root,
                "source": "import",
                "spent": false,
                "ts": chrono::Utc::now().to_rfc3339(),
            });
            if let Some(arr) = notes.as_array_mut() {
                // dedupe by tx_id
                let exists = arr.iter().any(|e| e.get("tx_id").and_then(|v| v.as_str()) == Some(tx_id));
                if exists {
                    println!("ℹ️  Note already imported; skipping duplicate.");
                } else { arr.push(note); }
            }
            fs::write(&notes_path, serde_json::to_string_pretty(&notes)?)?;
            println!("✅ Imported note into {}", notes_path);
        },
        
        Commands::Faucet { name, url } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }
            
            let stealth_address = fs::read(format!("{}/stealth_address", wallet_dir))?;
            let stealth_address_hex = hex::encode(stealth_address);
            
            println!("🚰 Requesting tokens from Nulla faucet");
            println!("📍 Wallet: {}", name);
            println!("🔗 Faucet: {}", url);
            println!("📤 Stealth address: {}", stealth_address_hex);
            println!();
            
            // HTTP client with explicit connect + overall timeout
            // - connect_timeout: fail fast if faucet isn't reachable
            // - timeout: allow enough time for on-chain finalization (can take >30s)
            let client = reqwest::blocking::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("http client");

            println!("🔍 Testing faucet connectivity...");
            
            // Optional health probe (non-fatal)
            match client.get(format!("{}/health", url)).send() {
                Ok(resp) => {
                    println!("✅ Health check successful: status {}", resp.status());
                    if !resp.status().is_success() {
                        println!("ℹ️  Faucet /health returned status {} (proceeding anyway)", resp.status());
                    }
                }
                Err(e) => {
                    println!("❌ Health check failed: {} (will try POST anyway)", e);
                }
            }

            let request_body = serde_json::json!({
                "stealth_address": stealth_address_hex,
                "amount": 1000
            });

            // Single POST request (no retries to avoid double-spending faucet commitments)
            let mut post_err: Option<String> = None;
            let mut json_ok: Option<serde_json::Value> = None;
            
            println!("📡 Sending faucet request...");
            match client.post(&format!("{}/faucet", url))
                .json(&request_body)
                .send() {
                Ok(response) => {
                    println!("✅ POST request successful: status {}", response.status());
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>() {
                            Ok(json) => { json_ok = Some(json); }
                            Err(e) => { post_err = Some(format!("parse json: {}", e)); }
                        }
                    } else {
                        post_err = Some(format!("status {}", response.status()));
                    }
                }
                Err(e) => { 
                    println!("❌ POST request failed: {}", e);
                    post_err = Some(e.to_string()); 
                }
            }

            if let Some(json) = json_ok {
                if json["success"].as_bool().unwrap_or(false) {
                    println!("✅ Faucet request successful!");
                    if let Some(tx_hash) = json["transaction_hash"].as_str() { println!("� Transaction: {}", tx_hash); }
                    if let Some(message) = json["message"].as_str() { println!("💬 Message: {}", message); }

                    // Persist note if present
                    let tx_id_opt = json["tx_id"].as_str().map(|s| s.to_string());
                    let out_comm_opt = json["output_commitment"].as_str().map(|s| s.to_string());
                    let amount_opt = json["amount"].as_u64();
                    let root_opt = json["new_merkle_root"].as_str().map(|s| s.to_string());
                    if let (Some(tx_id), Some(output_commitment), Some(amount)) = (tx_id_opt, out_comm_opt, amount_opt) {
                        let stealth_address_hex = stealth_address_hex.clone();
                        let note = serde_json::json!({
                            "stealth_address": stealth_address_hex,
                            "tx_id": tx_id,
                            "output_commitment": output_commitment,
                            "amount": amount,
                            "merkle_root": root_opt,
                            "source": "faucet",
                            "spent": false,
                            "ts": chrono::Utc::now().to_rfc3339(),
                        });
                        let notes_path = format!("{}/received_notes.json", wallet_dir);
                        let mut notes: serde_json::Value = if Path::new(&notes_path).exists() {
                            serde_json::from_str(&fs::read_to_string(&notes_path)?)
                                .unwrap_or_else(|_| serde_json::json!([]))
                        } else { serde_json::json!([]) };
                        if let Some(arr) = notes.as_array_mut() {
                            let exists = arr.iter().any(|e| e.get("tx_id").and_then(|v| v.as_str()) == note.get("tx_id").and_then(|v| v.as_str()));
                            if !exists { arr.push(note); }
                        }
                        fs::write(&notes_path, serde_json::to_string_pretty(&notes)?)?;
                        println!("🗂️  Saved received note to {notes_path}");
                    } else {
                        println!("ℹ️  Faucet did not return note details (tx_id/output). Skipping persistence.");
                    }
                    println!("💰 Tokens should arrive shortly");
                    println!("🔍 Run 'nulla-wallet scan --name {}' to check", name);
                } else {
                    let message = json["message"].as_str().unwrap_or("Unknown error");
                    println!("❌ Faucet request failed: {}", message);
                }
            } else {
                println!("❌ Failed to connect to faucet: {}", post_err.unwrap_or_else(|| "unknown".into()));
                println!("💡 Make sure the faucet service is running at {}", url);
            }
        },
    }
    
    Ok(())
}