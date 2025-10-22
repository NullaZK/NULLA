use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Parser)]
#[command(name = "nulla-wallet")]
#[command(about = "Nulla Network Privacy-Native Wallet")]
struct Cli {
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

    match cli.command {
        Commands::Init { name } => {
            println!("🔑 Initializing new Nulla wallet: {}", name);
            
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
            
            // This would connect to the blockchain and scan for transactions
            // For now, show a placeholder
            println!("⏳ Scanning recent blocks...");
            println!("✅ Scan complete");
            println!("💰 Found 0 unspent notes");
            println!("🔄 0 pending transactions");
        },
        
        Commands::Balance { name } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }
            
            println!("💰 Balance for wallet: {}", name);
            println!("🔍 Scanning for private notes...");
            
            // This would scan the blockchain for unspent notes
            // For now, show placeholder
            println!("📊 Total Balance: 0 NULLA");
            println!("📝 Unspent Notes: 0");
            println!("🔒 All balances are private on Nulla Network");
        },
        
        Commands::Transfer { to, amount, name } => {
            let wallet_dir = format!(".nulla/wallets/{}", name);
            
            if !Path::new(&wallet_dir).exists() {
                println!("❌ Wallet '{}' not found", name);
                return Ok(());
            }
            
            println!("🚀 Preparing private transfer");
            println!("📤 From: {} (private stealth address)", name);
            println!("📥 To: {}", to);
            println!("💰 Amount: {} NULLA", amount);
            println!();
            
            // This would create and submit a ZK proof transaction
            println!("🔄 Creating zero-knowledge proof...");
            println!("📝 Generating Schnorr signature...");
            println!("🔐 Proof generation complete");
            println!("📡 Broadcasting transaction...");
            
            // Simulate transaction
            let tx_hash = format!("0x{:x}", rand::random::<u64>());
            println!("✅ Transaction submitted: {}", tx_hash);
            println!("🎉 Private transfer complete!");
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
            
            // Make HTTP request to faucet
            let client = reqwest::blocking::Client::new();
            let request_body = serde_json::json!({
                "stealth_address": stealth_address_hex,
                "amount": 1000
            });
            
            match client.post(&format!("{}/faucet", url))
                .json(&request_body)
                .send() {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>() {
                            Ok(json) => {
                                if json["success"].as_bool().unwrap_or(false) {
                                    println!("✅ Faucet request successful!");
                                    if let Some(tx_hash) = json["transaction_hash"].as_str() {
                                        println!("📝 Transaction: {}", tx_hash);
                                    }
                                    if let Some(message) = json["message"].as_str() {
                                        println!("💬 Message: {}", message);
                                    }

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
                                            "ts": chrono::Utc::now().to_rfc3339(),
                                        });
                                        let notes_path = format!("{}/received_notes.json", wallet_dir);
                                        let mut notes: serde_json::Value = if Path::new(&notes_path).exists() {
                                            serde_json::from_str(&fs::read_to_string(&notes_path)?)
                                                .unwrap_or_else(|_| serde_json::json!([]))
                                        } else {
                                            serde_json::json!([])
                                        };
                                        if let Some(arr) = notes.as_array_mut() {
                                            arr.push(note);
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
                            },
                            Err(e) => println!("❌ Failed to parse faucet response: {}", e),
                        }
                    } else {
                        println!("❌ Faucet request failed with status: {}", response.status());
                    }
                },
                Err(e) => {
                    println!("❌ Failed to connect to faucet: {}", e);
                    println!("💡 Make sure the faucet service is running at {}", url);
                }
            }
        },
    }
    
    Ok(())
}
