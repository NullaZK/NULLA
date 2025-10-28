#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("spend_faucet tool is disabled after ECDH-based blinding change. Use 'nulla-wallet scan' and 'nulla-wallet transfer' instead.");
    Ok(())
}
