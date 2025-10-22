use anyhow::Context;
use subxt::{OnlineClient, PolkadotConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("WS").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let api = OnlineClient::<PolkadotConfig>::from_url(&url).await.context("connect ws")?;

    // Latest block events: filter ProofAccepted
    let blk = api.blocks().at_latest().await?;
    println!("Latest block: {:?}", blk.hash());
    let events = blk.events().await?;
    for ev in events.iter() {
        let ev = ev?;
        if ev.pallet_name() == "Proofs" && ev.variant_name() == "ProofAccepted" {
            println!("Event Proofs::ProofAccepted: {:?}", ev.field_values());
        }
    }

    Ok(())
}
