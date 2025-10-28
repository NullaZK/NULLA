use curve25519_dalek_v4::scalar::Scalar;
use parity_scale_codec::Decode;
use subxt::{dynamic::{self, Value}, OnlineClient, PolkadotConfig};
use wallet::pedersen_commit;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;
    let storage = api.storage().at_latest().await?;

    println!("Checking first 5 faucet genesis commitments on-chain (Proofs.FaucetCommitments)...");
    for i in 0u32..5 {
        let r = Scalar::from((i + 1) as u64);
        let c = pedersen_commit(10_000, r);
        let addr = dynamic::storage("Proofs", "FaucetCommitments", vec![Value::from_bytes(&c)]);
        let present = storage.fetch(&addr).await.ok().flatten().map(|v| {
            let mut bytes = &v.encoded()[..];
            bool::decode(&mut bytes).unwrap_or(false)
        }).unwrap_or(false);
        println!("i={} commitment=0x{} present={}", i+1, hex::encode(c), present);
    }
    Ok(())
}
