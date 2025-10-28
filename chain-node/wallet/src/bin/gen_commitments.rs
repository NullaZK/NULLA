use curve25519_dalek_v4::scalar::Scalar;
use wallet::pedersen_commit;

fn main() {
    let mut out: Vec<[u8;32]> = Vec::new();
    for i in 0u32..20 {
        let r = Scalar::from((i + 1) as u64);
        let c = pedersen_commit(10_000, r);
        out.push(c);
    }
    println!("// Generated genesis commitments for faucet (20 x 10_000)\n[");
    for c in out.iter() {
        print!("    [");
        for (j, b) in c.iter().enumerate() {
            if j > 0 { print!(", "); }
            print!("0x{:02x}", b);
        }
        println!("],");
    }
    println!("];");
}
