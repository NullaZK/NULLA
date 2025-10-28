use wallet::{ProofPublicInputs, pedersen_commit, compute_new_merkle_root, make_proof_bytes_with_w};
use parity_scale_codec::Encode;
use hex::ToHex;
use curve25519_dalek_v4::scalar::Scalar;

fn main() {
    // Demo values
    let old_root = [0u8; 32];

    // Suppose we spend one note with secret S, produce nullifier deterministically
    let input_secret = [1u8; 32];
    let nullifier = sp_core::blake2_256(&[input_secret, [0u8;32]].concat());

    // Input and outputs with Pedersen commitments
    let r_in = Scalar::from(7u64);
    let input_commitment = pedersen_commit(100, r_in);
    let r_out1 = Scalar::from(2u64);
    let r_out2 = Scalar::from(3u64);
    let out1 = pedersen_commit(60, r_out1);
    let out2 = pedersen_commit(40, r_out2);
    let outputs = vec![out1, out2];

    // Fee nullifier derived from fee secret
    let fee_nullifier = sp_core::blake2_256(&[[9u8;32], [0u8;32]].concat());
    let r_fee = Scalar::from(5u64);
    let fee_commitment = pedersen_commit(0, r_fee);

    // Off-chain merkle root update (placeholder)
    let new_root = compute_new_merkle_root(old_root, &outputs);

    let public_inputs = ProofPublicInputs {
        merkle_root: old_root,
        new_merkle_root: new_root,
        input_commitments: vec![input_commitment],
        input_indices: vec![0],
        input_paths: vec![Vec::new()],
        nullifiers: vec![nullifier],
        new_commitments: outputs,
        fee_commitment,
        fee_nullifier,
        tx_id: [7u8; 16],
    };

    // Witness for H component: w = r_in - r_out1 - r_out2 - r_fee
    let w = r_in - r_out1 - r_out2 - r_fee;
    let proof = make_proof_bytes_with_w(&public_inputs, w);

    println!("public_inputs: {} bytes", public_inputs.encode().len());
    println!("proof: {}", proof.encode_hex::<String>());
    println!("new_merkle_root: {}", new_root.encode_hex::<String>());
}
