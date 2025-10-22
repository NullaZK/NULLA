# NULLA – Privacy‑Native L1 (Testnet)

NULLA is a privacy‑native Layer 1 built on Substrate. Value is held as Pedersen commitments in a Merkle tree and moves via unsigned zero‑knowledge proofs submitted to the chain. Onboarding is private through a faucet that mints commitments directly to stealth addresses—no privacy pool.

Highlights
- Private notes (commitments), Merkle tree, and global nullifiers (double‑spend prevention)
- Unsigned proofs accepted via ValidateUnsigned (no account signatures in private flow)
- Stealth addresses for recipients; amounts and identities remain hidden
- Private faucet for instant onboarding (commitment → commitment), not public balances
- Token properties exposed as: symbol NULLA, 12 decimals, ss58 42
- PoS/fees compatibility kept (Balances/TransactionPayment present; privacy flow is separate)

Quick start
- Run node (dev): cargo run -p node -- --dev --rpc-external --rpc-cors all
- Run faucet: cargo run -p nulla-faucet
- Wallet (init → faucet → spend): use the wallet binaries in wallet/ (init, faucet request, scan, spend)

Repo map
- pallets/pallet-proofs: Merkle, nullifiers, unsigned submit_proof
- verifier/: ZK verifier used by the pallet
- faucet/: HTTP faucet that submits unsigned proofs
- wallet/: CLI for keys, faucet, scan, spend
- node/ + runtime/: Substrate node and runtime with the privacy pallet

# NULLA Proofs Pallet

Privacy‑native commitments and unsigned ZK transactions for NULLA.

- Commitments Merkle tree and global nullifier set (double‑spend prevention)
- Unsigned extrinsic: `submit_proof` (accepted via `ValidateUnsigned`)
- Emits new Merkle root and opaque outputs on success
- No privacy pool: onboarding via private faucet/output minting
- No trusted setup: Pedersen on Ristretto; homomorphic-friendly design

# NULLA Verifier

Verifier crate for NULLA’s private transactions.

- Ristretto Pedersen commitments
- Balance conservation and linkage to outputs
- Nullifier derivation to prevent double‑spends


Usage
- Library used by pallet-proofs to validate `submit_proof`.
- Accepts public inputs (merkle root, outputs, nullifier, fee commitment) and a proof blob.
- Returns Ok on valid proofs; errors otherwise.

# NULLA Wallet CLI

Command‑line wallet for the NULLA privacy‑native L1.

- Stealth keys (view/spend)
- Request private funds from the faucet (unsigned)
- Scan chain events for received outputs
- Spend notes via unsigned ZK proofs

Quick start
- Init: cargo run -p wallet --bin nulla-wallet -- init --name alice
- Request funds: cargo run -p wallet --bin nulla-wallet -- faucet --name alice --url http://localhost:3030
- Spend (unsigned): NAME=alice cargo run -p wallet --bin spend_faucet

Notes
- Uses commitments and nullifiers; no privacy pool.
- Unsigned extrinsics validated by pallet-proofs (ValidateUnsigned).
- You need to run the node and the faucet API on the same machine
