# Nulla Wallet & Faucet — Quick Usage Guide

This guide shows how to use the Nulla CLI wallet and the faucet end-to-end, plus common pitfalls and fixes.

## Prerequisites

- A running Nulla node.
  - No need to expose rpc ports
- IMPORTANT: Point wallet and faucet to the node RPC port.
  - Wallet: `--ws ws://HOST:WS_PORT` or `NULLA_WS=ws://HOST:WS_PORT`.
  - Faucet: `WS=ws://HOST:WS_PORT` environment variable.

## CLI locations

- Wallet binary: `./nulla-wallet`
- Faucet server: `./nulla-faucet` (HTTP service, default `http://127.0.0.1:3030`)

## Environment variables

- `NULLA_WS` or `WS`: WebSocket endpoint for the wallet (e.g., `ws://127.0.0.1:9944`).
- Faucet reads `WS` to reach the node. The wallet’s faucet subcommand uses an HTTP URL to call the faucet service.

## Wallet commands

Global:
- `--ws ws://HOST:PORT` overrides the node endpoint (also honors `NULLA_WS`/`WS`).

### 1) Initialize a wallet

```bash
./nulla-wallet init --name alice
```
- Creates `.nulla/wallets/alice/` with keys and stealth address.

### 2) Show address

```bash
./nulla-wallet address --name alice
```
- Prints the stealth address (hex). Use this as the recipient in transfers or faucet requests.

### 3) Request faucet funds

Run the faucet server (separate process):
```bash
# Make sure faucet points to the node WS
export WS=ws://127.0.0.1:<rpc-port>
./nulla-faucet
```
From the wallet, request tokens:
```bash
./nulla-wallet faucet --name alice --url http://127.0.0.1:3030
```
- The wallet POSTs to the faucet HTTP URL; the faucet submits a private mint tx to the node.
- Wallet saves a stub note locally; run a scan to derive blinding from on-chain hints.

### 4) Scan for incoming notes

```bash
./nulla-wallet scan --name alice --ws ws://127.0.0.1:9944
```
- Connects to the node, inspects recent blocks for `Proofs::ProofAccepted` events, decrypts hints, and imports notes.
- Diagnostics:
  - Prints counters: events, hints, tag mismatches, decrypt/memo failures.
  - If a faucet note already exists, scan updates its blinding (required to spend) and merkle_root.

### 5) Check balance (placeholder)

```bash
./nulla-wallet balance --name alice --ws ws://127.0.0.1:9944
```
- Shows a simple summary based on local notes (placeholder; doesn’t query public balances).

### 6) Transfer privately

```bash
# Get Bob’s address
./nulla-wallet init --name bob
BOB=$(./target/release/nulla-wallet address --name bob | tail -n1 | awk '{print $NF}')

# Send from Alice to Bob
./nulla-wallet transfer \
  --name alice \
  --to "$BOB" \
  --amount 200 \
  --ws ws://127.0.0.1:9944

# Bob scans to receive
./nulla-wallet scan --name bob --ws ws://127.0.0.1:9944
```
- The wallet creates a ZK spend proof and an aggregated range proof, submits the extrinsic, waits for on-chain processing, and stores a change note (if any).

### 7) Import from receipt (optional/off-chain delivery)

```bash
./nulla-wallet import --name bob --file /path/to/receipt.json
```
- Imports a note from a JSON file into `received_notes.json`.

## Faucet overview

- Start the faucet:
```bash
export WS=ws://127.0.0.1:9944   # Node WS
./nulla-faucet   # HTTP on 127.0.0.1:3030
```
- Wallet requests funds:
```bash
./nulla-wallet faucet --name alice --url http://127.0.0.1:3030
```
- Faucet will:
  - Submit a private mint to the node.
  - Return a JSON with tx info (optional) to the wallet.
  - The wallet then runs `scan` to decode the hint and complete the note (add blinding).

## Endpoints and networking

- Always pass the node WS to wallet (`--ws`) and set `WS` for the faucet.
- For users, run a public full node:
  - Same RAW chainspec as the authority.
  - `--pruning=archive` so scan can read historical state.
  - Peered to the authority (`--bootnodes`).
- Authority should run with GRANDPA and AURA keys inserted; otherwise finality stalls and transfers may fail.

## Troubleshooting

- Wallet says “Imported 0 notes” but saw events:
  - Expected if faucet already saved the note; run `scan` to update blinding so the note becomes spendable.

- ProofVerificationFailed during transfer:
  - Ensure you’re on the updated runtime (wallet submits proof + range proof + public inputs + hints).
  - Node must compute the Merkle root on-chain (runtime accepts `new_merkle_root = 0x00..00`).

- Scan sees events but fails to fetch storage at historical blocks:
  - Use a full node with `--pruning=archive` and point wallet to that WS.

- Wrong endpoint (using HTTP RPC port instead of WS):
  - Wallet requires WS like `ws://127.0.0.1:9944`. Faucet also uses WS via `WS` env.

- Mixed networks / checkpoints:
  - Use different wallet names per network to avoid mixing scan checkpoints (`.nulla/wallets/<name>`), or delete `scan_state.json` to reset.


