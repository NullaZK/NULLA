# NULLA Genesis Testnet — Community First Release (Node‑Only Package)

Purpose
- Kickstart the community, let people connect nodes, and start observing real network behavior.
- Deliver private transfers fundamentals today while we continue shipping upgrades toward strong privacy safely and iteratively.

What’s in this release package
- Node only:
  - Validator/full node binary and chain spec.
  - Sample configs and run scripts.
  - Official faucet and a user‑friendly wallet integration will follow shortly after enough nodes are connected.

What NULLA-Genesis delivers (privacy features you have today)
- Anonymous submission:
  - Private transfers are submitted as unsigned extrinsics. No on‑chain account/address is linked to the transfer.
- Hidden amounts with commitments:
  - Amounts are encoded as Pedersen commitments over Ristretto: C = v·G + r·H. Values are never revealed on‑chain.
- Receiver privacy with opaque, padded hints:
  - Events carry an encrypted hints blob for receiver discovery. Wallets scan and decrypt locally.
- Double‑spend protection:
  - Nullifiers enforce one‑time spend. Domain‑separated derivation prevents cross‑context correlation.


What observers can see
- Commitments (outputs), nullifiers, the moving Merkle root, and opaque hints. Identities and amounts remain private.

Step‑by‑step: how to participate now (node‑only)
1) Download the node

2) Get the chain spec
- Use the provided mychain.no-bootnodes.raw.json (in the release package).

3) Connect as a participant
- Launch a full node and point it at the published bootnode.
- Example: ./target/release/<node-binary> --chain mychain.no-bootnodes.raw.json --bootnodes "<multiaddr>" --rpc-methods=Safe --unsafe-rpc-external=false

4) Observe and validate
- Watch block production, finality, peers, mempool behavior, and resource usage.

What comes next (short horizon)
- Public faucet (official)
  - Once a healthy set of community nodes is connected and stable, we will open an official, rate‑limited faucet for users who cannot run a node.
  - This faucet will spend from a controlled pool and follow privacy‑aware operational guidelines.
- User‑friendly wallet integration (official)
  - We will release an endorsed wallet integration to make receiving/spending more accessible for non‑operators.
  - It will default to encrypted, fixed‑size hints and privacy‑safe settings.

Why start node‑only
- Build a resilient network first: validate peering, consensus, weights, and mempool under real conditions.
- Reduce off‑chain linkage risk during the earliest days by avoiding premature public services that can log/request metadata.
- Give engineers and operators a clean baseline for performance and stability metrics.

Community focus and continuous updates
- This testnet will be continuously updated to reach strong privacy in a safe way:
  - Iterative upgrades that enhance unlinkability while preserving stability.
  - Clear changelogs and migration notes.
- Goals for the next milestones:
  - Circuit‑verified membership proofs inside the zero‑knowledge proof, keeping inputs out of public inputs.
  - Maintained nullifier model and uniform hints to minimize metadata leakage.
  - Benchmark‑guided weights and improved tooling.

Support and feedback
- Report issues and share metrics/observations via the repository issue tracker.
- We will iterate quickly based on real‑world feedback to improve safety, performance, and privacy.

