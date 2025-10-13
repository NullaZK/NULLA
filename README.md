# NULLA - Privacy-Focused Blockchain Runtime

**NULLA** is a privacy-focused Layer 1 blockchain built on Substrate, designed specifically for anonymous transactions. This runtime implements the Q1 phase of the NULLA roadmap, focusing on transaction privacy.

## 🔐 Privacy Features

### Core Privacy Components

1. **Private Balances (`pallet-private-balances`)**
   - Encrypted balance storage using Pedersen commitments
   - Only wallet owners can decrypt their balance
   - Homomorphic properties for balance verification

2. **Stealth Addresses (`pallet-stealth-addresses`)**
   - One-time addresses for each transaction
   - ECDH-based key derivation
   - View tags for efficient scanning

3. **ZK Transactions (`pallet-zk-transactions`)**
   - Zero-knowledge proof verification
   - Bulletproofs for range proofs
   - Balance conservation proofs

4. **Nullifier Set (`pallet-nullifier-set`)**
   - Global nullifier tracking to prevent double-spending
   - Efficient storage and pruning mechanisms
   - Automatic cleanup of old nullifiers

## 🏗️ Architecture

### Privacy Transaction Flow

```
Wallet  → ZK Proof Generation → Substrate Node → Verification → On-chain Storage
     ↓                    ↓                    ↓              ↓              ↓
 Encryption         Stealth Address      Nullifier Set   Commitment    Private Balance
```

### Key Components Removed

- **`pallet-sudo`**: Removed for production security
- **`pallet-balances`**: Replaced with private balance system
- **`pallet-template`**: Removed as no longer needed

### Key Components Modified

- **Transaction Payment**: Modified to work with private transactions
- **Runtime**: Updated with privacy pallets and new configurations

## 🔧 Technical Implementation

### Cryptographic Primitives

- **Curve25519**: Elliptic curve operations
- **Ristretto**: Prime-order group for Pedersen commitments
- **Bulletproofs**: Range proofs for transaction amounts
- **SHA3**: Hashing for derivations and commitments
- **ChaCha20-Poly1305**: Symmetric encryption for balance data

### Storage Architecture

- **Encrypted Notes**: Balance data encrypted per account
- **Stealth UTXOs**: Transaction outputs using stealth addresses
- **Nullifier Tracking**: Global set preventing double-spends
- **Commitment Tree**: Merkle tree for membership proofs

## 🚀 Usage


Your  wallet should:

1. **Generate Stealth Keys**: Create view/spend key pairs
2. **Create ZK Proofs**: Generate bulletproofs for transactions
3. **Submit Transactions**: Use the privacy pallets via RPC
4. **Scan for Outputs**: Use view tags for efficient scanning



## 🛠️ Configuration

### Runtime Parameters

- **Max Notes Per Account**: 1,000 encrypted notes
- **Max Stealth Outputs**: 16 outputs per transaction
- **Max Inputs/Outputs**: 16 each for ZK transactions
- **Max Proof Size**: 1MB per proof
- **Nullifier Retention**: ~30 days (201,600 blocks)

### Block Parameters

- **Block Time**: 6 seconds 
- **Block Weight**: Optimized for ZK proof verification
- **Consensus**: Aura + GRANDPA 




## 📊 Performance Characteristics

### Transaction Costs

- **Private Transfer**: ~100,000 weight units
- **ZK Proof Verification**: ~50,000 weight units per proof
- **Stealth Output Creation**: ~10,000 weight units per output
- **Nullifier Addition**: ~10,000 weight units

### Storage Requirements

- **Per Account**: ~1KB for stealth keys + notes
- **Per Transaction**: ~500 bytes for stealth outputs
- **Global State**: Nullifier set (~32 bytes per nullifier)

## 🔍 Privacy Guarantees

### What is Private

✅ **Transaction Amounts**: Hidden via Pedersen commitments  
✅ **Sender Identity**: Hidden via stealth addresses  
✅ **Receiver Identity**: Hidden via stealth addresses  
✅ **Transaction Graph**: Hidden via nullifier unlinkability  
✅ **Balance Information**: Encrypted and only viewable by owner  

### What is Public

❌ **Transaction Existence**: That a transaction occurred  
❌ **Timing**: When transactions were submitted  
❌ **Fee Information**: Transaction fees (for now)  
❌ **Proof Verification**: That proofs were verified successfully  


## 📝 License

Apache 2.0 License - See LICENSE file for details.

