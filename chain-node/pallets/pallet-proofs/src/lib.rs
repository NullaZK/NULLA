#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeSet;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
};

/// Canonical public inputs structure (SCALE encoded when passed on-chain).
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct ProofPublicInputs {
    pub merkle_root: [u8; 32],
    /// New Merkle root after applying new_commitments (computed off-chain).
    /// This prepares the pallet for hidden values: the ZK proof must attest
    /// correct Merkle tree updates from `merkle_root` to `new_merkle_root`.
    pub new_merkle_root: [u8; 32],
    /// Public list of input commitments for balance proof (temporary until
    /// inclusion proofs are added); later this can be replaced by Merkle paths
    /// in the proof and omitted from public inputs.
    pub input_commitments: Vec<[u8; 32]>,
    // Ownership data removed from public inputs; authorization must be proved in-circuit.
    pub input_indices: Vec<u32>,
    pub input_paths: Vec<Vec<[u8; 32]>>, // optional for now; empty means skip path check
    pub nullifiers: Vec<[u8; 32]>,
    pub new_commitments: Vec<[u8; 32]>,
    /// Fee commitment used in balance proof (value hidden, same commitment scheme).
    pub fee_commitment: [u8; 32],
    pub fee_nullifier: [u8; 32],  // Proves fee payment without revealing payer
    pub tx_id: [u8; 16],
}

/// Optional per-output receiver discovery data emitted in events only.
/// Not used for verification – wallets validate against the output commitment.

/// Runtime trait the runtime must implement to provide verification.
pub trait ProofVerify {
    fn verify(proof: &[u8], public_inputs: &[u8]) -> bool;
    fn pedersen_check_u64(value: u64, blinding: [u8;32], commitment: [u8;32]) -> bool;
    /// Verify aggregated Bulletproofs range proof for (outputs..., fee)
    fn verify_range_proof(range_proof: &[u8], commitments: &[[u8;32]], public_inputs: &[u8], nbits: u32) -> bool;
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use alloc::vec::Vec;
    use frame_support::BoundedVec;
    use frame_support::pallet_prelude::ConstU32;
    use sp_core::ed25519;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Runtime must provide a verifier implementation.
        type ProofVerifier: ProofVerify;

        /// Maximum proof size in bytes.
        #[pallet::constant]
        type MaxProofSize: Get<u32>;

    /// Maximum size for the Bulletproofs range proof in bytes.
    #[pallet::constant]
    type MaxRangeProofSize: Get<u32>;

    /// Maximum number of outputs allowed per transaction (for range proof aggregation and spam control).
    #[pallet::constant]
    type MaxOutputs: Get<u32>;

        /// Genesis commitments for the faucet pool.
        /// These are pre-generated Pedersen commitments with known values but unknown blinding factors
        /// that will be distributed by the faucet service.
        #[pallet::constant]
        type GenesisCommitments: Get<&'static [[u8; 32]]>;
    }

    #[pallet::storage]
    #[pallet::getter(fn nullifier_used)]
    pub type NullifierUsed<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], bool, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn merkle_root)]
    pub type MerkleRoot<T: Config> = StorageValue<_, [u8;32], ValueQuery>;

    /// Current canonical Merkle root used to anchor new private transactions.
    #[pallet::storage]
    #[pallet::getter(fn current_root)]
    pub type CurrentRoot<T: Config> = StorageValue<_, [u8;32], ValueQuery>;

    /// Recent historical roots to tolerate anchor races (last N roots).
    #[pallet::storage]
    #[pallet::getter(fn recent_roots)]
    pub type RecentRoots<T: Config> = StorageValue<_, BoundedVec<[u8; 32], ConstU32<64>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn fee_nullifier_used)]
    pub type FeeNullifierUsed<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], bool, ValueQuery>;

    /// Faucet commitments available for distribution
    #[pallet::storage]
    #[pallet::getter(fn faucet_commitments)]
    pub type FaucetCommitments<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], bool, ValueQuery>;

    /// One-time switch to ensure genesis commitments are initialized even if a dev chain
    /// is started without picking up updated genesis. This lets us backfill on first block.
    #[pallet::storage]
    #[pallet::getter(fn genesis_initialized)]
    pub type GenesisInitialized<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Append-only list of leaf hashes for the commitment tree (dev depth, recompute root per tx)
    #[pallet::storage]
    #[pallet::getter(fn leaves)]
    pub type Leaves<T: Config> = StorageValue<_, BoundedVec<[u8;32], ConstU32<16384>>, ValueQuery>;

    /// Index of leaf count per finalized root to enable membership checks anchored at a past root.
    #[pallet::storage]
    #[pallet::getter(fn root_leaf_count)]
    pub type RootLeafCount<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], u32, ValueQuery>;

    /// Map output commitment -> leaf index when it was appended.
    #[pallet::storage]
    #[pallet::getter(fn commitment_index)]
    pub type CommitmentIndex<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], u32, OptionQuery>;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            // Initialize Merkle root to zeros
            MerkleRoot::<T>::put([0u8; 32]);
            CurrentRoot::<T>::put([0u8; 32]);
            RecentRoots::<T>::put(BoundedVec::default());
            Leaves::<T>::put(BoundedVec::default());
            RootLeafCount::<T>::insert([0u8; 32], 0u32);
            // Note: Faucet genesis commitments are not part of the Merkle tree; they are handled separately.
            
            // Add genesis commitments to faucet pool
            for commitment in T::GenesisCommitments::get() {
                FaucetCommitments::<T>::insert(commitment, true);
            }
            GenesisInitialized::<T>::put(true);
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            // If genesis commitments were not populated (e.g., due to running on an older dev DB),
            // populate them now once.
            if !GenesisInitialized::<T>::get() {
                for commitment in T::GenesisCommitments::get() {
                    // Only set if missing to avoid overwriting consumed flags on upgraded chains.
                    if !FaucetCommitments::<T>::contains_key(commitment) {
                        FaucetCommitments::<T>::insert(commitment, true);
                    }
                }
                GenesisInitialized::<T>::put(true);
            }
            Weight::zero()
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Proof accepted, with new Merkle root and the emitted output commitments
        ProofAccepted {
            /// Transaction identifier (opaque, used for receiver derivations/scanning)
            tx_id: [u8; 16],
            /// New canonical root after applying outputs
            new_merkle_root: [u8; 32],
            /// Output commitments (public commitments only)
            outputs: Vec<[u8; 32]>,
            /// Optional opaque hints blob for private discovery (bounded bytes)
            /// Suggested encoding: SCALE Vec<Vec<u8>>, where each element packs
            /// eph_pk(32) || tag(4) || memo_len(2 LE) || memo
            hints_blob: BoundedVec<u8, ConstU32<4096>>,
        },
        ProofRejected,
        FeeDeposited { commitment: [u8; 32] },
        /// Range proof verified successfully (on-chain)
        RangeProofVerified,
    }

    #[pallet::error]
    pub enum Error<T> {
        ProofVerificationFailed,
        NullifierAlreadyUsed,
        FeeNullifierAlreadyUsed,
        ProofTooLarge,
        RangeProofTooLarge,
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_proof { proof, range_proof, public_inputs, .. } => {
                    // Basic validation - detailed verification happens in the call
                    let max_size = T::MaxProofSize::get() as usize;
                    if proof.len() > max_size {
                        return InvalidTransaction::ExhaustsResources.into();
                    }
                    let max_rp = T::MaxRangeProofSize::get() as usize;
                    if range_proof.len() > max_rp {
                        return InvalidTransaction::ExhaustsResources.into();
                    }

                    // Decode and check nullifiers haven't been used
                    if let Ok(inputs) = ProofPublicInputs::decode(&mut &public_inputs[..]) {
                        // Anchor root must be either current or within recent window
                        let anchor = inputs.merkle_root;
                        let cur = CurrentRoot::<T>::get();
                        if anchor != cur {
                            let window = RecentRoots::<T>::get();
                            if !window.iter().any(|r| *r == anchor) {
                                return InvalidTransaction::Stale.into();
                            }
                        }
                        // Nullifiers basic shape checks
                        if inputs.nullifiers.len() != inputs.input_commitments.len() {
                            return InvalidTransaction::BadMandatory.into();
                        }
                        // Indices shape check only
                        let n = inputs.input_commitments.len();
                        if inputs.input_indices.len() != n { return InvalidTransaction::BadMandatory.into(); }
                        // Ensure all nullifiers are unique within the tx and distinct from fee nullifier
                        {
                            let mut seen: BTreeSet<[u8;32]> = BTreeSet::new();
                            for n in inputs.nullifiers.iter() {
                                if *n == inputs.fee_nullifier { return InvalidTransaction::BadMandatory.into(); }
                                if !seen.insert(*n) { return InvalidTransaction::BadMandatory.into(); }
                            }
                        }
                        // Check fee nullifier
                        if FeeNullifierUsed::<T>::get(inputs.fee_nullifier) {
                            return InvalidTransaction::Stale.into();
                        }
                        
                        // Check transaction nullifiers
                        for nullifier in inputs.nullifiers.iter() {
                            if NullifierUsed::<T>::get(nullifier) {
                                return InvalidTransaction::Stale.into();
                            }
                        }

                        ValidTransaction::with_tag_prefix("ProofSubmission")
                            .and_provides(inputs.tx_id)
                            .and_provides(inputs.fee_nullifier)
                            // Provide each nullifier to dedupe in mempool
                            .and_provides(inputs.nullifiers.clone())
                            .priority(100)
                            .longevity(64)
                            .propagate(true)
                            .build()
                    } else {
                        InvalidTransaction::Call.into()
                    }
                }
                _ => InvalidTransaction::Call.into(),
            }
        }
    }

    // Non-dispatchable helper methods for Merkle operations.
    impl<T: Config> Pallet<T> {
        /// blake2_256(left || right)
        fn hash2(left: [u8;32], right: [u8;32]) -> [u8;32] {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&left);
            data[32..].copy_from_slice(&right);
            sp_io::hashing::blake2_256(&data)
        }

        /// leaf hash from commitment (owner/auth data can be added later)
        fn leaf_hash(commitment: [u8;32]) -> [u8;32] {
            // For now, leaf = blake2_256(commitment || zeros)
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&commitment);
            // trailing zeros
            sp_io::hashing::blake2_256(&data)
        }

        /// Compute full binary Merkle root by padding leaves to next power-of-two with zero hash.
        fn compute_merkle_root(leaves: &[[u8;32]]) -> [u8;32] {
            if leaves.is_empty() { return [0u8;32]; }
            // Build vector of leaf nodes (already hashed as leaves)
            let mut level: alloc::vec::Vec<[u8;32]> = leaves.to_vec();
            // If not a power of two, pad with zero leaf
            let zero = [0u8;32];
            while level.len() & (level.len() - 1) != 0 { level.push(zero); }
            let mut cur = level;
            while cur.len() > 1 {
                let mut next = alloc::vec::Vec::with_capacity((cur.len()+1)/2);
                for pair in cur.chunks(2) {
                    let a = pair[0];
                    let b = if pair.len() == 2 { pair[1] } else { zero };
                    next.push(Self::hash2(a, b));
                }
                cur = next;
            }
            cur[0]
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a zero-knowledge proof transaction.
        /// 
        /// **This is an ANONYMOUS call - no signature required!**
        /// 
        /// Fee is paid via zero-knowledge proof of fee commitment ownership.
        /// The proof must demonstrate:
        /// 1. Ownership of input notes (via nullifiers)
        /// 2. Correct computation of output commitments
        /// 3. Ownership of a fee commitment (via fee_nullifier)
        /// 4. Conservation of value: inputs = outputs + fee
    pub fn submit_proof(origin: OriginFor<T>, proof: Vec<u8>, range_proof: BoundedVec<u8, <T as Config>::MaxRangeProofSize>, public_inputs: Vec<u8>, hints_blob: BoundedVec<u8, ConstU32<4096>>) -> DispatchResult {
            // Accept unsigned transactions for privacy
            ensure_none(origin)?;

            // size checks
            let max_size = T::MaxProofSize::get() as usize;
            ensure!(proof.len() <= max_size, Error::<T>::ProofTooLarge);
        ensure!(range_proof.len() <= T::MaxRangeProofSize::get() as usize, Error::<T>::RangeProofTooLarge);

            // Decode public inputs
            let inputs = ProofPublicInputs::decode(&mut &public_inputs[..])
                .map_err(|_| Error::<T>::ProofVerificationFailed)?;

            // Check fee nullifier hasn't been used
            let fee_used = FeeNullifierUsed::<T>::get(inputs.fee_nullifier);
            ensure!(!fee_used, Error::<T>::FeeNullifierAlreadyUsed);

            // Anchor root check against current/historical window
            let anchor = inputs.merkle_root;
            let current = CurrentRoot::<T>::get();
            if anchor != current {
                let window = RecentRoots::<T>::get();
                ensure!(window.iter().any(|r| *r == anchor), Error::<T>::ProofVerificationFailed);
            }

            // Verify range proof first: aggregated over new_commitments followed by fee commitment
            {
                let mut cmts: alloc::vec::Vec<[u8;32]> = inputs.new_commitments.clone();
                // Enforce MaxOutputs
                ensure!(cmts.len() as u32 <= T::MaxOutputs::get(), Error::<T>::ProofVerificationFailed);
                cmts.push(inputs.fee_commitment);
                let ok = T::ProofVerifier::verify_range_proof(&range_proof, &cmts, &public_inputs, 64);
                ensure!(ok, Error::<T>::ProofVerificationFailed);
                Self::deposit_event(Event::RangeProofVerified);
            }

            // Verify Schnorr balance proof using runtime-provided verifier (transcript bound inside)
            let ok = T::ProofVerifier::verify(&proof, &public_inputs);
            if !ok {
                Self::deposit_event(Event::ProofRejected);
                Err(Error::<T>::ProofVerificationFailed)?;
            }

            // Membership check against the anchor root.
            // If a Merkle path is provided, verify it reconstructs the anchor root using the provided index orientation.
            // Otherwise, ensure each input existed before or at the anchor by verifying its on-chain index < leaf_count(anchor).
            let anchor_count = RootLeafCount::<T>::get(anchor);
            let mut faucet_commitments_to_consume: Vec<[u8;32]> = Vec::new();
            for (i, c) in inputs.input_commitments.iter().enumerate() {
                // Allow spending of genesis faucet commitments once, tracked on-chain.
                if FaucetCommitments::<T>::contains_key(c) {
                    // If it was already consumed, reject.
                    let available = FaucetCommitments::<T>::get(c);
                    ensure!(available, Error::<T>::ProofVerificationFailed);
                    // Don't mark consumed yet - collect for later consumption after all validation passes.
                    faucet_commitments_to_consume.push(*c);
                    // Skip ownership checks for faucet genesis notes
                    continue;
                }
                // If path is provided, verify it; else fall back to index gating via on-chain index and anchor_count.
                if i < inputs.input_paths.len() && !inputs.input_paths[i].is_empty() && i < inputs.input_indices.len() {
                    let mut node = Self::leaf_hash(*c);
                    let mut idx = inputs.input_indices[i] as usize;
                    for sib in inputs.input_paths[i].iter() {
                        if (idx & 1) == 0 { // current is left child
                            node = Self::hash2(node, *sib);
                        } else { // current is right child
                            node = Self::hash2(*sib, node);
                        }
                        idx >>= 1;
                    }
                    ensure!(node == anchor, Error::<T>::ProofVerificationFailed);
                } else {
                    // Otherwise, require membership prior to anchor based on on-chain index.
                    let idx = match CommitmentIndex::<T>::get(c) {
                        Some(v) => v,
                        None => { return Err(Error::<T>::ProofVerificationFailed.into()); }
                    };
                    // Note: idx is zero-based, count is number of leaves at anchor.
                    ensure!((idx as u32) < anchor_count, Error::<T>::ProofVerificationFailed);
                }

                // Authorization must be enforced by the ZK proof; runtime only checks membership and nullifier uniqueness.
            }

            // check and mark nullifiers
            for n in inputs.nullifiers.iter() {
                let used = NullifierUsed::<T>::get(n);
                ensure!(!used, Error::<T>::NullifierAlreadyUsed);
            }
            for n in inputs.nullifiers.iter() {
                NullifierUsed::<T>::insert(n, true);
            }

            // Mark fee nullifier as used
            FeeNullifierUsed::<T>::insert(inputs.fee_nullifier, true);

            // Now that all validation has passed, consume faucet commitments
            // In development mode, allow infinite faucet by not permanently consuming commitments
            for _c in faucet_commitments_to_consume {
                // For infinite faucet: don't mark as consumed, just track usage in nullifiers
                // FaucetCommitments::<T>::insert(c, false);
                // Note: The nullifier mechanism already prevents double-spending within the same session
            }

            // Reject duplicate outputs within the tx and outputs that already exist on-chain
            {
                let mut seen: BTreeSet<[u8;32]> = BTreeSet::new();
                for c in inputs.new_commitments.iter() {
                    // No duplicates in the same transaction
                    ensure!(seen.insert(*c), Error::<T>::ProofVerificationFailed);
                    // Commitment must not already be present on-chain
                    ensure!(!CommitmentIndex::<T>::contains_key(c), Error::<T>::ProofVerificationFailed);
                }
            }

            // Limit outputs per transaction to mitigate spam and growth.
            ensure!(inputs.new_commitments.len() as u32 <= T::MaxOutputs::get(), Error::<T>::ProofVerificationFailed);

            // Append outputs to on-chain leaf set and recompute root.
            let mut leaves = Leaves::<T>::get();
            for c in inputs.new_commitments.iter() {
                let leaf = Self::leaf_hash(*c);
                // Record index for commitment prior to push (0-based)
                let idx = leaves.len() as u32;
                // Enforce capacity; reject tx if tree is full.
                ensure!(leaves.try_push(leaf).is_ok(), Error::<T>::ProofVerificationFailed);
                // Only record index after successful push to avoid desync.
                CommitmentIndex::<T>::insert(c, idx);
            }
            let computed_root = Self::compute_merkle_root(&leaves);
            Leaves::<T>::put(leaves);

            // Dev-friendly concurrency: allow a sentinel (all-zero) new_merkle_root to mean
            // "compute on-chain and accept", avoiding off-chain prediction races.
            // If a non-zero root is provided, enforce equality.
            if inputs.new_merkle_root != [0u8; 32] {
                ensure!(inputs.new_merkle_root == computed_root, Error::<T>::ProofVerificationFailed);
            }

            // Rotate roots: push previous current into recent window, set new current to computed_root.
            let prev = CurrentRoot::<T>::get();
            CurrentRoot::<T>::put(computed_root);
            // Keep legacy MerkleRoot updated for compatibility while clients migrate.
            MerkleRoot::<T>::put(computed_root);
            // Record leaf count for this root for future membership checks.
            let leaf_count = Leaves::<T>::get().len() as u32;
            RootLeafCount::<T>::insert(computed_root, leaf_count);
            let mut window = RecentRoots::<T>::get();
            // Maintain a window of up to 64 recent roots
            if window.len() >= 64 {
                // shift-left by one (drop oldest)
                let mut shifted: BoundedVec<[u8;32], ConstU32<64>> = BoundedVec::default();
                for i in 1..window.len() { let _ = shifted.try_push(window[i]); }
                window = shifted;
            }
            let _ = window.try_push(prev);
            RecentRoots::<T>::put(&window);

            // Emit event with optional receiver hints. Hints are opaque to the pallet.
            Self::deposit_event(Event::ProofAccepted {
                tx_id: inputs.tx_id,
                new_merkle_root: computed_root,
                outputs: inputs.new_commitments.clone(),
                hints_blob,
            });
            Ok(())
        }

    /// Deposit funds into the anonymous fee pool.
        /// 
        /// This creates a fee commitment that can later be spent using zero-knowledge proofs.
        /// The depositor's identity is revealed during deposit, but spending is anonymous.
        /// 
        /// Workflow:
        /// 1. User calls this with a commitment
        /// 2. Tokens are transferred to pallet account
        /// 3. Commitment is added to the tree
        /// 4. Later, user can spend via `submit_proof` without revealing identity
        pub fn deposit_fee(origin: OriginFor<T>, fee_commitment: [u8; 32]) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            
            // In production, you'd:
            // 1. Transfer tokens from `who` to pallet account
            // 2. Store fee_commitment in the commitment tree
            // 3. Emit event so depositor can track their fee notes
            
            // For now, just accept the commitment (simplified)
            // The fee commitment should be added to the main commitment tree
            // so it can be referenced in proofs
            
            Self::deposit_event(Event::FeeDeposited { commitment: fee_commitment });
            Ok(())
        }
    }
}
