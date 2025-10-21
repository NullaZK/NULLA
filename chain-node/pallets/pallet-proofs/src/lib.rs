#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;
use alloc::vec::Vec;
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
    pub nullifiers: Vec<[u8; 32]>,
    pub new_commitments: Vec<[u8; 32]>,
    /// Fee commitment used in balance proof (value hidden, same commitment scheme).
    pub fee_commitment: [u8; 32],
    pub fee_nullifier: [u8; 32],  // Proves fee payment without revealing payer
    pub tx_id: [u8; 16],
}

/// Runtime trait the runtime must implement to provide verification.
pub trait ProofVerify {
    fn verify(proof: &[u8], public_inputs: &[u8]) -> bool;
    fn pedersen_check_u64(value: u64, blinding: [u8;32], commitment: [u8;32]) -> bool;
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use alloc::vec::Vec;

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

    #[pallet::storage]
    #[pallet::getter(fn fee_nullifier_used)]
    pub type FeeNullifierUsed<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], bool, ValueQuery>;

    /// Faucet commitments available for distribution
    #[pallet::storage]
    #[pallet::getter(fn faucet_commitments)]
    pub type FaucetCommitments<T: Config> = StorageMap<_, Blake2_128Concat, [u8;32], bool, ValueQuery>;

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
            
            // Add genesis commitments to faucet pool
            for commitment in T::GenesisCommitments::get() {
                FaucetCommitments::<T>::insert(commitment, true);
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Proof accepted, with new Merkle root and the emitted output commitments
        ProofAccepted { new_merkle_root: [u8; 32], outputs: Vec<[u8; 32]> },
        ProofRejected,
        FeeDeposited { commitment: [u8; 32] },
        /// Public -> Private shield completed
        Shielded { who: T::AccountId, amount: u64, commitment: [u8; 32], epk: [u8; 32], memo_hash: [u8; 32] },
    }

    #[pallet::error]
    pub enum Error<T> {
        ProofVerificationFailed,
        NullifierAlreadyUsed,
        FeeNullifierAlreadyUsed,
        ProofTooLarge,
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_proof { proof, public_inputs } => {
                    // Basic validation - detailed verification happens in the call
                    let max_size = T::MaxProofSize::get() as usize;
                    if proof.len() > max_size {
                        return InvalidTransaction::ExhaustsResources.into();
                    }

                    // Decode and check nullifiers haven't been used
                    if let Ok(inputs) = ProofPublicInputs::decode(&mut &public_inputs[..]) {
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
        pub fn submit_proof(origin: OriginFor<T>, proof: Vec<u8>, public_inputs: Vec<u8>) -> DispatchResult {
            // Accept unsigned transactions for privacy
            ensure_none(origin)?;

            // size checks
            let max_size = T::MaxProofSize::get() as usize;
            ensure!(proof.len() <= max_size, Error::<T>::ProofTooLarge);

            // Decode public inputs
            let inputs = ProofPublicInputs::decode(&mut &public_inputs[..])
                .map_err(|_| Error::<T>::ProofVerificationFailed)?;

            // Check fee nullifier hasn't been used
            let fee_used = FeeNullifierUsed::<T>::get(inputs.fee_nullifier);
            ensure!(!fee_used, Error::<T>::FeeNullifierAlreadyUsed);

            // Merkle root check
            let onchain_root = MerkleRoot::<T>::get();
            ensure!(onchain_root == inputs.merkle_root, Error::<T>::ProofVerificationFailed);

            // Verify proof using runtime-provided verifier
            let ok = T::ProofVerifier::verify(&proof, &public_inputs);
            if !ok {
                Self::deposit_event(Event::ProofRejected);
                Err(Error::<T>::ProofVerificationFailed)?;
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

            // Update Merkle root to the value computed off-chain and
            // attested by the ZK proof. This enables hidden values since
            // commitments and tree transitions are verified inside the proof.
            MerkleRoot::<T>::put(inputs.new_merkle_root);

            Self::deposit_event(Event::ProofAccepted {
                new_merkle_root: inputs.new_merkle_root,
                outputs: inputs.new_commitments.clone(),
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

        /// Move public balance into a private note commitment.
        /// For demo simplicity, we take amount as u64 and verify the Pedersen opening.
        #[pallet::weight(10_000)]
        pub fn shield(
            origin: OriginFor<T>,
            amount: u64,
            blinding: [u8; 32],
            commitment: [u8; 32],
            epk: [u8; 32],
            memo_hash: [u8; 32],
            new_merkle_root: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // In a production system, transfer `amount` from `who` to a pallet account using a Currency.
            // For this demo, we skip the actual transfer to avoid bringing in Currency dependencies.

            // Verify Pedersen opening for the deposited amount
            let ok = T::ProofVerifier::pedersen_check_u64(amount, blinding, commitment);
            ensure!(ok, Error::<T>::ProofVerificationFailed);

            // Update the Merkle root to the provided value. In production, append on-chain.
            MerkleRoot::<T>::put(new_merkle_root);

            Self::deposit_event(Event::Shielded { who, amount, commitment, epk, memo_hash });
            Ok(())
        }
    }
}
