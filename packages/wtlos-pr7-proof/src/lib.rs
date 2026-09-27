//! Opt-in, offline-only WTLOS proof adapter for the pinned PR7 circuit.
//!
//! The existing wallet history APIs still use the embedded 1.4.0 circuit. This
//! crate uses a separate PR7 type universe, so callers must construct a PR7
//! witness explicitly. No live wallet route or relayer submission uses it.

pub const SOURCE_TREE: &str = "7a22196e1d4a791b452a6140bdfa915298f3f1da";

pub mod domain;

use domain::{build_memo, TransactionKind};
use libzeropool_pr7::fawkes_crypto::engines::bn256::{Fr, Fs};
use libzeropool_pr7::{
    circuit::tx::c_transfer,
    constants,
    fawkes_crypto::{
        backend::bellman_groth16::{
            engines::Bn256,
            prover::{prove, Proof},
            Parameters,
        },
        ff_uint::{Num, NumRepr, Uint},
        native::ecc::EdwardsPoint,
    },
    native::{
        cipher,
        key::{derive_key_a, derive_key_eta},
        params::PoolParams,
        tx::{
            make_delta, out_commitment_hash, parse_delta, tx_hash, tx_sign, tx_verify, TransferPub,
            TransferSec,
        },
    },
    POOL_PARAMS,
};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

pub struct DepositWitness {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub signing_key: Num<Fs>,
    pub pool_id: u32,
    /// Deposit amount in pool units (one unit = 10^9 WTLOS base units).
    pub amount: u64,
    /// Relayer fee in the same pool units, encoded in the memo's first 8 bytes.
    pub fee: u64,
    pub proxy: [u8; 20],
}

pub struct PrivateTransferWitness {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub signing_key: Num<Fs>,
    pub pool_id: u32,
    pub fee: u64,
    pub proxy: [u8; 20],
}

pub struct WithdrawalWitness {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub signing_key: Num<Fs>,
    pub pool_id: u32,
    /// Total amount removed from the private balance, in pool units.
    pub amount: u64,
    /// Fee retained by the pool operator; the recipient receives amount - fee.
    pub fee: u64,
    pub recipient: [u8; 20],
    pub proxy: [u8; 20],
}

pub struct FinalizedTransaction {
    pub public: TransferPub<Fr>,
    pub memo: Vec<u8>,
    secret: TransferSec<Fr>,
}

pub type FinalizedDeposit = FinalizedTransaction;

pub struct TransactionProof {
    pub public: TransferPub<Fr>,
    pub memo: Vec<u8>,
    pub public_inputs: Vec<Num<Fr>>,
    pub proof: Proof<Bn256>,
}

pub type DepositProof = TransactionProof;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    InvalidPoolId,
    InvalidDepositAmount,
    InvalidWithdrawalAmount,
    UnfundedInput,
    WrongRoot,
    WrongDelta,
    FundedOutputNote,
    InvalidOutputNoteRecipient,
    OutputNoteGap,
    WrongOutputCommitment,
    WrongSigningKey,
    InvalidSignature,
    RandomnessUnavailable,
    Domain(domain::DomainError),
}

/// Finalize exact calldata memo before computing the PR7 signing message.
/// `public` and `secret` must already be source-matched PR7 witness values.
pub fn finalize_deposit(witness: DepositWitness) -> Result<FinalizedDeposit, AdapterError> {
    if witness.pool_id == 0 || witness.pool_id >= (1 << constants::POOLID_SIZE_BITS) {
        return Err(AdapterError::InvalidPoolId);
    }
    if witness.amount <= witness.fee || witness.amount - witness.fee > i64::MAX as u64 {
        return Err(AdapterError::InvalidDepositAmount);
    }

    let pool_id = Num::<Fr>::from(witness.pool_id);
    let (_, _, index, parsed_pool_id) = parse_delta(witness.public.delta);
    if parsed_pool_id != pool_id
        || witness.public.delta
            != make_delta::<Fr>(
                Num::from(witness.amount - witness.fee),
                Num::ZERO,
                index,
                pool_id,
            )
    {
        return Err(AdapterError::WrongDelta);
    }

    if witness.secret.tx.output.1.iter().any(|note| {
        note.d.to_num() != Num::ZERO
            || note.p_d != Num::ZERO
            || note.b.to_num() != Num::ZERO
            || note.t.to_num() != Num::ZERO
    }) {
        return Err(AdapterError::FundedOutputNote);
    }

    finalize_signed_transaction(
        witness.public,
        witness.secret,
        witness.signing_key,
        witness.pool_id,
        witness.proxy,
        TransactionKind::Deposit,
        &witness.fee.to_be_bytes(),
    )
}

#[cfg(test)]
#[path = "funded_flow_tests.rs"]
mod funded_flow_tests;

/// Finalize a funded account spend with no public token movement. The PR7
/// relation checks balances, note ownership, account membership, and paths.
pub fn finalize_private_transfer(
    witness: PrivateTransferWitness,
) -> Result<FinalizedTransaction, AdapterError> {
    if witness.fee > i64::MAX as u64 {
        return Err(AdapterError::WrongDelta);
    }
    let (_, _, index, pool) = parse_delta(witness.public.delta);
    if index == Num::ZERO
        || pool != Num::from(witness.pool_id)
        || witness.public.delta
            != make_delta::<Fr>(
                -Num::from(witness.fee),
                Num::ZERO,
                index,
                Num::from(witness.pool_id),
            )
    {
        return Err(AdapterError::WrongDelta);
    }
    if witness.public.root == Num::ZERO {
        return Err(AdapterError::WrongRoot);
    }
    if !has_funded_input(&witness.secret) {
        return Err(AdapterError::UnfundedInput);
    }
    finalize_signed_transaction(
        witness.public,
        witness.secret,
        witness.signing_key,
        witness.pool_id,
        witness.proxy,
        TransactionKind::Transfer,
        &witness.fee.to_be_bytes(),
    )
}

/// Finalize a WTLOS withdrawal. The native conversion field stays zero and
/// the recipient address occupies the original V1 fixed-field offset.
pub fn finalize_withdrawal(
    witness: WithdrawalWitness,
) -> Result<FinalizedTransaction, AdapterError> {
    if witness.amount <= witness.fee || witness.amount > i64::MAX as u64 {
        return Err(AdapterError::InvalidWithdrawalAmount);
    }
    let (_, _, index, pool) = parse_delta(witness.public.delta);
    if index == Num::ZERO
        || pool != Num::from(witness.pool_id)
        || witness.public.delta
            != make_delta::<Fr>(
                -Num::from(witness.amount),
                Num::ZERO,
                index,
                Num::from(witness.pool_id),
            )
    {
        return Err(AdapterError::WrongDelta);
    }
    if witness.public.root == Num::ZERO {
        return Err(AdapterError::WrongRoot);
    }
    if !has_funded_input(&witness.secret) {
        return Err(AdapterError::UnfundedInput);
    }
    let mut fixed = [0u8; 36];
    fixed[..8].copy_from_slice(&witness.fee.to_be_bytes());
    fixed[16..].copy_from_slice(&witness.recipient);
    finalize_signed_transaction(
        witness.public,
        witness.secret,
        witness.signing_key,
        witness.pool_id,
        witness.proxy,
        TransactionKind::Withdraw,
        &fixed,
    )
}

fn has_funded_input(secret: &TransferSec<Fr>) -> bool {
    secret.tx.input.0.b.to_num() != Num::ZERO
        || secret
            .tx
            .input
            .1
            .iter()
            .any(|note| note.b.to_num() != Num::ZERO)
}

fn finalize_signed_transaction(
    mut public: TransferPub<Fr>,
    mut secret: TransferSec<Fr>,
    signing_key: Num<Fs>,
    pool_id: u32,
    proxy: [u8; 20],
    kind: TransactionKind,
    fixed_fields: &[u8],
) -> Result<FinalizedTransaction, AdapterError> {
    if pool_id == 0 || pool_id >= (1 << constants::POOLID_SIZE_BITS) {
        return Err(AdapterError::InvalidPoolId);
    }
    let params = &*POOL_PARAMS;
    let a = derive_key_a(signing_key, params);
    if a.x == Num::ZERO || a.x != secret.eddsa_a {
        return Err(AdapterError::WrongSigningKey);
    }
    let eta = derive_key_eta(a.x, params);
    if eta.to_other_reduced() == Num::<Fs>::ZERO {
        return Err(AdapterError::WrongSigningKey);
    }

    let out_account = secret.tx.output.0;
    let mut encryption_entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *encryption_entropy)
        .map_err(|_| AdapterError::RandomnessUnavailable)?;
    let mut note_outputs = Vec::new();
    let mut saw_empty_note = false;
    for note in secret.tx.output.1.iter() {
        let is_empty = note.d.to_num() == Num::ZERO
            && note.p_d == Num::ZERO
            && note.b.to_num() == Num::ZERO
            && note.t.to_num() == Num::ZERO;
        if is_empty {
            saw_empty_note = true;
        } else {
            if saw_empty_note {
                return Err(AdapterError::OutputNoteGap);
            }
            note_outputs.push(*note);
        }
    }
    if note_outputs.iter().any(|note| {
        note.p_d == Num::ZERO
            || EdwardsPoint::subgroup_decompress(note.p_d, params.jubjub()).is_none()
    }) {
        return Err(AdapterError::InvalidOutputNoteRecipient);
    }
    let raw_ciphertext = cipher::encrypt(
        &*encryption_entropy,
        eta,
        out_account,
        &note_outputs,
        params,
    );
    let memo =
        build_memo(kind, fixed_fields, &raw_ciphertext, &proxy).map_err(AdapterError::Domain)?;
    let memo_hash = Keccak256::digest(&memo);
    let memo_field = Num::<Fr>::from_uint_reduced(NumRepr(Uint::from_big_endian(&memo_hash)));
    public.memo = memo_field;

    let in_account_hash = secret.tx.input.0.hash(params);
    let mut input_hashes = Vec::with_capacity(constants::IN + 1);
    input_hashes.push(in_account_hash);
    input_hashes.extend(secret.tx.input.1.iter().map(|note| note.hash(params)));

    let mut output_hashes = Vec::with_capacity(constants::OUT + 1);
    output_hashes.push(out_account.hash(params));
    output_hashes.extend(secret.tx.output.1.iter().map(|note| note.hash(params)));
    let out_commit = out_commitment_hash(&output_hashes, params);
    if out_commit != public.out_commit {
        return Err(AdapterError::WrongOutputCommitment);
    }

    let signing_message = tx_hash(
        &input_hashes,
        out_commit,
        memo_field,
        Num::from(pool_id),
        params,
    );
    let (s, r) = tx_sign(signing_key, signing_message, params);
    if !tx_verify(s, r, a.x, signing_message, params) {
        return Err(AdapterError::InvalidSignature);
    }
    secret.eddsa_s = s.to_other().expect("subgroup scalar fits SNARK field");
    secret.eddsa_r = r;

    Ok(FinalizedTransaction {
        public,
        memo,
        secret,
    })
}

/// This draft does not authenticate the proving-key identity. Keep this entry
/// point offline until a qualified-key loader and full client route exist.
pub fn prove_deposit_with_unchecked_key(
    parameters: &Parameters<Bn256>,
    witness: DepositWitness,
) -> Result<DepositProof, AdapterError> {
    let finalized = finalize_deposit(witness)?;
    let (public_inputs, proof) = prove(
        parameters,
        &finalized.public,
        &finalized.secret,
        |public, secret| c_transfer(&public, &secret, &*POOL_PARAMS),
    );
    Ok(TransactionProof {
        public: finalized.public,
        memo: finalized.memo,
        public_inputs,
        proof,
    })
}

/// Unsafe key entry point for offline transfer/withdrawal rehearsal only.
pub fn prove_finalized_with_unchecked_key(
    parameters: &Parameters<Bn256>,
    finalized: FinalizedTransaction,
) -> TransactionProof {
    let (public_inputs, proof) = prove(
        parameters,
        &finalized.public,
        &finalized.secret,
        |public, secret| c_transfer(&public, &secret, &*POOL_PARAMS),
    );
    TransactionProof {
        public: finalized.public,
        memo: finalized.memo,
        public_inputs,
        proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libzeropool_pr7::{
        fawkes_crypto::{core::sizedvec::SizedVec, native::poseidon::MerkleProof},
        native::{
            account::Account, boundednum::BoundedNum, key::derive_key_p_d, note::Note, tx::Tx,
        },
    };

    const POOL_ID: u32 = 0x10203;
    const PROXY: [u8; 20] = [0x42; 20];

    fn zero_note() -> Note<Fr> {
        Note {
            d: BoundedNum::ZERO,
            p_d: Num::ZERO,
            b: BoundedNum::ZERO,
            t: BoundedNum::ZERO,
        }
    }

    fn zero_proof() -> MerkleProof<Fr, { constants::HEIGHT }> {
        MerkleProof {
            sibling: (0..constants::HEIGHT).map(|_| Num::ZERO).collect(),
            path: (0..constants::HEIGHT).map(|_| false).collect(),
        }
    }

    fn witness_for(
        pool_id: u32,
        proxy: [u8; 20],
        root: Num<Fr>,
        balance: u64,
        fee: u64,
        index: u64,
    ) -> DepositWitness {
        let params = &*POOL_PARAMS;
        let signing_key = Num::<Fs>::from(23u64);
        let a = derive_key_a(signing_key, params);
        let eta = derive_key_eta(a.x, params);
        let input_d = BoundedNum::new(Num::<Fr>::from(pool_id));
        let input_p_d = derive_key_p_d(input_d.to_num(), eta, params).x;
        let input_account = Account {
            d: input_d,
            p_d: input_p_d,
            i: BoundedNum::ZERO,
            b: BoundedNum::ZERO,
            e: BoundedNum::ZERO,
        };
        let output_d = BoundedNum::new(Num::<Fr>::from(17u64));
        let output_account = Account {
            d: output_d,
            p_d: derive_key_p_d(output_d.to_num(), eta, params).x,
            i: BoundedNum::new(Num::from(index)),
            b: BoundedNum::new(Num::from(balance)),
            ..input_account
        };
        let input_notes: SizedVec<_, { constants::IN }> = (0..constants::IN)
            .map(|i| {
                let d = BoundedNum::new(Num::<Fr>::from(31u64 + i as u64));
                Note {
                    d,
                    p_d: derive_key_p_d(d.to_num(), eta, params).x,
                    b: BoundedNum::ZERO,
                    t: BoundedNum::ZERO,
                }
            })
            .collect();
        let output_notes: SizedVec<_, { constants::OUT }> =
            (0..constants::OUT).map(|_| zero_note()).collect();
        let mut output_hashes = vec![output_account.hash(params)];
        output_hashes.extend(output_notes.iter().map(|note| note.hash(params)));
        let out_commit = out_commitment_hash(&output_hashes, params);
        let encoded_pool_id = Num::from(pool_id);
        DepositWitness {
            public: TransferPub {
                root,
                nullifier: libzeropool_pr7::native::tx::nullifier(
                    input_account.hash(params),
                    eta,
                    Num::ZERO,
                    params,
                ),
                out_commit,
                delta: make_delta(
                    Num::from(balance),
                    Num::ZERO,
                    Num::from(index),
                    encoded_pool_id,
                ),
                memo: Num::ZERO,
            },
            secret: TransferSec {
                tx: Tx {
                    input: (input_account, input_notes),
                    output: (output_account, output_notes),
                },
                in_proof: (
                    zero_proof(),
                    (0..constants::IN).map(|_| zero_proof()).collect(),
                ),
                eddsa_s: Num::ZERO,
                eddsa_r: Num::ZERO,
                eddsa_a: a.x,
            },
            signing_key,
            pool_id,
            amount: balance + fee,
            fee,
            proxy,
        }
    }

    fn witness() -> DepositWitness {
        witness_for(POOL_ID, PROXY, Num::ZERO, 5, 7, 128)
    }

    #[test]
    fn memo_pool_and_proxy_are_signed_together() {
        let finalized = finalize_deposit(witness()).unwrap();
        assert_eq!(&finalized.memo[..8], &7u64.to_be_bytes());
        assert_eq!(&finalized.memo[8..12], &[1, 0, 0, 0]);
        assert_eq!(&finalized.memo[12..16], b"TPD1");
        assert_eq!(&finalized.memo[16..36], &PROXY);

        let actual_hash = Keccak256::digest(&finalized.memo);
        let expected_memo =
            Num::<Fr>::from_uint_reduced(NumRepr(Uint::from_big_endian(&actual_hash)));
        assert_eq!(finalized.public.memo, expected_memo);

        let params = &*POOL_PARAMS;
        let mut input_hashes = vec![finalized.secret.tx.input.0.hash(params)];
        input_hashes.extend(
            finalized
                .secret
                .tx
                .input
                .1
                .iter()
                .map(|note| note.hash(params)),
        );
        let a = finalized.secret.eddsa_a;
        let s = finalized.secret.eddsa_s.to_other().unwrap();
        let r = finalized.secret.eddsa_r;
        let signed = tx_hash(
            &input_hashes,
            finalized.public.out_commit,
            finalized.public.memo,
            Num::from(POOL_ID),
            params,
        );
        assert!(tx_verify(s, r, a, signed, params));

        let changed_memo = tx_hash(
            &input_hashes,
            finalized.public.out_commit,
            finalized.public.memo + Num::ONE,
            Num::from(POOL_ID),
            params,
        );
        assert!(!tx_verify(s, r, a, changed_memo, params));

        let changed_pool = tx_hash(
            &input_hashes,
            finalized.public.out_commit,
            finalized.public.memo,
            Num::from(POOL_ID + 1),
            params,
        );
        assert!(!tx_verify(s, r, a, changed_pool, params));
    }

    #[test]
    fn inconsistent_deposit_witness_is_rejected_before_proving() {
        let mut value = witness();
        value.public.delta += Num::ONE;
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::WrongDelta)
        ));

        let mut value = witness();
        value.public.out_commit += Num::ONE;
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::WrongOutputCommitment)
        ));

        let mut value = witness();
        value.secret.tx.output.1[0].b = BoundedNum::new(Num::ONE);
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::FundedOutputNote)
        ));

        let mut value = witness();
        value.pool_id += 1;
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::WrongDelta)
        ));

        let mut value = witness();
        value.signing_key = Num::from(2u64);
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::WrongSigningKey)
        ));

        let mut value = witness();
        value.pool_id = 0;
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::InvalidPoolId)
        ));

        let mut value = witness();
        value.amount = value.fee;
        assert!(matches!(
            finalize_deposit(value),
            Err(AdapterError::InvalidDepositAmount)
        ));
    }

    #[test]
    fn private_and_withdrawal_adapters_reject_wrong_delta_and_unfunded_account() {
        let deposit = witness();
        let mut value = PrivateTransferWitness {
            public: deposit.public,
            secret: deposit.secret,
            signing_key: deposit.signing_key,
            pool_id: deposit.pool_id,
            fee: 0,
            proxy: deposit.proxy,
        };
        assert!(matches!(
            finalize_private_transfer(PrivateTransferWitness {
                public: value.public.clone(),
                secret: value.secret.clone(),
                ..value
            }),
            Err(AdapterError::WrongDelta)
        ));
        value.public.delta =
            make_delta(Num::ZERO, Num::ZERO, Num::from(128u64), Num::from(POOL_ID));
        assert!(matches!(
            finalize_private_transfer(PrivateTransferWitness {
                public: value.public.clone(),
                secret: value.secret.clone(),
                ..value
            }),
            Err(AdapterError::WrongRoot)
        ));
        value.public.root = Num::ONE;
        assert!(matches!(
            finalize_private_transfer(PrivateTransferWitness {
                public: value.public.clone(),
                secret: value.secret.clone(),
                ..value
            }),
            Err(AdapterError::UnfundedInput)
        ));
        value.fee = 1;
        assert!(matches!(
            finalize_private_transfer(value),
            Err(AdapterError::WrongDelta)
        ));

        let deposit = witness();
        let mut withdrawal = WithdrawalWitness {
            public: deposit.public,
            secret: deposit.secret,
            signing_key: deposit.signing_key,
            pool_id: deposit.pool_id,
            amount: 5,
            fee: 0,
            recipient: [0x11; 20],
            proxy: deposit.proxy,
        };
        assert!(matches!(
            finalize_withdrawal(WithdrawalWitness {
                public: withdrawal.public.clone(),
                secret: withdrawal.secret.clone(),
                ..withdrawal
            }),
            Err(AdapterError::WrongDelta)
        ));
        withdrawal.public.delta = make_delta(
            -Num::from(5u64),
            Num::ZERO,
            Num::from(128u64),
            Num::from(POOL_ID),
        );
        assert!(matches!(
            finalize_withdrawal(WithdrawalWitness {
                public: withdrawal.public.clone(),
                secret: withdrawal.secret.clone(),
                ..withdrawal
            }),
            Err(AdapterError::WrongRoot)
        ));
        withdrawal.public.root = Num::ONE;
        assert!(matches!(
            finalize_withdrawal(WithdrawalWitness {
                public: withdrawal.public.clone(),
                secret: withdrawal.secret.clone(),
                ..withdrawal
            }),
            Err(AdapterError::UnfundedInput)
        ));
        withdrawal.fee = withdrawal.amount;
        assert!(matches!(
            finalize_withdrawal(withdrawal),
            Err(AdapterError::InvalidWithdrawalAmount)
        ));

        let deposit = witness();
        let mut private = PrivateTransferWitness {
            public: deposit.public,
            secret: deposit.secret,
            signing_key: deposit.signing_key,
            pool_id: deposit.pool_id,
            fee: 0,
            proxy: deposit.proxy,
        };
        private.public.root = Num::ONE;
        private.public.delta =
            make_delta(Num::ZERO, Num::ZERO, Num::from(128u64), Num::from(POOL_ID));
        private.secret.tx.input.0.b = BoundedNum::new(Num::from(5u64));
        private.secret.tx.output.1[1].b = BoundedNum::new(Num::ONE);
        assert!(matches!(
            finalize_private_transfer(PrivateTransferWitness {
                public: private.public.clone(),
                secret: private.secret.clone(),
                ..private
            }),
            Err(AdapterError::OutputNoteGap)
        ));
        private.secret.tx.output.1[1] = zero_note();
        private.secret.tx.output.1[0].b = BoundedNum::new(Num::ONE);
        assert!(matches!(
            finalize_private_transfer(private),
            Err(AdapterError::InvalidOutputNoteRecipient)
        ));
    }

    #[test]
    fn finalized_initial_deposit_satisfies_exact_pr7_transfer_circuit() {
        use libzeropool_pr7::{
            circuit::tx::{CTransferPub, CTransferSec},
            fawkes_crypto::{circuit::cs::DebugCS, core::signal::Signal},
        };

        let finalized = finalize_deposit(witness()).unwrap();
        let cs = DebugCS::rc_new();
        let public = CTransferPub::alloc(&cs, Some(&finalized.public));
        let secret = CTransferSec::alloc(&cs, Some(&finalized.secret));
        c_transfer(&public, &secret, &*POOL_PARAMS);
    }

    /// Diagnostic only: zero-contribution Stage 0 has no ceremony security.
    /// The environment paths must point at the sealed current PR7 fixture.
    #[test]
    #[ignore = "explicit opt-in unsafe Stage 0 proof; never use for production"]
    fn unsafe_current_stagezero_deposit_proof() {
        use fawkes_crypto_phase2::parameters::MPCParameters;
        use libzeropool_pr7::{
            circuit::{
                tree::{tree_update, CTreePub, CTreeSec},
                tx::{CTransferPub, CTransferSec},
            },
            fawkes_crypto::{
                backend::bellman_groth16::{verifier::verify, Parameters},
                circuit::cs::BuildCS,
                core::signal::Signal,
                native::poseidon::{poseidon, poseidon_merkle_proof_root},
                BorshSerialize,
            },
            native::{
                params::PoolParams,
                tree::{TreePub, TreeSec},
            },
        };
        use sha2::{Digest as _, Sha256};
        use std::io::{Read, Write};

        let stage_path =
            std::env::var("UNSAFE_PR7_STAGE0_TRANSFER").expect("Stage 0 path required");
        let vk_path =
            std::env::var("UNSAFE_PR7_STAGE0_TRANSFER_VK").expect("sealed VK path required");
        let tree_stage_path =
            std::env::var("UNSAFE_PR7_STAGE0_TREE").expect("Stage 0 tree path required");
        let tree_vk_path =
            std::env::var("UNSAFE_PR7_STAGE0_TREE_VK").expect("sealed tree VK path required");
        let out_path =
            std::env::var("UNSAFE_PR7_PROOF_OUT").expect("new proof output path required");

        let mut stage = std::fs::File::open(&stage_path).unwrap();
        let mut hasher = Sha256::new();
        std::io::copy(&mut stage, &mut hasher).unwrap();
        assert_eq!(
            hex::encode(hasher.finalize()),
            "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30",
            "Stage 0 transcript differs from sealed current-source fixture"
        );
        let mut stage = std::fs::File::open(&stage_path).unwrap();
        let mpc = MPCParameters::read(&mut stage, true, true).unwrap();
        let mut trailing = [0u8; 1];
        assert_eq!(
            stage.read(&mut trailing).unwrap(),
            0,
            "trailing Stage 0 bytes"
        );

        // Recreate the same Fawkes gate compression and constant tracker as
        // PR7's ceremony finalizer, without writing an unsafe proving key.
        let cs = BuildCS::<Fr>::rc_new();
        let public = CTransferPub::alloc(&cs, None);
        public.inputize();
        let secret = CTransferSec::alloc(&cs, None);
        c_transfer(&public, &secret, &*POOL_PARAMS);
        let cs = cs.borrow();
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 9, 22);
            for gate in &cs.gates {
                writer.write_all(&gate.try_to_vec().unwrap()).unwrap();
            }
            writer.flush().unwrap();
        }
        let parameters = Parameters::<Bn256>(
            mpc.get_params().clone(),
            cs.gates.len() as u32,
            compressed,
            cs.const_tracker.clone(),
        );
        drop(cs);
        let vk = parameters.get_vk();
        let expected_vk: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(vk_path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&vk).unwrap(),
            expected_vk,
            "Stage 0 VK mismatch"
        );

        let mut empty_root = Num::<Fr>::ZERO;
        for _ in 0..constants::HEIGHT {
            empty_root = poseidon(&[empty_root, empty_root], POOL_PARAMS.compress());
        }
        assert_eq!(
            empty_root.to_string(),
            "11469701942666298368112882412133877458305516134926649826543144744382391691533"
        );
        let mut proxy = [0u8; 20];
        proxy[18] = 0xf0;
        proxy[19] = 0x03;
        let result = prove_deposit_with_unchecked_key(
            &parameters,
            witness_for(40003, proxy, empty_root, 1_000_000_000, 0, 0),
        )
        .unwrap();
        assert_eq!(result.public_inputs.len(), 5);
        assert_eq!(result.public_inputs[0], empty_root);
        assert_eq!(result.public_inputs[4], result.public.memo);
        assert!(
            verify(&vk, &result.proof, &result.public_inputs),
            "Stage 0 proof rejected"
        );

        // Prove the append of this adapter-produced output commitment. This
        // supplies PR21's second proof without inventing a tree root.
        let mut defaults = vec![Num::<Fr>::ZERO];
        for _ in 0..constants::HEIGHT {
            let before = *defaults.last().unwrap();
            defaults.push(poseidon(&[before, before], POOL_PARAMS.compress()));
        }
        let empty_leaf = defaults[constants::OUTPLUSONELOG];
        let tree_path: MerkleProof<Fr, { constants::HEIGHT - constants::OUTPLUSONELOG }> =
            MerkleProof {
                sibling: (constants::OUTPLUSONELOG..constants::HEIGHT)
                    .map(|i| defaults[i])
                    .collect(),
                path: (constants::OUTPLUSONELOG..constants::HEIGHT)
                    .map(|_| false)
                    .collect(),
            };
        assert_eq!(
            poseidon_merkle_proof_root(empty_leaf, &tree_path, POOL_PARAMS.compress()),
            empty_root
        );
        let next_root = poseidon_merkle_proof_root(
            result.public.out_commit,
            &tree_path,
            POOL_PARAMS.compress(),
        );
        assert_ne!(next_root, empty_root);
        let tree_public = TreePub {
            root_before: empty_root,
            root_after: next_root,
            leaf: result.public.out_commit,
        };
        let tree_secret = TreeSec {
            proof_filled: tree_path.clone(),
            proof_free: tree_path,
            prev_leaf: empty_leaf,
        };

        let mut tree_stage = std::fs::File::open(&tree_stage_path).unwrap();
        let mut tree_hasher = Sha256::new();
        std::io::copy(&mut tree_stage, &mut tree_hasher).unwrap();
        assert_eq!(
            hex::encode(tree_hasher.finalize()),
            "6fa8054b88077e4f531eb3e7fcf094ea9e2746672ea2788f816b2c4a13f3e68f"
        );
        let mut tree_stage = std::fs::File::open(&tree_stage_path).unwrap();
        let tree_mpc = MPCParameters::read(&mut tree_stage, true, true).unwrap();
        assert_eq!(
            tree_stage.read(&mut trailing).unwrap(),
            0,
            "trailing tree Stage 0 bytes"
        );
        let tree_cs = BuildCS::<Fr>::rc_new();
        let tree_pub_signal = CTreePub::alloc(&tree_cs, None);
        tree_pub_signal.inputize();
        let tree_sec_signal = CTreeSec::alloc(&tree_cs, None);
        tree_update(&tree_pub_signal, &tree_sec_signal, &*POOL_PARAMS);
        let tree_cs = tree_cs.borrow();
        let mut tree_compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut tree_compressed, 4096, 9, 22);
            for gate in &tree_cs.gates {
                writer.write_all(&gate.try_to_vec().unwrap()).unwrap();
            }
            writer.flush().unwrap();
        }
        let tree_parameters = Parameters::<Bn256>(
            tree_mpc.get_params().clone(),
            tree_cs.gates.len() as u32,
            tree_compressed,
            tree_cs.const_tracker.clone(),
        );
        drop(tree_cs);
        let tree_vk = tree_parameters.get_vk();
        let expected_tree_vk: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(tree_vk_path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&tree_vk).unwrap(),
            expected_tree_vk,
            "tree Stage 0 VK mismatch"
        );
        let (tree_inputs, tree_proof) = prove(
            &tree_parameters,
            &tree_public,
            &tree_secret,
            |public, secret| tree_update(&public, &secret, &*POOL_PARAMS),
        );
        assert_eq!(tree_inputs.len(), 3);
        assert_eq!(tree_inputs[0], empty_root);
        assert_eq!(tree_inputs[1], next_root);
        assert_eq!(tree_inputs[2], result.public.out_commit);
        assert!(
            verify(&tree_vk, &tree_proof, &tree_inputs),
            "tree Stage 0 proof rejected"
        );

        let output = serde_json::json!({
            "schema": "telos-pr7-wallet-adapter-unsafe-deposit-proof-v1",
            "testOnly": true,
            "unsafeZeroContribution": true,
            "sourceTree": SOURCE_TREE,
            "stage0Sha256": "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30",
            "poolId": 40003,
            "poolAddress": "0x000000000000000000000000000000000000F003",
            "depositZkUnits": 1_000_000_000u64,
            "feeZkUnits": 0,
            "memoDataHex": format!("0x{}", hex::encode(&result.memo)),
            "publicInputs": result.public_inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "proof": result.proof,
            "verifiedAgainstSealedStage0Vk": true,
            "treeUpdate": {
                "stage0Sha256": "6fa8054b88077e4f531eb3e7fcf094ea9e2746672ea2788f816b2c4a13f3e68f",
                "publicInputs": tree_inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "proof": tree_proof,
                "verifiedAgainstSealedStage0Vk": true
            }
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out_path)
            .unwrap();
        serde_json::to_writer_pretty(&mut file, &output).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
    }
}
