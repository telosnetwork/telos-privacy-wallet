//! UNSAFE_STAGE0_NO_GO: isolated compatibility experiment, never wallet dispatch.
//!
//! Construct a transaction with the actual 1.4.0 wallet account builder, then
//! explicitly translate its serialized witness to the pinned PR7 type universe.
//! The account's signing scalar stays inside this Rust process. In particular,
//! the old nullifier and signature are not accepted as PR7 values.

use libzeropool_pr7::{
    fawkes_crypto::{
        backend::bellman_groth16::{engines::Bn256, verifier::verify, Parameters},
        engines::bn256::{Fr, Fs},
        ff_uint::Num,
    },
    native::{
        key::{derive_key_a, derive_key_eta},
        tx::{nullifier, TransferPub, TransferSec},
    },
    POOL_PARAMS,
};
use libzkbob_rs::{
    client::{state::State, TxOperator, TxType, UserAccount},
    libzeropool::{
        fawkes_crypto::ff_uint::Num as OldNum, native::boundednum::BoundedNum,
        POOL_PARAMS as OLD_POOL_PARAMS,
    },
};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use wtlos_pr7_proof::{
    finalize_deposit, prove_deposit_with_unchecked_key, AdapterError, DepositWitness, SOURCE_TREE,
};

const POOL_ID: u32 = 40003;
const AMOUNT: u64 = 1_000_000_000;
const PROXY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0x03,
];
const UNSAFE_STAGE0_KEY_SHA256: &str =
    "44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1";

fn wallet_deposit_witness() -> (DepositWitness, Num<Fr>) {
    // This is the actual legacy wallet transaction builder and in-memory state,
    // configured for the fresh WTLOS V1 domain. The same `create_tx` is called
    // by the existing browser UserAccount wrapper.
    let state = State::init_test(OLD_POOL_PARAMS.clone());
    let mut account = UserAccount::new(
        OldNum::from(42u64),
        POOL_ID,
        true,
        state,
        OLD_POOL_PARAMS.clone(),
    );
    account.enable_wtlos_v1_domain(PROXY);
    let operator = TxOperator {
        proxy_address: PROXY.to_vec(),
        prover_address: vec![0; 20],
        proxy_fee: BoundedNum::ZERO,
        prover_fee: BoundedNum::ZERO,
    };
    let old = account
        .create_tx(
            TxType::Deposit(operator, vec![], BoundedNum::new(OldNum::from(AMOUNT))),
            Some(128),
            None,
        )
        .expect("legacy wallet creates the synthetic deposit witness");

    // The two circuit crates intentionally remain different Rust type worlds.
    // Serialization is a narrow, reviewable boundary; never transmute field
    // elements or assume package-name equality means relation equality.
    let mut public: TransferPub<Fr> =
        serde_json::from_value(serde_json::to_value(&old.public).unwrap()).unwrap();
    let secret: TransferSec<Fr> =
        serde_json::from_value(serde_json::to_value(&old.secret).unwrap()).unwrap();
    let signing_key = Num::<Fs>::from_str(&account.keys.sk.to_string()).unwrap();
    assert_eq!(derive_key_a(signing_key, &*POOL_PARAMS).x, secret.eddsa_a);

    // The wallet builder uses the pre-PR7 raw-eta nullifier. PR7 binds the
    // canonical subgroup scalar and the physical account Merkle position.
    let path_index = secret
        .in_proof
        .0
        .path
        .iter()
        .enumerate()
        .fold(0u64, |index, (bit, set)| index | (u64::from(*set) << bit));
    let eta = derive_key_eta(secret.eddsa_a, &*POOL_PARAMS);
    let old_nullifier = public.nullifier;
    public.nullifier = nullifier(
        secret.tx.input.0.hash(&*POOL_PARAMS),
        eta,
        Num::from(path_index),
        &*POOL_PARAMS,
    );
    assert_ne!(
        old_nullifier, public.nullifier,
        "the wallet's raw-eta nullifier must not be reused"
    );

    (
        DepositWitness {
            public,
            secret,
            signing_key,
            pool_id: POOL_ID,
            amount: AMOUNT,
            fee: 0,
            proxy: PROXY,
        },
        old_nullifier,
    )
}

#[test]
fn actual_wallet_witness_can_be_finalized_only_after_explicit_pr7_conversion() {
    assert_eq!(SOURCE_TREE, "7a22196e1d4a791b452a6140bdfa915298f3f1da");
    let (mut unconverted, old_nullifier) = wallet_deposit_witness();
    unconverted.public.nullifier = old_nullifier;
    assert!(matches!(
        finalize_deposit(unconverted),
        Err(AdapterError::WrongNullifier)
    ));

    let (witness, _) = wallet_deposit_witness();
    let finalized = finalize_deposit(witness).expect("source-matched PR7 finalizer");
    assert_eq!(&finalized.memo[..8], &0u64.to_be_bytes());
    assert_eq!(&finalized.memo[12..16], b"TPD1");
    assert_eq!(&finalized.memo[16..36], &PROXY);
    assert_ne!(finalized.public.nullifier, Num::ZERO);

    let (mut wrong_nullifier, _) = wallet_deposit_witness();
    wrong_nullifier.public.nullifier += Num::ONE;
    assert!(matches!(
        finalize_deposit(wrong_nullifier),
        Err(AdapterError::WrongNullifier)
    ));
}

#[test]
#[ignore = "explicit opt-in zero-contribution Stage 0 proof; never use with a wallet or live service"]
fn actual_wallet_witness_proves_against_source_matched_stage0_key() {
    let path = std::env::var("UNSAFE_PR7_CONVERTED_KEY")
        .expect("set the exact sealed, zero-contribution Stage 0 converted key path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        UNSAFE_STAGE0_KEY_SHA256
    );
    let mut reader = bytes.as_slice();
    let params = Parameters::<Bn256>::read(&mut reader, true, true).unwrap();
    assert!(reader.is_empty());
    assert_eq!(params.1, 196_327);

    let (witness, _) = wallet_deposit_witness();
    let result = prove_deposit_with_unchecked_key(&params, witness).unwrap();
    assert_eq!(result.public_inputs.len(), 5);
    assert!(verify(
        &params.get_vk(),
        &result.proof,
        &result.public_inputs
    ));
    let mut changed_inputs = result.public_inputs.clone();
    changed_inputs[0] += Num::ONE;
    assert!(!verify(&params.get_vk(), &result.proof, &changed_inputs));
}
