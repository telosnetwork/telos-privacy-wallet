use libzeropool_zkbob::{
    circuit::tx::{c_transfer, c_tx_verify, CTransferPub, CTransferSec},
    constants::HEIGHT,
    fawkes_crypto::{
        circuit::{cs::DebugCS, num::CNum},
        core::signal::Signal,
        engines::bn256::{Fr, Fs},
        ff_uint::Num,
        native::poseidon::poseidon,
        rand::{rngs::StdRng, SeedableRng},
    },
    helpers::sample_data::{State, N_ITEMS},
    native::{
        key::{derive_key_eta, derive_key_p_d},
        params::PoolParams,
        tx::{make_delta, parse_delta, tx_verify},
    },
    POOL_PARAMS,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn transfer_accepts(
    public: &libzeropool_zkbob::native::tx::TransferPub<Fr>,
    secret: &libzeropool_zkbob::native::tx::TransferSec<Fr>,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let cs = DebugCS::<Fr>::rc_new();
        let p = CTransferPub::alloc(&cs, Some(public));
        let s = CTransferSec::alloc(&cs, Some(secret));
        c_transfer(&p, &s, &*POOL_PARAMS);
    }))
    .is_ok()
}

#[test]
fn identity_key_zero_signature_is_rejected_for_every_message() {
    let zero = Num::<Fr>::ZERO;
    for message in [zero, Num::<Fr>::ONE, Num::from(2026u64)] {
        let cs = DebugCS::<Fr>::rc_new();
        let s = CNum::alloc(&cs, Some(&zero));
        let r = CNum::alloc(&cs, Some(&zero));
        let a = CNum::alloc(&cs, Some(&zero));
        let m = CNum::alloc(&cs, Some(&message));
        assert!(catch_unwind(AssertUnwindSafe(|| {
            c_tx_verify(&s, &r, &a, &m, &*POOL_PARAMS).assert_const(&true);
        }))
        .is_err());
        assert!(!tx_verify::<libzeropool_zkbob::native::params::PoolBN256>(
            Num::<Fs>::ZERO,
            zero,
            zero,
            message,
            &*POOL_PARAMS,
        ));
    }
}

#[test]
fn full_transfer_rejects_identity_key_and_zero_signature() {
    // This deterministic fixture satisfied the full pre-fix transfer relation,
    // including its funded-note Merkle and balance constraints. It exercises
    // the authorization guard in the complete circuit, not only its helper.
    let mut rng = StdRng::seed_from_u64(0x54454c4f53505237);
    let mut state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    state.sigma = Num::<Fs>::ZERO;
    let eta = derive_key_eta(Num::<Fr>::ZERO, &*POOL_PARAMS);
    let account_id = state.account_id;
    state.items[account_id].0.p_d =
        derive_key_p_d(state.items[account_id].0.d.to_num(), eta, &*POOL_PARAMS).x;
    let note_ids = state.note_id.clone();
    for note_id in note_ids.iter().copied() {
        state.items[note_id].1.p_d =
            derive_key_p_d(state.items[note_id].1.d.to_num(), eta, &*POOL_PARAMS).x;
    }
    let mut changed = vec![account_id * 2];
    changed.extend(note_ids.iter().map(|i| i * 2 + 1));
    for leaf in changed {
        let i = leaf / 2;
        state.hashes[0][leaf] = if leaf % 2 == 0 {
            state.items[i].0.hash(&*POOL_PARAMS)
        } else {
            state.items[i].1.hash(&*POOL_PARAMS)
        };
        let mut current = leaf;
        for depth in 0..HEIGHT {
            let parent = current >> 1;
            let left = state.hashes[depth]
                .get(parent * 2)
                .copied()
                .unwrap_or(state.default_hashes[depth]);
            let right = state.hashes[depth]
                .get(parent * 2 + 1)
                .copied()
                .unwrap_or(state.default_hashes[depth]);
            state.hashes[depth + 1][parent] = poseidon(&[left, right], POOL_PARAMS.compress());
            current = parent;
        }
    }
    assert_eq!(state.hashes[0].len(), N_ITEMS * 2);
    let (mut public, mut secret) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);
    assert_eq!(secret.eddsa_a, Num::<Fr>::ZERO);
    secret.eddsa_s = Num::<Fr>::ZERO;
    secret.eddsa_r = Num::<Fr>::ZERO;
    assert!(!transfer_accepts(&public, &secret));

    public.memo = if public.memo == Num::ZERO {
        Num::ONE
    } else {
        Num::ZERO
    };
    assert!(!transfer_accepts(&public, &secret));

    let (value, energy, index, _) = parse_delta(public.delta);
    public.delta = make_delta(value, energy, index, Num::from(40002u64));
    assert!(!transfer_accepts(&public, &secret));
}
