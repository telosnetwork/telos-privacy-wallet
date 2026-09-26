use libzeropool_zkbob::{
    circuit::{account::CAccount, key::{c_canonical_eta_scalar, c_derive_key_p_d},
              tx::c_enforce_funded_output_note_nonidentity},
    fawkes_crypto::{
        circuit::{cs::DebugCS, num::CNum},
        core::signal::Signal,
        engines::bn256::{Fr, Fs},
        ff_uint::Num,
    },
    native::{account::Account, boundednum::BoundedNum,
             key::{canonical_eta_scalar, derive_key_p_d}, params::PoolBN256,
             tx::nullifier},
    POOL_PARAMS,
};
#[cfg(feature = "cli_libzeropool_setup")]
use libzeropool_zkbob::{
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    fawkes_crypto::rand::thread_rng,
    helpers::sample_data::State,
    native::tx::{make_delta, out_commitment_hash, parse_delta, tx_hash, tx_sign, TransferPub, TransferSec},
};
use std::str::FromStr;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn order() -> Num<Fr> {
    Num::<Fr>::from_str(
        "2736030358979909402780800718157159386076813972158567259200215660948447373041",
    ).unwrap()
}

#[test]
fn canonical_eta_boundary_witnesses_satisfy_the_circuit() {
    let r = order();
    let values = [
        Num::<Fr>::ONE,
        r - Num::ONE,
        r + Num::ONE,
        r * Num::from(7u64) - Num::ONE,
        r * Num::from(7u64) + Num::ONE,
        -Num::ONE,
    ];
    for eta in values.iter().copied() {
        let cs = DebugCS::<Fr>::rc_new();
        let eta_signal = CNum::alloc(&cs, Some(&eta));
        let (reduced, bits) = c_canonical_eta_scalar::<DebugCS<Fr>, PoolBN256>(&eta_signal);
        let native = canonical_eta_scalar::<PoolBN256>(eta);
        let direct: Num<Fr> = eta.to_other_reduced::<Fs>().to_other().unwrap();
        assert_eq!(bits.len(), 254);
        assert_eq!(reduced.get_value().unwrap(), native);
        assert_eq!(native, direct);
    }
}

#[test]
fn same_point_uses_same_canonical_nullifier_input() {
    let r = order();
    let eta_1 = Num::<Fr>::ONE;
    let eta_2 = eta_1 + r;
    for pool_id in [40001_u32, 40002_u32].iter().copied() {
        let d = Num::<Fr>::from(pool_id);
        let point_1 = derive_key_p_d(d, eta_1, &*POOL_PARAMS);
        let point_2 = derive_key_p_d(d, eta_2, &*POOL_PARAMS);
        assert_eq!(point_1.x, point_2.x);
        assert_eq!(canonical_eta_scalar::<PoolBN256>(eta_1),
                   canonical_eta_scalar::<PoolBN256>(eta_2));
        assert_eq!(nullifier(Num::ONE, eta_1, Num::ZERO, &*POOL_PARAMS),
                   nullifier(Num::ONE, eta_2, Num::ZERO, &*POOL_PARAMS));
    }
}

#[test]
fn native_derived_basepoints_are_nonzero_for_dummy_and_pool_diversifiers() {
    for diversifier in [0_u32, 40001_u32, 40002_u32].iter().copied() {
        let point = derive_key_p_d(Num::<Fr>::from(diversifier), Num::<Fr>::ONE, &*POOL_PARAMS);
        assert_ne!(point.x, Num::ZERO);
    }
}

#[test]
fn identity_scalar_representatives_are_rejected_by_circuit_and_native_paths() {
    let r = order();
    let d = Num::<Fr>::from(40001u32);
    for eta in [Num::<Fr>::ZERO, r, r * Num::from(2u64), r * Num::from(7u64)] {
        let circuit = catch_unwind(AssertUnwindSafe(|| {
            let cs = DebugCS::<Fr>::rc_new();
            let eta_signal = CNum::alloc(&cs, Some(&eta));
            c_canonical_eta_scalar::<DebugCS<Fr>, PoolBN256>(&eta_signal);
        }));
        assert!(circuit.is_err(), "identity scalar accepted by the circuit");
        assert!(catch_unwind(|| canonical_eta_scalar::<PoolBN256>(eta)).is_err());
        assert!(catch_unwind(|| derive_key_p_d(d, eta, &*POOL_PARAMS)).is_err());
        assert!(catch_unwind(|| nullifier(Num::ONE, eta, Num::ZERO, &*POOL_PARAMS)).is_err());
    }
}

#[test]
fn funded_output_notes_cannot_use_identity_address_but_padding_can() {
    for (amount, p_d, allowed) in [
        (Num::<Fr>::ZERO, Num::<Fr>::ZERO, true),
        (Num::<Fr>::ZERO, Num::<Fr>::ONE, true),
        (Num::<Fr>::ONE, Num::<Fr>::ONE, true),
        (Num::<Fr>::ONE, Num::<Fr>::ZERO, false),
    ] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let cs = DebugCS::<Fr>::rc_new();
            let amount_signal = CNum::alloc(&cs, Some(&amount));
            let p_d_signal = CNum::alloc(&cs, Some(&p_d));
            c_enforce_funded_output_note_nonidentity(&amount_signal, &p_d_signal);
        }));
        assert_eq!(result.is_ok(), allowed);
    }
}

#[test]
#[cfg(feature = "cli_libzeropool_setup")]
fn full_transfer_rejects_funded_identity_output_note() {
    let mut rng = thread_rng();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let (mut public, mut secret) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);
    let note = &mut secret.tx.output.1[0];
    note.b = BoundedNum::new(Num::ONE);
    note.p_d = derive_key_p_d(note.d.to_num(), Num::<Fr>::ONE, &*POOL_PARAMS).x;
    secret.tx.output.0.b =
        BoundedNum::new(secret.tx.output.0.b.to_num() - Num::ONE);

    let sign = |public: &mut TransferPub<Fr>, secret: &mut TransferSec<Fr>| {
        let out_hashes = std::iter::once(secret.tx.output.0.hash(&*POOL_PARAMS))
            .chain(secret.tx.output.1.iter().map(|n| n.hash(&*POOL_PARAMS)))
            .collect::<Vec<_>>();
        public.out_commit = out_commitment_hash(&out_hashes, &*POOL_PARAMS);
        let in_hashes = std::iter::once(secret.tx.input.0.hash(&*POOL_PARAMS))
            .chain(secret.tx.input.1.iter().map(|n| n.hash(&*POOL_PARAMS)))
            .collect::<Vec<_>>();
        let poolid = parse_delta(public.delta).3;
        let message = tx_hash(&in_hashes, public.out_commit, public.memo, poolid, &*POOL_PARAMS);
        let (s, r) = tx_sign(state.sigma, message, &*POOL_PARAMS);
        secret.eddsa_s = s.to_other().unwrap();
        secret.eddsa_r = r;
    };
    sign(&mut public, &mut secret);

    let witness = |public: &TransferPub<Fr>, secret: &TransferSec<Fr>| {
        let cs = DebugCS::<Fr>::rc_new();
        let p = CTransferPub::alloc(&cs, Some(&public));
        let s = CTransferSec::alloc(&cs, Some(&secret));
        c_transfer(&p, &s, &*POOL_PARAMS);
    };
    assert!(catch_unwind(AssertUnwindSafe(|| witness(&public, &secret))).is_ok());

    // A prover who keeps the spending signature cannot substitute different
    // calldata memo bytes (including fee or withdrawal recipient fields).
    let authorized_memo = public.memo;
    public.memo = if authorized_memo == Num::ZERO { Num::ONE } else { Num::ZERO };
    assert!(catch_unwind(AssertUnwindSafe(|| witness(&public, &secret))).is_err());
    public.memo = authorized_memo;

    // A retained spending signature also cannot authorize a different pool.
    let authorized_delta = public.delta;
    let (value, energy, index, _) = parse_delta(public.delta);
    public.delta = make_delta(value, energy, index, Num::from(40002u32));
    assert!(catch_unwind(AssertUnwindSafe(|| witness(&public, &secret))).is_err());
    public.delta = authorized_delta;

    secret.tx.output.1[0].p_d = Num::ZERO;
    sign(&mut public, &mut secret);
    assert!(catch_unwind(AssertUnwindSafe(|| witness(&public, &secret))).is_err());
}

#[test]
fn representative_initial_account_ownership_slice_satisfies_the_circuit() {
    let d = Num::<Fr>::from(40001u32);
    let eta = Num::<Fr>::ONE;
    let account = Account {
        d: BoundedNum::new(d),
        p_d: derive_key_p_d(d, eta, &*POOL_PARAMS).x,
        i: BoundedNum::ZERO,
        b: BoundedNum::ZERO,
        e: BoundedNum::ZERO,
    };
    let cs = DebugCS::<Fr>::rc_new();
    let c_account = CAccount::alloc(&cs, Some(&account));
    let c_pool = CNum::alloc(&cs, Some(&d));
    let c_eta = CNum::alloc(&cs, Some(&eta));
    assert_eq!(c_account.is_initial(&c_pool).get_value(), Some(true));
    let (_, bits) = c_canonical_eta_scalar::<DebugCS<Fr>, PoolBN256>(&c_eta);
    let derived = c_derive_key_p_d(c_account.d.as_num(), &bits, &*POOL_PARAMS);
    (&c_account.p_d - &derived.x).assert_zero();
}

#[test]
fn field_only_quotient_relation_has_a_wrap_witness_but_canonical_gadget_excludes_it() {
    let r = order();
    let forged_quotient = Num::<Fr>::from(7u64);
    // For eta=1, 7*Fs + (1+Fr-7*Fs) is 1 mod Fr. This passes a field equality and
    // both naive quotient/remainder bounds, despite being the wrong quotient.
    let forged_remainder = Num::<Fr>::ONE - forged_quotient * r;
    assert!(forged_remainder.to_uint() < r.to_uint());
    assert_eq!(forged_quotient * r + forged_remainder, Num::ONE);

    let cs = DebugCS::<Fr>::rc_new();
    let eta_signal = CNum::alloc(&cs, Some(&Num::ONE));
    let (canonical, _) = c_canonical_eta_scalar::<DebugCS<Fr>, PoolBN256>(&eta_signal);
    assert_eq!(canonical.get_value().unwrap(), Num::ONE);
    assert_ne!(canonical.get_value().unwrap(), forged_remainder);
}
