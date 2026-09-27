use fawkes_crypto::ff_uint::PrimeField;
use fawkes_crypto::native::{ecc::{EdwardsPoint, JubJubParams}, poseidon::{poseidon}};
use fawkes_crypto::ff_uint::Num;
use crate::native::params::PoolParams;


// intermediate key
pub fn derive_key_a<P:PoolParams>(
    sigma: Num<P::Fs>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    params.jubjub().edwards_g().mul(sigma, params.jubjub())
}

// intermediate key
pub fn derive_key_eta<P:PoolParams>(a: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[a], params.hash())
}

/// Canonical subgroup-scalar representative, encoded back in the SNARK field.
pub fn canonical_eta_scalar<P:PoolParams>(eta: Num<P::Fr>) -> Num<P::Fr> {
    let reduced: Num<P::Fs> = eta.to_other_reduced();
    assert_ne!(reduced, Num::ZERO, "identity eta scalar is not a spend key");
    reduced.to_other().unwrap()
}


pub fn derive_key_p_d<P:PoolParams, Fr:PrimeField>(
    d: Num<P::Fr>,
    eta: Num<Fr>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    let eta_reduced: Num<P::Fs> = eta.to_other_reduced();
    assert_ne!(eta_reduced, Num::ZERO, "identity eta scalar is not an address key");
    let d_hash = poseidon(&[d], params.hash());
    let base = EdwardsPoint::from_scalar(d_hash, params.jubjub());
    assert_ne!(base.x, Num::ZERO, "identity diversifier base is not an address key");
    base.mul(eta_reduced, params.jubjub())
}
