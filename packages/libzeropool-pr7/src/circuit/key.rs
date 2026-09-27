use fawkes_crypto::circuit::bool::CBool;

use crate::fawkes_crypto::circuit::{
    bitify::{c_comp_constant, c_into_bits_le_strict},
    ecc::CEdwardsPoint,
    num::CNum,
    poseidon::{c_poseidon},
    cs::CS
};
use crate::fawkes_crypto::core::signal::Signal;
use crate::fawkes_crypto::ff_uint::Num;
use crate::native::params::PoolParams;



// intermediate key
pub fn c_derive_key_eta<C:CS, P: PoolParams<Fr = C::Fr>>(a: &CNum<C>, params: &P) -> CNum<C> {
    c_poseidon(&[a.clone()], params.hash())
}

/// Return the canonical Jubjub scalar represented by a BN254 field element.
///
/// The point multiplication used for p_d reduces eta modulo the subgroup
/// order. Nullifiers must hash that same reduced representative, otherwise
/// eta and eta + subgroup_order share p_d but have different nullifiers.
///
/// The quotient is derived from strict field bits using seven constant
/// thresholds. In particular, it is not an unconstrained witness satisfying
/// only a field equality, which would admit a wrap at the BN254 modulus.
pub fn c_canonical_eta_scalar<C:CS, P: PoolParams<Fr = C::Fr>>(
    eta: &CNum<C>,
) -> (CNum<C>, Vec<CBool<C>>) {
    assert_eq!(
        Num::<C::Fr>::MODULUS.to_string(),
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    );
    assert_eq!(
        Num::<P::Fs>::MODULUS.to_string(),
        "2736030358979909402780800718157159386076813972158567259200215660948447373041"
    );
    let eta_bits = c_into_bits_le_strict(eta);
    let order_minus_one: Num<C::Fr> = (-Num::<P::Fs>::ONE).to_other().unwrap();
    let order = order_minus_one + Num::ONE;
    let mut quotient: CNum<C> = eta.derive_const(&Num::ZERO);
    // Fr is smaller than 8 * Fs, so the quotient is in 0..=7.
    for multiple in 1..=7 {
        let threshold = order * Num::from(multiple as u64) - Num::ONE;
        quotient += c_comp_constant(&eta_bits, threshold).as_num();
    }
    let reduced = eta - quotient * order;
    let reduced_bits = c_into_bits_le_strict(&reduced);
    c_comp_constant(&reduced_bits, order_minus_one).assert_const(&false);
    // Multiples of Fs act as the identity on every derived address.  An
    // identity p_d has no unique owner and must not authorize a transfer.
    reduced.assert_nonzero();
    (reduced, eta_bits)
}


pub fn c_derive_key_p_d<C:CS, P: PoolParams<Fr = C::Fr>>(
    d: &CNum<C>,
    eta_bits: &[CBool<C>],
    params: &P,
) -> CEdwardsPoint<C> {
    let d_hash = c_poseidon(&[d.clone()], params.hash());
    let base = CEdwardsPoint::from_scalar(&d_hash, params.jubjub());
    // Nonzero base makes its prime-order scalar action injective modulo Fs.
    // In c_transfer, the canonical-scalar check also excludes identity p_d.
    base.x.assert_nonzero();
    base.mul(&eta_bits, params.jubjub())
}
