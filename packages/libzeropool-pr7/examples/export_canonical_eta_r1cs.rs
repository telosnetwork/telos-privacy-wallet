//! Export the exact R1CS emitted by the canonical eta gadget used by c_transfer.
use libzeropool_zkbob::{
    circuit::key::c_canonical_eta_scalar,
    fawkes_crypto::{
        circuit::{cs::BuildCS, lc::{AbstractLC, Index}, num::CNum},
        core::signal::Signal,
        engines::bn256::Fr,
        ff_uint::Num,
    },
    native::params::PoolBN256,
};
use serde_json::{json, Value};

fn terms(lc: &[(Num<Fr>, Index)]) -> Vec<Value> {
    lc.iter().map(|(coefficient, index)| {
        let variable = match index {
            Index::Input(i) => format!("input_{i}"),
            Index::Aux(i) => format!("aux_{i}"),
        };
        json!({ "coefficient": coefficient.to_string(), "variable": variable })
    }).collect()
}

fn main() {
    let cs = BuildCS::<Fr>::rc_new();
    let eta = CNum::alloc(&cs, None);
    let (eta_scalar, _) = c_canonical_eta_scalar::<BuildCS<Fr>, PoolBN256>(&eta);
    let scalar_lc = terms(&eta_scalar.lc.to_vec());
    let cs = cs.borrow();
    let gates = cs.gates.iter().map(|g| json!({
        "a": terms(&g.0), "b": terms(&g.1), "c": terms(&g.2)
    })).collect::<Vec<_>>();
    let export = json!({
        "format": "fawkes-r1cs-canonical-eta-slice-v1",
        "field_modulus": Num::<Fr>::MODULUS.to_string(),
        "scalar_order": "2736030358979909402780800718157159386076813972158567259200215660948447373041",
        "eta": "aux_0", "eta_scalar_lc": scalar_lc, "constant_one": "input_0",
        "num_inputs": cs.num_input, "num_aux": cs.num_aux,
        "gates": gates,
    });
    println!("{}", serde_json::to_string_pretty(&export).unwrap());
}
