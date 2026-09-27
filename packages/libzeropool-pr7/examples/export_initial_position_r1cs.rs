//! Export the R1CS produced by the guard called from the real transfer circuit.
use libzeropool_zkbob::{
    circuit::tx::c_enforce_initial_account_position,
    fawkes_crypto::{
        circuit::{bool::CBool, cs::BuildCS, lc::Index, num::CNum},
        core::signal::Signal,
        engines::bn256::Fr,
        ff_uint::Num,
    },
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
    let position = CNum::alloc(&cs, None);
    let initial = CBool::alloc(&cs, None);
    c_enforce_initial_account_position(&position, &initial);
    let cs = cs.borrow();
    let gates = cs.gates.iter().map(|g| json!({
        "a": terms(&g.0), "b": terms(&g.1), "c": terms(&g.2)
    })).collect::<Vec<_>>();
    let export = json!({
        "format": "fawkes-r1cs-slice-v1",
        "modulus": Num::<Fr>::MODULUS.to_string(),
        "position": "aux_0", "is_initial": "aux_1", "constant_one": "input_0",
        "num_inputs": cs.num_input, "num_aux": cs.num_aux,
        "gates": gates,
    });
    println!("{}", serde_json::to_string_pretty(&export).unwrap());
}
