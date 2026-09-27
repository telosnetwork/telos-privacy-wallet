//! Export the R1CS slice that excludes identity-address funded output notes.
use libzeropool_zkbob::{
    circuit::tx::c_enforce_funded_output_note_nonidentity,
    fawkes_crypto::{
        circuit::{cs::BuildCS, lc::Index, num::CNum},
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
    let amount = CNum::alloc(&cs, None);
    let p_d = CNum::alloc(&cs, None);
    c_enforce_funded_output_note_nonidentity(&amount, &p_d);
    let cs = cs.borrow();
    let gates = cs.gates.iter().map(|g| json!({
        "a": terms(&g.0), "b": terms(&g.1), "c": terms(&g.2)
    })).collect::<Vec<_>>();
    let export = json!({
        "format": "fawkes-r1cs-funded-output-nonidentity-slice-v1",
        "field_modulus": Num::<Fr>::MODULUS.to_string(),
        "amount": "aux_0", "p_d": "aux_1", "constant_one": "input_0",
        "num_inputs": cs.num_input, "num_aux": cs.num_aux,
        "gates": gates,
    });
    println!("{}", serde_json::to_string_pretty(&export).unwrap());
}
