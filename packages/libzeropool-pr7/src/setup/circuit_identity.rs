//! Deterministic public circuit identity. This module never creates proving parameters.
// The repaired-transfer prototype uses the exact git revisions in Cargo.lock. The source
// hashes below bind the emitted circuit to this local CLI and relation source.

use libzeropool_zkbob::{
    circuit::{
        tx::{c_transfer, CTransferPub, CTransferSec},
        tree::{tree_update, CTreePub, CTreeSec},
        delegated_deposit::{check_delegated_deposit_batch, CDelegatedDepositBatchPub, CDelegatedDepositBatchSec},
    },
    constants::{IN, OUT, HEIGHT, BALANCE_SIZE_BITS, ENERGY_SIZE_BITS, POOLID_SIZE_BITS},
    native::params::PoolParams,
    POOL_PARAMS,
};
use fawkes_crypto::{
    circuit::{cs::{BuildCS, RCS}, lc::{AbstractLC, Index}, num::CNum},
    core::signal::Signal, engines::bn256::Fr, ff_uint::Num,
};
use fawkes_crypto::BorshSerialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub fn terms(lc: &[(Num<Fr>, Index)]) -> Vec<Value> {
    lc.iter().map(|(coefficient, index)| {
        let variable = match index { Index::Input(i) => format!("input_{i}"), Index::Aux(i) => format!("aux_{i}") };
        json!({"coefficient": coefficient.to_string(), "variable": variable})
    }).collect()
}
fn wire(n: &CNum<BuildCS<Fr>>) -> Value { json!(terms(&n.lc.to_vec())) }

/// Exactly the same allocate/inputize/allocate/circuit sequence as setup_circuit.
pub fn build(name: &str) -> Result<(RCS<BuildCS<Fr>>, Value), String> {
    let cs = BuildCS::<Fr>::rc_new();
    let (public, ranges, body_start) = match name {
        "transfer" => {
            let p = CTransferPub::alloc(&cs, None); p.inputize();
            let s = CTransferSec::alloc(&cs, None);
            let public = json!([
                {"name":"root", "wire":wire(&p.root)}, {"name":"nullifier", "wire":wire(&p.nullifier)},
                {"name":"out_commit", "wire":wire(&p.out_commit)}, {"name":"delta", "wire":wire(&p.delta)},
                {"name":"memo", "wire":wire(&p.memo)}]);
            let ranges = json!({
                "account_in_balance":wire(s.tx.input.0.b.as_num()), "account_out_balance":wire(s.tx.output.0.b.as_num()),
                "account_in_energy":wire(s.tx.input.0.e.as_num()), "account_out_energy":wire(s.tx.output.0.e.as_num()),
                "note_in_balances":s.tx.input.1.iter().map(|n| wire(n.b.as_num())).collect::<Vec<_>>(),
                "note_out_balances":s.tx.output.1.iter().map(|n| wire(n.b.as_num())).collect::<Vec<_>>(),
                "account_path_bits":s.in_proof.0.path.iter().map(|b| wire(b.as_num())).collect::<Vec<_>>(),
                "note_path_bits":s.in_proof.1.iter().map(|p| p.path.iter().map(|b| wire(b.as_num())).collect::<Vec<_>>()).collect::<Vec<_>>()
            });
            let start = cs.borrow().gates.len();
            c_transfer(&p, &s, &*POOL_PARAMS);
            (public, ranges, start)
        },
        "tree_update" => {
            let p = CTreePub::alloc(&cs, None); p.inputize();
            let s = CTreeSec::alloc(&cs, None);
            let public = json!([{"name":"root_before", "wire":wire(&p.root_before)}, {"name":"root_after", "wire":wire(&p.root_after)}, {"name":"leaf", "wire":wire(&p.leaf)}]);
            let start = cs.borrow().gates.len(); tree_update(&p, &s, &*POOL_PARAMS);
            (public, json!({}), start)
        },
        "delegated_deposit" => {
            let p = CDelegatedDepositBatchPub::alloc(&cs, None); p.inputize();
            let s = CDelegatedDepositBatchSec::alloc(&cs, None);
            let public = json!([{"name":"keccak_sum", "wire":wire(&p.keccak_sum)}]);
            let start = cs.borrow().gates.len(); check_delegated_deposit_batch(&p, &s, &*POOL_PARAMS);
            (public, json!({}), start)
        },
        _ => return Err("circuit must be transfer, tree_update, or delegated_deposit".into()),
    };
    let metadata = json!({"circuit":name, "public_inputs":public, "wires":ranges, "body_start_gate":body_start});
    Ok((cs, metadata))
}

/// Serialized rows are the exact pinned Fawkes Gate Borsh bytes, in emitted order.
pub fn describe(cs: &BuildCS<Fr>, mut metadata: Value, mut output: impl Write) -> io::Result<Value> {
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    for g in &cs.gates {
        let row = g.try_to_vec()?;
        hasher.update(&row); output.write_all(&row)?; bytes += row.len() as u64;
    }
    output.flush()?;
    let tracker = cs.const_tracker.to_bytes();
    metadata["format"] = json!("telos-privacy-circuit-identity-v1");
    metadata["modulus"] = json!(Num::<Fr>::MODULUS.to_string());
    metadata["layout"] = json!({"inputs":IN,"outputs":OUT,"height":HEIGHT,"balance_bits":BALANCE_SIZE_BITS,"energy_bits":ENERGY_SIZE_BITS,"pool_id_bits":POOLID_SIZE_BITS});
    metadata["layout_feature"] = json!(format!("in{}out{}",IN,OUT));
    let mut empty_root=Num::<Fr>::ZERO;
    for _ in 0..HEIGHT { empty_root=fawkes_crypto::native::poseidon::poseidon(&[empty_root,empty_root],POOL_PARAMS.compress()); }
    metadata["empty_tree_root"] = json!(empty_root.to_string());
    // Hash every circuit/parameter input directly. The source lock additionally
    // covers native code, ceremony code, the checker, regressions and docs.
    let sources: &[(&str,&[u8])] = &[
        ("Cargo.lock",include_bytes!("../../Cargo.lock")),
        ("Cargo.toml",include_bytes!("../../Cargo.toml")),
        ("formal/ceremony-source-lock.json",include_bytes!("../../formal/ceremony-source-lock.json")),
        ("rust-toolchain.toml",include_bytes!("../../rust-toolchain.toml")),
        ("src/lib.rs",include_bytes!("../lib.rs")),
        ("src/circuit/tx.rs",include_bytes!("../circuit/tx.rs")),
        ("src/circuit/account.rs",include_bytes!("../circuit/account.rs")),
        ("src/circuit/note.rs",include_bytes!("../circuit/note.rs")),
        ("src/circuit/key.rs",include_bytes!("../circuit/key.rs")),
        ("src/circuit/boundednum.rs",include_bytes!("../circuit/boundednum.rs")),
        ("src/circuit/tree.rs",include_bytes!("../circuit/tree.rs")),
        ("src/circuit/delegated_deposit.rs",include_bytes!("../circuit/delegated_deposit.rs")),
        ("src/setup/main.rs",include_bytes!("main.rs")),
        ("src/setup/ceremony_input.rs",include_bytes!("ceremony_input.rs")),
        ("src/setup/ceremony_verify.rs",include_bytes!("ceremony_verify.rs")),
        ("src/setup/ceremony_contribute.rs",include_bytes!("ceremony_contribute.rs")),
        ("src/setup/circuit_setup.rs",include_bytes!("circuit_setup.rs")),
        ("src/constants/mod.rs",include_bytes!("../constants/mod.rs")),
        ("src/constants/in1out127.rs",include_bytes!("../constants/in1out127.rs")),
        ("src/constants/in3out127.rs",include_bytes!("../constants/in3out127.rs")),
        ("src/constants/in7out127.rs",include_bytes!("../constants/in7out127.rs")),
        ("src/constants/in15out127.rs",include_bytes!("../constants/in15out127.rs")),
        ("src/setup/circuit_identity.rs",include_bytes!("circuit_identity.rs")),
        ("res/poseidon_params_t_2.json",include_bytes!("../../res/poseidon_params_t_2.json")),
        ("res/poseidon_params_t_3.json",include_bytes!("../../res/poseidon_params_t_3.json")),
        ("res/poseidon_params_t_4.json",include_bytes!("../../res/poseidon_params_t_4.json")),
        ("res/poseidon_params_t_5.json",include_bytes!("../../res/poseidon_params_t_5.json")),
        ("res/poseidon_params_t_6.json",include_bytes!("../../res/poseidon_params_t_6.json")),
    ];
    let hashes: serde_json::Map<String,Value> = sources.iter().map(|(name,bytes)| (name.to_string(),json!(hex::encode(Sha256::digest(bytes))))).collect();
    metadata["source_sha256"] = json!(hashes);
    metadata["num_inputs_including_one"] = json!(cs.num_input);
    metadata["num_aux"] = json!(cs.num_aux);
    metadata["num_gates"] = json!(cs.gates.len());
    metadata["r1cs_encoding"] = json!("concatenated Fawkes Gate Borsh: 3 vectors per row; u32 little endian vector length; each term canonical field 32 bytes little endian, enum u8 (0 Input, 1 Aux), index u32 little endian");
    metadata["r1cs_bytes"] = json!(bytes);
    metadata["r1cs_sha256"] = json!(hex::encode(hasher.finalize()));
    metadata["constant_tracker_bit_length"] = json!(cs.const_tracker.len());
    metadata["constant_tracker_sha256"] = json!(hex::encode(Sha256::digest(&tracker)));
    metadata["constant_tracker_hex"] = json!(hex::encode(tracker));
    // Hash the canonical compact serde_json representation without self-reference.
    metadata["identity_sha256"] = json!(hex::encode(Sha256::digest(serde_json::to_vec(&metadata)?)));
    Ok(metadata)
}
