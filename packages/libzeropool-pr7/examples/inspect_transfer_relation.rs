//! Inspect the setup-shaped transfer R1CS without starting a ceremony.
#[cfg(not(all(feature = "in3out127", feature = "cli_libzeropool_setup")))]
compile_error!("inspect_transfer_relation requires the production in3out127 setup features");
#[cfg(any(feature = "in1out127", feature = "in15out127", feature = "in7ount127"))]
compile_error!("inspect_transfer_relation requires only the in3out127 circuit size");
use libzeropool_zkbob::{
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    fawkes_crypto::{
        borsh::BorshSerialize,
        circuit::cs::BuildCS,
        core::signal::Signal,
        engines::bn256::Fr,
    },
    POOL_PARAMS,
};
use sha2::{Digest, Sha256};

fn main() {
    // Exact allocation/inputization order used by setup_circuit.
    let cs = BuildCS::<Fr>::rc_new();
    let public = CTransferPub::alloc(&cs, None);
    public.inputize();
    let secret = CTransferSec::alloc(&cs, None);
    c_transfer(&public, &secret, &*POOL_PARAMS);
    let cs = cs.borrow();
    let mut matrix_hash = Sha256::new();
    let mut raw_bytes = 0usize;
    for gate in cs.gates.iter() {
        let row = gate.try_to_vec().unwrap();
        raw_bytes += row.len();
        matrix_hash.update(row);
    }
    println!(
        "{{\"feature\":\"in3out127\",\"num_gates\":{},\"num_inputs\":{},\"num_aux\":{},\"raw_matrix_bytes\":{},\"raw_matrix_sha256\":\"{:x}\",\"radix18_capacity\":{},\"within_radix18\":{}}}",
        cs.gates.len(), cs.num_input, cs.num_aux, raw_bytes, matrix_hash.finalize(),
        1usize << 18, cs.gates.len() < (1usize << 18),
    );
}
