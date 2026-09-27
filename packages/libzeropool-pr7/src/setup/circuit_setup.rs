use bit_vec::BitVec;
use fawkes_crypto::{
    backend::bellman_groth16::{
        engines::{Bn256, Engine},
        BellmanCS, Parameters,
    },
    circuit::cs::BuildCS,
    core::signal::Signal,
    engines::bn256::Fr,
};
use fawkes_crypto_phase2::parameters::MPCParameters;
use fawkes_crypto_zkbob::BorshSerialize;
use std::io::Write;

pub fn setup_circuit<
    E: Engine,
    Pub: Signal<BuildCS<E::Fr>>,
    Sec: Signal<BuildCS<E::Fr>>,
    C: Fn(Pub, Sec),
>(
    circuit: C,
) -> (
    BellmanCS<E, BuildCS<<E as Engine>::Fr>>,
    u32,
    Vec<u8>,
    BitVec,
) {
    let ref rcs = BuildCS::rc_new();
    let signal_pub = Pub::alloc(rcs, None);
    signal_pub.inputize();
    let signal_sec = Sec::alloc(rcs, None);

    circuit(signal_pub, signal_sec);

    let circuit = BellmanCS::<E, BuildCS<E::Fr>>::new(rcs.clone());
    let cs = rcs.borrow();
    let num_gates = cs.gates.len();

    let mut buf = std::io::Cursor::new(vec![]);
    let mut c = brotli::CompressorWriter::new(&mut buf, 4096, 9, 22);
    for g in cs.gates.iter() {
        c.write_all(&g.try_to_vec().unwrap()).unwrap();
    }

    c.flush().unwrap();
    drop(c);

    (
        circuit,
        num_gates as u32,
        buf.into_inner(),
        cs.const_tracker.clone(),
    )
}
