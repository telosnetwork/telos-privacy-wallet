use fawkes_crypto::rand::Rng;
use libzeropool_zkbob::{POOL_PARAMS, circuit::tree::{CTreePub, CTreeSec, tree_update},
    native::tree::{TreePub, TreeSec},
    fawkes_crypto::{
        ff_uint::Num,
        circuit::{
            cs::{CS, DebugCS}
        }, 
        core::signal::Signal,
        rand::thread_rng,
    }, 
};

use std::time::Instant;
use libzeropool_zkbob::helpers::sample_data::HashTreeState;
use libzeropool_zkbob::native::params::PoolParams;
use libzeropool_zkbob::constants::OUTPLUSONELOG;
use libzeropool_zkbob::fawkes_crypto::native::poseidon::poseidon;
use std::panic::{catch_unwind, AssertUnwindSafe};


#[test]
fn test_circuit_tx_fullfill_not_empty(){
    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);
    let num_elements:usize = rng.gen_range(1, 1000);

    for _ in 0..num_elements {
        state.push(rng.gen(), &*POOL_PARAMS);
    }

    let root_before = state.root();
    let proof_filled = state.merkle_proof(num_elements-1);
    let proof_free = state.merkle_proof(num_elements);
    let prev_leaf = state.hashes[0].last().unwrap().clone();
    state.push(rng.gen(), &*POOL_PARAMS);
    let root_after = state.root();
    let leaf = state.hashes[0].last().unwrap().clone();
    


    let p = TreePub {root_before, root_after, leaf};
    let s = TreeSec {proof_filled, proof_free, prev_leaf};


    let ref cs = DebugCS::rc_new();
    let ref p = CTreePub::alloc(cs, Some(&p));
    let ref s = CTreeSec::alloc(cs, Some(&s));

    
    let mut num_gates = cs.borrow().num_gates();
    let start = Instant::now();
    tree_update(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    num_gates=cs.borrow().num_gates()-num_gates;

    println!("tx gates = {}", num_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}

#[test]
fn test_circuit_tx_fullfill_empty(){
    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);


    let root_before = state.root();
    let proof_filled = state.merkle_proof(0);
    let proof_free = state.merkle_proof(0);
    let prev_leaf = Num::ZERO;
    state.push(rng.gen(), &*POOL_PARAMS);
    let root_after = state.root();
    let leaf = state.hashes[0].last().unwrap().clone();
     
    let p = TreePub {root_before, root_after, leaf};
    let s = TreeSec {proof_filled, proof_free, prev_leaf};


    let ref cs = DebugCS::rc_new();
    let ref p = CTreePub::alloc(cs, Some(&p));
    let ref s = CTreeSec::alloc(cs, Some(&s));

    
    let mut num_gates = cs.borrow().num_gates();
    let start = Instant::now();
    tree_update(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    num_gates=cs.borrow().num_gates()-num_gates;

    println!("tx gates = {}", num_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}

#[test]
fn test_circuit_rejects_empty_block_noop() {
    let state = HashTreeState::new(&*POOL_PARAMS);
    let root = state.root();
    let mut empty_block = Num::ZERO;
    for _ in 0..OUTPLUSONELOG {
        empty_block = poseidon(&[empty_block, empty_block], POOL_PARAMS.compress());
    }

    let public = TreePub { root_before: root, root_after: root, leaf: empty_block };
    let secret = TreeSec {
        proof_filled: state.merkle_proof(0),
        proof_free: state.merkle_proof(0),
        prev_leaf: Num::ZERO,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let cs = DebugCS::rc_new();
        let public = CTreePub::alloc(&cs, Some(&public));
        let secret = CTreeSec::alloc(&cs, Some(&secret));
        tree_update(&public, &secret, &*POOL_PARAMS);
    }));
    assert!(result.is_err(), "empty-block no-op satisfied tree_update");
}
