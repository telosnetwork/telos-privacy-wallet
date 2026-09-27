use crate::{constants::{BALANCE_SIZE_BITS, ENERGY_SIZE_BITS, HEIGHT, IN, OUT, POOLID_SIZE_BITS}, fawkes_crypto::{
        native::{
            eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify},
            poseidon::{poseidon, poseidon_merkle_tree_root, poseidon_sponge, MerkleProof},
        },
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField, Uint},
        borsh::{self, BorshSerialize, BorshDeserialize},
    }, native::{
        params::PoolParams,
        note::Note,
        account::Account
    }};
use crate::native::key::canonical_eta_scalar;


use std::fmt::Debug;



#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Tx<Fr:PrimeField> {
    pub input: (Account<Fr>, SizedVec<Note<Fr>, { IN }>),
    pub output: (Account<Fr>, SizedVec<Note<Fr>, { OUT }>)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferPub<Fr:PrimeField> {
    pub root: Num<Fr>,
    pub nullifier: Num<Fr>,
    pub out_commit: Num<Fr>,
    pub delta: Num<Fr>,
    pub memo: Num<Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferSec<Fr:PrimeField> {
    pub tx: Tx<Fr>,
    pub in_proof: (MerkleProof<Fr, { HEIGHT }>, SizedVec<MerkleProof<Fr, { HEIGHT }>, { IN }>),
    pub eddsa_s: Num<Fr>,
    pub eddsa_r: Num<Fr>,
    pub eddsa_a: Num<Fr>,
}

pub fn nullifier_intermediate_hash<P:PoolParams>(account_hash: Num<P::Fr>, eta: Num<P::Fr>, path: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[account_hash, canonical_eta_scalar::<P>(eta), path], params.nullifier_intermediate())
}

pub fn nullifier<P:PoolParams>(account_hash: Num<P::Fr>, eta: Num<P::Fr>, path: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    let intermediate_hash = nullifier_intermediate_hash(account_hash, eta, path, params);
    poseidon(&[account_hash, intermediate_hash], params.compress())
}

pub fn note_hash<P:PoolParams>(note: Note<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(
        &[note.d.to_num(), note.p_d, note.b.to_num(), note.t.to_num()],
        params.note(),
    )
}

/// Legacy misspelling. Always use the five-field account hash used by the
/// transfer circuit, including energy, with the account Poseidon parameters.
#[deprecated(note = "use Account::hash; this misspelled wrapper is retained for compatibility")]
pub fn accout_hash<P:PoolParams>(ac: Account<P::Fr>, params: &P) -> Num<P::Fr> {
    ac.hash(params)
}


pub fn tx_hash<P:PoolParams>(
    in_hash: &[Num<P::Fr>],
    out_commitment: Num<P::Fr>,
    memo: Num<P::Fr>,
    poolid: Num<P::Fr>,
    params: &P,
) -> Num<P::Fr> {
    let data = in_hash.iter().chain([out_commitment, memo, poolid].iter()).cloned().collect::<Vec<_>>();
    poseidon_sponge(&data, params.sponge())
}


pub fn tx_sign<P:PoolParams>(
    sk: Num<P::Fs>,
    tx_hash: Num<P::Fr>,
    params: &P,
) -> (Num<P::Fs>, Num<P::Fr>) {
    eddsaposeidon_sign(sk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn tx_verify<P:PoolParams>(
    s: Num<P::Fs>,
    r: Num<P::Fr>,
    xsk: Num<P::Fr>,
    tx_hash: Num<P::Fr>,
    params: &P,
) -> bool {
    // The subgroup identity has no secret owner: s=0, R=identity verifies for
    // every message when A=identity. Mirror the circuit's nonidentity guard.
    if xsk == Num::ZERO {
        return false;
    }
    eddsaposeidon_verify(s, r, xsk, tx_hash, params.eddsa(), params.jubjub())
}


pub fn out_commitment_hash<P:PoolParams>(items:&[Num<P::Fr>], params: &P) -> Num<P::Fr> {
    assert!(items.len()==OUT+1);
    poseidon_merkle_tree_root(items, params.compress())
}




pub fn parse_delta<Fr:PrimeField>(delta: Num<Fr>) -> (Num<Fr>, Num<Fr>, Num<Fr>, Num<Fr>) {
    fn _parse_uint<U:Uint>(n:&mut NumRepr<U>, len:usize) -> NumRepr<U> {
        let t = *n;
        *n = *n >> len as u32;
        t - (*n << len as u32)
    }

    fn parse_uint<Fr:PrimeField>(n:&mut NumRepr<Fr::Inner>, len:usize) -> Num<Fr> {
        Num::from_uint(_parse_uint(n, len)).unwrap()
    }

    fn parse_int<Fr:PrimeField>(n:&mut NumRepr<Fr::Inner>, len:usize) -> Num<Fr> {
        let two_component_term =  -Num::from_uint(NumRepr::ONE << len as u32).unwrap();
        let r = _parse_uint(n, len);
        if r >> (len as u32 - 1) == NumRepr::ZERO {
            Num::from_uint(r).unwrap()
        } else {
            Num::from_uint(r).unwrap() + two_component_term
        }
    }

    let mut delta_num = delta.to_uint();

    (
        parse_int(&mut delta_num, BALANCE_SIZE_BITS),
        parse_int(&mut delta_num, ENERGY_SIZE_BITS),
        parse_uint(&mut delta_num, HEIGHT),
        parse_uint(&mut delta_num, POOLID_SIZE_BITS),

    )
}


pub fn make_delta<Fr:PrimeField>(v:Num<Fr>, e:Num<Fr>, index:Num<Fr>, poolid:Num<Fr>) -> Num<Fr> {
    fn make_uint<Fr:PrimeField>(s: &mut NumRepr<Fr::Inner>, n:Num<Fr>, len:usize) {
        let r = n.to_uint();
        assert!(r >> len as u32 == NumRepr::ZERO, "out of range");
        *s = (*s << len as u32) + r;
    }

    fn make_int<Fr:PrimeField>(s: &mut NumRepr<Fr::Inner>, n:Num<Fr>, len:usize) {
        let mut r = n.to_uint();
        if r >> (len as u32 - 1) == NumRepr::ZERO {
            *s = (*s << len as u32) + r;
            return;
        }
        r = Num::<Fr>::MODULUS - r;
        if (r - NumRepr::ONE) >> (len as u32 - 1) == NumRepr::ZERO {
            r = (NumRepr::ONE << len as u32) - r;
            *s = (*s << len as u32) + r;
            return;
        }
        
        panic!("out of range");
    }

    let mut s = NumRepr::ZERO;
    make_uint(&mut s, poolid, POOLID_SIZE_BITS);
    make_uint(&mut s, index, HEIGHT);
    make_int(&mut s, e, ENERGY_SIZE_BITS);
    make_int(&mut s, v, BALANCE_SIZE_BITS);

    Num::from_uint(s).unwrap()
}
