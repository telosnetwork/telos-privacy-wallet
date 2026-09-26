//! Synthetic, opt-in funded account proof sequence. Stage 0 is unsafe.
use super::*;
use fawkes_crypto_phase2::parameters::MPCParameters;
use libzeropool_pr7::{
    circuit::{
        tree::{tree_update, CTreePub, CTreeSec},
        tx::{CTransferPub, CTransferSec},
    },
    fawkes_crypto::{
        backend::bellman_groth16::{verifier::verify, Parameters},
        circuit::cs::{BuildCS, DebugCS},
        core::{signal::Signal, sizedvec::SizedVec},
        native::poseidon::{poseidon, poseidon_merkle_proof_root, MerkleProof},
        BorshSerialize,
    },
    native::{
        account::Account,
        boundednum::BoundedNum,
        key::derive_key_p_d,
        note::Note,
        params::PoolParams,
        tree::{TreePub, TreeSec},
        tx::{nullifier, Tx},
    },
};
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    str::FromStr,
};

const POOL_ID: u32 = 40003;
const BALANCE: u64 = 1_000_000_000;
const HALF: u64 = 500_000_000;
const UPPER_HEIGHT: usize = constants::HEIGHT - constants::OUTPLUSONELOG;

fn proxy() -> [u8; 20] {
    let mut proxy = [0; 20];
    proxy[18..].copy_from_slice(&[0xf0, 0x03]);
    proxy
}

fn parse_num(value: &serde_json::Value) -> Num<Fr> {
    Num::<Fr>::from_str(value.as_str().expect("decimal field string")).unwrap()
}

fn zero_note() -> Note<Fr> {
    Note {
        d: BoundedNum::ZERO,
        p_d: Num::ZERO,
        b: BoundedNum::ZERO,
        t: BoundedNum::ZERO,
    }
}

fn dummy_note(eta: Num<Fr>) -> Note<Fr> {
    Note {
        d: BoundedNum::ZERO,
        p_d: derive_key_p_d(Num::ZERO, eta, &*POOL_PARAMS).x,
        b: BoundedNum::ZERO,
        t: BoundedNum::ZERO,
    }
}

fn dummy_proof() -> MerkleProof<Fr, { constants::HEIGHT }> {
    MerkleProof {
        sibling: (0..constants::HEIGHT).map(|_| Num::ZERO).collect(),
        path: (0..constants::HEIGHT).map(|_| false).collect(),
    }
}

struct State {
    leaves: Vec<Num<Fr>>,
    default: Vec<Num<Fr>>,
}

impl State {
    fn new() -> Self {
        let mut default = vec![Num::ZERO];
        for _ in 0..constants::HEIGHT {
            let before = *default.last().unwrap();
            default.push(poseidon(&[before, before], POOL_PARAMS.compress()));
        }
        Self {
            leaves: vec![],
            default,
        }
    }

    fn layers(&self) -> Vec<HashMap<usize, Num<Fr>>> {
        let mut layers: Vec<HashMap<usize, Num<Fr>>> = Vec::with_capacity(UPPER_HEIGHT + 1);
        layers.push(self.leaves.iter().copied().enumerate().collect());
        for height in 0..UPPER_HEIGHT {
            let parents: HashSet<_> = layers[height].keys().map(|index| index >> 1).collect();
            let mut next = HashMap::new();
            for parent in parents {
                let left = *layers[height]
                    .get(&(parent * 2))
                    .unwrap_or(&self.default[constants::OUTPLUSONELOG + height]);
                let right = *layers[height]
                    .get(&(parent * 2 + 1))
                    .unwrap_or(&self.default[constants::OUTPLUSONELOG + height]);
                next.insert(parent, poseidon(&[left, right], POOL_PARAMS.compress()));
            }
            layers.push(next);
        }
        layers
    }

    fn root(&self) -> Num<Fr> {
        *self.layers()[UPPER_HEIGHT]
            .get(&0)
            .unwrap_or(&self.default[constants::HEIGHT])
    }

    fn upper_proof(&self, subtree_index: usize) -> MerkleProof<Fr, UPPER_HEIGHT> {
        let layers = self.layers();
        MerkleProof {
            sibling: (0..UPPER_HEIGHT)
                .map(|height| {
                    *layers[height]
                        .get(&((subtree_index >> height) ^ 1))
                        .unwrap_or(&self.default[constants::OUTPLUSONELOG + height])
                })
                .collect(),
            path: (0..UPPER_HEIGHT)
                .map(|height| ((subtree_index >> height) & 1) == 1)
                .collect(),
        }
    }

    fn account_proof(
        &self,
        subtree_index: usize,
        output_hashes: &[Num<Fr>],
    ) -> MerkleProof<Fr, { constants::HEIGHT }> {
        assert_eq!(output_hashes.len(), 1 << constants::OUTPLUSONELOG);
        assert_eq!(
            self.leaves[subtree_index],
            out_commitment_hash(output_hashes, &*POOL_PARAMS)
        );
        let mut layer = output_hashes.to_vec();
        let mut lower_siblings = Vec::new();
        for _ in 0..constants::OUTPLUSONELOG {
            lower_siblings.push(layer[1]);
            layer = layer
                .chunks_exact(2)
                .map(|pair| poseidon(pair, POOL_PARAMS.compress()))
                .collect();
        }
        assert_eq!(layer[0], self.leaves[subtree_index]);
        let upper = self.upper_proof(subtree_index);
        let proof = MerkleProof {
            sibling: lower_siblings
                .into_iter()
                .chain(upper.sibling.iter().copied())
                .collect(),
            path: (0..constants::OUTPLUSONELOG)
                .map(|_| false)
                .chain(upper.path.iter().copied())
                .collect(),
        };
        assert_eq!(
            poseidon_merkle_proof_root(output_hashes[0], &proof, POOL_PARAMS.compress()),
            self.root()
        );
        proof
    }

    fn note_proof(
        &self,
        subtree_index: usize,
        output_hashes: &[Num<Fr>],
        note_slot: usize,
    ) -> MerkleProof<Fr, { constants::HEIGHT }> {
        let item_index = note_slot + 1;
        assert!(item_index < output_hashes.len());
        assert_eq!(
            self.leaves[subtree_index],
            out_commitment_hash(output_hashes, &*POOL_PARAMS)
        );
        let mut layer = output_hashes.to_vec();
        let mut lower_siblings = Vec::new();
        let mut lower_path = Vec::new();
        for height in 0..constants::OUTPLUSONELOG {
            lower_siblings.push(layer[(item_index >> height) ^ 1]);
            lower_path.push(((item_index >> height) & 1) == 1);
            layer = layer
                .chunks_exact(2)
                .map(|pair| poseidon(pair, POOL_PARAMS.compress()))
                .collect();
        }
        assert_eq!(layer[0], self.leaves[subtree_index]);
        let upper = self.upper_proof(subtree_index);
        let proof = MerkleProof {
            sibling: lower_siblings
                .into_iter()
                .chain(upper.sibling.iter().copied())
                .collect(),
            path: lower_path
                .into_iter()
                .chain(upper.path.iter().copied())
                .collect(),
        };
        assert_eq!(
            poseidon_merkle_proof_root(output_hashes[item_index], &proof, POOL_PARAMS.compress()),
            self.root()
        );
        proof
    }

    fn append_witness(&mut self, leaf: Num<Fr>) -> (TreePub<Fr>, TreeSec<Fr>) {
        let before = self.root();
        let index = self.leaves.len();
        let free = self.upper_proof(index);
        let filled = if index == 0 {
            free.clone()
        } else {
            self.upper_proof(index - 1)
        };
        let prev_leaf = if index == 0 {
            self.default[constants::OUTPLUSONELOG]
        } else {
            self.leaves[index - 1]
        };
        assert_eq!(
            poseidon_merkle_proof_root(
                self.default[constants::OUTPLUSONELOG],
                &free,
                POOL_PARAMS.compress()
            ),
            before
        );
        self.leaves.push(leaf);
        let after = self.root();
        assert_eq!(
            poseidon_merkle_proof_root(leaf, &free, POOL_PARAMS.compress()),
            after
        );
        (
            TreePub {
                root_before: before,
                root_after: after,
                leaf,
            },
            TreeSec {
                proof_filled: filled,
                proof_free: free,
                prev_leaf,
            },
        )
    }
}

fn output_hashes(
    account: Account<Fr>,
    notes: &SizedVec<Note<Fr>, { constants::OUT }>,
) -> Vec<Num<Fr>> {
    std::iter::once(account.hash(&*POOL_PARAMS))
        .chain(notes.iter().map(|note| note.hash(&*POOL_PARAMS)))
        .collect()
}

fn signed_secret(
    input: Account<Fr>,
    output: Account<Fr>,
    output_notes: SizedVec<Note<Fr>, { constants::OUT }>,
    account_proof: MerkleProof<Fr, { constants::HEIGHT }>,
    signer: Num<Fs>,
) -> TransferSec<Fr> {
    let eta = derive_key_eta(derive_key_a(signer, &*POOL_PARAMS).x, &*POOL_PARAMS);
    TransferSec {
        tx: Tx {
            input: (input, (0..constants::IN).map(|_| dummy_note(eta)).collect()),
            output: (output, output_notes),
        },
        in_proof: (
            account_proof,
            (0..constants::IN).map(|_| dummy_proof()).collect(),
        ),
        eddsa_s: Num::ZERO,
        eddsa_r: Num::ZERO,
        eddsa_a: derive_key_a(signer, &*POOL_PARAMS).x,
    }
}

fn read_stage(path_var: &str, expected_hash: &str) -> MPCParameters {
    let path = std::env::var(path_var).expect("Stage 0 path required");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        expected_hash,
        "wrong Stage 0 bytes"
    );
    let mut reader = bytes.as_slice();
    let mpc = MPCParameters::read(&mut reader, true, true).unwrap();
    assert_eq!(
        reader.read(&mut [0u8; 1]).unwrap(),
        0,
        "trailing Stage 0 bytes"
    );
    mpc
}

fn transfer_parameters(mpc: &MPCParameters) -> Parameters<Bn256> {
    let cs = BuildCS::<Fr>::rc_new();
    let public = CTransferPub::alloc(&cs, None);
    public.inputize();
    let secret = CTransferSec::alloc(&cs, None);
    c_transfer(&public, &secret, &*POOL_PARAMS);
    let cs = cs.borrow();
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 9, 22);
        for gate in &cs.gates {
            writer.write_all(&gate.try_to_vec().unwrap()).unwrap();
        }
        writer.flush().unwrap();
    }
    Parameters::<Bn256>(
        mpc.get_params().clone(),
        cs.gates.len() as u32,
        compressed,
        cs.const_tracker.clone(),
    )
}

fn tree_parameters(mpc: &MPCParameters) -> Parameters<Bn256> {
    let cs = BuildCS::<Fr>::rc_new();
    let public = CTreePub::alloc(&cs, None);
    public.inputize();
    let secret = CTreeSec::alloc(&cs, None);
    tree_update(&public, &secret, &*POOL_PARAMS);
    let cs = cs.borrow();
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 9, 22);
        for gate in &cs.gates {
            writer.write_all(&gate.try_to_vec().unwrap()).unwrap();
        }
        writer.flush().unwrap();
    }
    Parameters::<Bn256>(
        mpc.get_params().clone(),
        cs.gates.len() as u32,
        compressed,
        cs.const_tracker.clone(),
    )
}

#[test]
#[ignore = "explicit opt-in unsafe Stage 0 funded flow; never use for production"]
fn unsafe_current_stagezero_funded_flow_proof() {
    const TRANSFER_STAGE_HASH: &str =
        "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30";
    const TREE_STAGE_HASH: &str =
        "6fa8054b88077e4f531eb3e7fcf094ea9e2746672ea2788f816b2c4a13f3e68f";
    let deposit_path =
        std::env::var("UNSAFE_PR7_FIRST_DEPOSIT_PROOF").expect("accepted deposit fixture required");
    let deposit_bytes = std::fs::read(deposit_path).unwrap();
    let deposit: serde_json::Value = serde_json::from_slice(&deposit_bytes).unwrap();
    assert_eq!(
        deposit["schema"],
        "telos-pr7-wallet-adapter-unsafe-deposit-proof-v1"
    );
    assert_eq!(deposit["sourceTree"], SOURCE_TREE);
    assert_eq!(deposit["stage0Sha256"], TRANSFER_STAGE_HASH);
    assert_eq!(deposit["treeUpdate"]["stage0Sha256"], TREE_STAGE_HASH);
    assert_eq!(deposit["testOnly"], true);
    assert_eq!(deposit["unsafeZeroContribution"], true);
    assert_eq!(deposit["verifiedAgainstSealedStage0Vk"], true);
    assert_eq!(deposit["treeUpdate"]["verifiedAgainstSealedStage0Vk"], true);
    assert_eq!(deposit["poolId"], POOL_ID);
    assert_eq!(
        deposit["poolAddress"],
        "0x000000000000000000000000000000000000F003"
    );
    let first_inputs = deposit["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    let first_tree_inputs = deposit["treeUpdate"]["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    assert_eq!(first_inputs.len(), 5);
    assert_eq!(first_tree_inputs.len(), 3);
    assert_eq!(first_inputs[2], first_tree_inputs[2]);
    assert_eq!(first_inputs[0], first_tree_inputs[0]);
    let first_memo = hex::decode(
        deposit["memoDataHex"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let memo_hash = Keccak256::digest(&first_memo);
    assert_eq!(
        first_inputs[4],
        Num::<Fr>::from_uint_reduced(NumRepr(Uint::from_big_endian(&memo_hash)))
    );
    assert_eq!(&first_memo[..8], &[0u8; 8]);
    let raw_ciphertext = domain::strip_domain(&first_memo[8..], &proxy()).unwrap();
    let signer = Num::<Fs>::from(23u64);
    let eta = derive_key_eta(derive_key_a(signer, &*POOL_PARAMS).x, &*POOL_PARAMS);
    let (first_account, first_notes) =
        cipher::decrypt_out(eta, &raw_ciphertext, &*POOL_PARAMS).unwrap();
    assert!(first_notes.is_empty());
    assert_eq!(first_account.i.to_num(), Num::ZERO);
    assert_eq!(first_account.b.to_num(), Num::from(BALANCE));
    let first_notes: SizedVec<Note<Fr>, { constants::OUT }> =
        (0..constants::OUT).map(|_| zero_note()).collect();
    let first_hashes = output_hashes(first_account, &first_notes);
    assert_eq!(
        out_commitment_hash(&first_hashes, &*POOL_PARAMS),
        first_inputs[2]
    );
    let mut state = State::new();
    assert_eq!(state.root(), first_inputs[0]);
    let (first_tree_public, _) = state.append_witness(first_inputs[2]);
    assert_eq!(first_tree_public.root_after, first_tree_inputs[1]);

    let transfer_mpc = read_stage("UNSAFE_PR7_STAGE0_TRANSFER", TRANSFER_STAGE_HASH);
    let transfer_parameters = transfer_parameters(&transfer_mpc);
    let transfer_vk = transfer_parameters.get_vk();
    let expected_vk: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(std::env::var("UNSAFE_PR7_STAGE0_TRANSFER_VK").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&transfer_vk).unwrap(),
        expected_vk,
        "wrong transfer VK"
    );
    let tree_mpc = read_stage("UNSAFE_PR7_STAGE0_TREE", TREE_STAGE_HASH);
    let tree_parameters = tree_parameters(&tree_mpc);
    let tree_vk = tree_parameters.get_vk();
    let expected_tree_vk: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(std::env::var("UNSAFE_PR7_STAGE0_TREE_VK").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&tree_vk).unwrap(),
        expected_tree_vk,
        "wrong tree VK"
    );

    let recipient_signer = Num::<Fs>::from(37u64);
    let recipient_eta = derive_key_eta(
        derive_key_a(recipient_signer, &*POOL_PARAMS).x,
        &*POOL_PARAMS,
    );
    let note_d = BoundedNum::new(Num::from(29u64));
    let recipient_note = Note {
        d: note_d,
        p_d: derive_key_p_d(note_d.to_num(), recipient_eta, &*POOL_PARAMS).x,
        b: BoundedNum::new(Num::from(HALF)),
        t: BoundedNum::new(Num::from(77u64)),
    };
    assert_ne!(recipient_note.p_d, Num::ZERO);
    let transfer_notes: SizedVec<Note<Fr>, { constants::OUT }> = std::iter::once(recipient_note)
        .chain((1..constants::OUT).map(|_| zero_note()))
        .collect();
    let next_d = BoundedNum::new(Num::from(18u64));
    let second_account = Account {
        d: next_d,
        p_d: derive_key_p_d(next_d.to_num(), eta, &*POOL_PARAMS).x,
        i: BoundedNum::new(Num::from(128u64)),
        b: BoundedNum::new(Num::from(HALF)),
        e: BoundedNum::new(Num::from(128 * BALANCE)),
    };
    let second_hashes = output_hashes(second_account, &transfer_notes);
    let second_commit = out_commitment_hash(&second_hashes, &*POOL_PARAMS);
    let transfer_witness = PrivateTransferWitness {
        public: TransferPub {
            root: state.root(),
            nullifier: nullifier(
                first_account.hash(&*POOL_PARAMS),
                eta,
                Num::ZERO,
                &*POOL_PARAMS,
            ),
            out_commit: second_commit,
            delta: make_delta(Num::ZERO, Num::ZERO, Num::from(128u64), Num::from(POOL_ID)),
            memo: Num::ZERO,
        },
        secret: signed_secret(
            first_account,
            second_account,
            transfer_notes.clone(),
            state.account_proof(0, &first_hashes),
            signer,
        ),
        signing_key: signer,
        pool_id: POOL_ID,
        fee: 0,
        proxy: proxy(),
    };
    let finalized_transfer = finalize_private_transfer(transfer_witness).unwrap();
    assert_eq!(&finalized_transfer.memo[..8], &[0u8; 8]);
    let decrypted_transfer = domain::strip_domain(&finalized_transfer.memo[8..], &proxy()).unwrap();
    let (recovered_account, recovered_notes) =
        cipher::decrypt_out(eta, &decrypted_transfer, &*POOL_PARAMS).unwrap();
    assert_eq!(recovered_account, second_account);
    assert_eq!(recovered_notes, vec![recipient_note]);
    let cs = DebugCS::rc_new();
    let public = CTransferPub::alloc(&cs, Some(&finalized_transfer.public));
    let secret = CTransferSec::alloc(&cs, Some(&finalized_transfer.secret));
    c_transfer(&public, &secret, &*POOL_PARAMS);
    let transfer_result =
        prove_finalized_with_unchecked_key(&transfer_parameters, finalized_transfer);
    assert!(verify(
        &transfer_vk,
        &transfer_result.proof,
        &transfer_result.public_inputs
    ));
    let (transfer_tree_pub, transfer_tree_sec) = state.append_witness(second_commit);
    let (transfer_tree_inputs, transfer_tree_proof) = prove(
        &tree_parameters,
        &transfer_tree_pub,
        &transfer_tree_sec,
        |public, secret| tree_update(&public, &secret, &*POOL_PARAMS),
    );
    assert!(verify(
        &tree_vk,
        &transfer_tree_proof,
        &transfer_tree_inputs
    ));
    assert_eq!(transfer_result.public_inputs[0], first_tree_inputs[1]);
    assert_eq!(transfer_result.public_inputs[2], transfer_tree_inputs[2]);
    assert_eq!(transfer_tree_inputs[0], first_tree_inputs[1]);

    let final_d = BoundedNum::new(Num::from(19u64));
    let final_account = Account {
        d: final_d,
        p_d: derive_key_p_d(final_d.to_num(), eta, &*POOL_PARAMS).x,
        i: BoundedNum::new(Num::from(256u64)),
        b: BoundedNum::ZERO,
        e: BoundedNum::new(Num::from(192 * BALANCE)),
    };
    let final_notes: SizedVec<Note<Fr>, { constants::OUT }> =
        (0..constants::OUT).map(|_| zero_note()).collect();
    let final_hashes = output_hashes(final_account, &final_notes);
    let mut recipient = [0u8; 20];
    recipient[18..].copy_from_slice(&[0xbe, 0xef]);
    let withdrawal_witness = WithdrawalWitness {
        public: TransferPub {
            root: state.root(),
            nullifier: nullifier(
                second_account.hash(&*POOL_PARAMS),
                eta,
                Num::from(128u64),
                &*POOL_PARAMS,
            ),
            out_commit: out_commitment_hash(&final_hashes, &*POOL_PARAMS),
            delta: make_delta(
                -Num::from(HALF),
                Num::ZERO,
                Num::from(256u64),
                Num::from(POOL_ID),
            ),
            memo: Num::ZERO,
        },
        secret: signed_secret(
            second_account,
            final_account,
            final_notes,
            state.account_proof(1, &second_hashes),
            signer,
        ),
        signing_key: signer,
        pool_id: POOL_ID,
        amount: HALF,
        fee: 0,
        recipient,
        proxy: proxy(),
    };
    let finalized_withdrawal = finalize_withdrawal(withdrawal_witness).unwrap();
    assert_eq!(&finalized_withdrawal.memo[..16], &[0u8; 16]);
    assert_eq!(&finalized_withdrawal.memo[16..36], &recipient);
    let cs = DebugCS::rc_new();
    let public = CTransferPub::alloc(&cs, Some(&finalized_withdrawal.public));
    let secret = CTransferSec::alloc(&cs, Some(&finalized_withdrawal.secret));
    c_transfer(&public, &secret, &*POOL_PARAMS);
    let withdrawal_result =
        prove_finalized_with_unchecked_key(&transfer_parameters, finalized_withdrawal);
    assert!(verify(
        &transfer_vk,
        &withdrawal_result.proof,
        &withdrawal_result.public_inputs
    ));
    let (withdraw_tree_pub, withdraw_tree_sec) =
        state.append_witness(withdrawal_result.public.out_commit);
    let (withdraw_tree_inputs, withdraw_tree_proof) = prove(
        &tree_parameters,
        &withdraw_tree_pub,
        &withdraw_tree_sec,
        |public, secret| tree_update(&public, &secret, &*POOL_PARAMS),
    );
    assert!(verify(
        &tree_vk,
        &withdraw_tree_proof,
        &withdraw_tree_inputs
    ));
    assert_eq!(withdrawal_result.public_inputs[0], transfer_tree_inputs[1]);
    assert_eq!(withdrawal_result.public_inputs[2], withdraw_tree_inputs[2]);
    assert_eq!(withdraw_tree_inputs[0], transfer_tree_inputs[1]);

    let operation = |kind: &str,
                     proof: TransactionProof,
                     tree_inputs: Vec<Num<Fr>>,
                     tree_proof: Proof<Bn256>| {
        serde_json::json!({
            "kind": kind,
            "memoDataHex": format!("0x{}", hex::encode(proof.memo)),
            "publicInputs": proof.public_inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "proof": proof.proof,
            "treeUpdate": {
                "publicInputs": tree_inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "proof": tree_proof,
                "verifiedAgainstSealedStage0Vk": true,
            },
            "verifiedAgainstSealedStage0Vk": true,
        })
    };
    let output = serde_json::json!({
        "schema": "telos-pr7-wallet-adapter-unsafe-funded-flow-v1",
        "testOnly": true,
        "unsafeZeroContribution": true,
        "sourceTree": SOURCE_TREE,
        "transferStage0Sha256": TRANSFER_STAGE_HASH,
        "treeStage0Sha256": TREE_STAGE_HASH,
        "firstDepositProofSha256": hex::encode(Sha256::digest(&deposit_bytes)),
        "poolId": POOL_ID,
        "poolAddress": "0x000000000000000000000000000000000000F003",
        "recipient": "0x000000000000000000000000000000000000bEEF",
        "operations": [
            operation("transfer", transfer_result, transfer_tree_inputs, transfer_tree_proof),
            operation("withdraw", withdrawal_result, withdraw_tree_inputs, withdraw_tree_proof),
        ],
    });
    let out_path =
        std::env::var("UNSAFE_PR7_FUNDED_FLOW_OUT").expect("new funded-flow output path required");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_path)
        .unwrap();
    serde_json::to_writer_pretty(&mut file, &output).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}

/// A separately derived recipient key discovers the exact funded transfer
/// memo and spends its physical note at global position 129. The previous
/// three proofs are pinned sealed inputs, not regenerated in this test.
#[test]
#[ignore = "explicit opt-in unsafe Stage 0 recipient-note spend; never use for production"]
fn unsafe_current_stagezero_recipient_note_spend() {
    const TRANSFER_STAGE_HASH: &str =
        "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30";
    const TREE_STAGE_HASH: &str =
        "6fa8054b88077e4f531eb3e7fcf094ea9e2746672ea2788f816b2c4a13f3e68f";
    const PRIOR_FUNDED_HASH: &str =
        "9d8fe1ee19caec796c8f94c77d224a1d646c62d0b6a8e682d32815511bf0e2c7";
    const DEPOSIT_HASH: &str = "e5f938e84ef9bfa22275e7d996c5d911a6b8750e0963c281149545e728e24107";

    let deposit_bytes = std::fs::read(
        std::env::var("UNSAFE_PR7_FIRST_DEPOSIT_PROOF").expect("sealed first deposit path"),
    )
    .unwrap();
    assert_eq!(hex::encode(Sha256::digest(&deposit_bytes)), DEPOSIT_HASH);
    let deposit: serde_json::Value = serde_json::from_slice(&deposit_bytes).unwrap();
    assert_eq!(deposit["sourceTree"], SOURCE_TREE);
    let first_inputs = deposit["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    let first_tree_inputs = deposit["treeUpdate"]["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    let first_memo = hex::decode(
        deposit["memoDataHex"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let sender_key = Num::<Fs>::from(23u64);
    let sender_eta = derive_key_eta(derive_key_a(sender_key, &*POOL_PARAMS).x, &*POOL_PARAMS);
    let first_raw = domain::strip_domain(&first_memo[8..], &proxy()).unwrap();
    let (first_account, first_decrypted_notes) =
        cipher::decrypt_out(sender_eta, &first_raw, &*POOL_PARAMS).unwrap();
    assert!(first_decrypted_notes.is_empty());
    let zero_notes: SizedVec<Note<Fr>, { constants::OUT }> =
        (0..constants::OUT).map(|_| zero_note()).collect();
    let first_hashes = output_hashes(first_account, &zero_notes);
    assert_eq!(
        out_commitment_hash(&first_hashes, &*POOL_PARAMS),
        first_inputs[2]
    );
    let mut state = State::new();
    assert_eq!(state.root(), first_inputs[0]);
    let (first_tree, _) = state.append_witness(first_inputs[2]);
    assert_eq!(first_tree.root_after, first_tree_inputs[1]);

    let prior_bytes = std::fs::read(
        std::env::var("UNSAFE_PR7_FUNDED_PROOFS").expect("sealed funded-flow proof path"),
    )
    .unwrap();
    assert_eq!(hex::encode(Sha256::digest(&prior_bytes)), PRIOR_FUNDED_HASH);
    let prior: serde_json::Value = serde_json::from_slice(&prior_bytes).unwrap();
    assert_eq!(
        prior["schema"],
        "telos-pr7-wallet-adapter-unsafe-funded-flow-v1"
    );
    assert_eq!(prior["sourceTree"], SOURCE_TREE);
    assert_eq!(prior["firstDepositProofSha256"], DEPOSIT_HASH);
    assert_eq!(prior["transferStage0Sha256"], TRANSFER_STAGE_HASH);
    assert_eq!(prior["treeStage0Sha256"], TREE_STAGE_HASH);
    assert_eq!(prior["testOnly"], true);
    assert_eq!(prior["unsafeZeroContribution"], true);
    let prior_operations = prior["operations"].as_array().unwrap();
    assert_eq!(prior_operations.len(), 2);
    assert_eq!(prior_operations[0]["kind"], "transfer");
    assert_eq!(prior_operations[1]["kind"], "withdraw");

    let recipient_key = Num::<Fs>::from(37u64);
    let recipient_eta = derive_key_eta(derive_key_a(recipient_key, &*POOL_PARAMS).x, &*POOL_PARAMS);
    let note_d = BoundedNum::new(Num::from(29u64));
    let recipient_note = Note {
        d: note_d,
        p_d: derive_key_p_d(note_d.to_num(), recipient_eta, &*POOL_PARAMS).x,
        b: BoundedNum::new(Num::from(HALF)),
        t: BoundedNum::new(Num::from(77u64)),
    };
    let transfer_memo = hex::decode(
        prior_operations[0]["memoDataHex"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let transfer_raw = domain::strip_domain(&transfer_memo[8..], &proxy()).unwrap();
    let receiver_incoming = cipher::decrypt_in(recipient_eta, &transfer_raw, &*POOL_PARAMS);
    assert_eq!(
        receiver_incoming,
        vec![Some(recipient_note)],
        "recipient cannot decrypt exact funded note"
    );
    let sender_incoming = cipher::decrypt_in(sender_eta, &transfer_raw, &*POOL_PARAMS);
    assert_eq!(
        sender_incoming,
        vec![None],
        "sender must not decrypt as the incoming-note recipient"
    );
    // The sender may still inspect their own outgoing note with decrypt_out.
    let (sender_outgoing_account, sender_outgoing_notes) =
        cipher::decrypt_out(sender_eta, &transfer_raw, &*POOL_PARAMS).unwrap();
    assert_eq!(sender_outgoing_notes, vec![recipient_note]);

    let transfer_inputs = prior_operations[0]["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    let transfer_tree_inputs = prior_operations[0]["treeUpdate"]["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    assert_eq!(transfer_inputs[0], state.root());
    assert_eq!(
        transfer_inputs[4],
        Num::<Fr>::from_uint_reduced(NumRepr(Uint::from_big_endian(&Keccak256::digest(
            &transfer_memo
        ))))
    );
    let transfer_notes: SizedVec<Note<Fr>, { constants::OUT }> = std::iter::once(recipient_note)
        .chain((1..constants::OUT).map(|_| zero_note()))
        .collect();
    let transfer_hashes = output_hashes(sender_outgoing_account, &transfer_notes);
    let transfer_commit = out_commitment_hash(&transfer_hashes, &*POOL_PARAMS);
    assert_eq!(transfer_commit, transfer_inputs[2]);
    let (second_tree, _) = state.append_witness(transfer_commit);
    assert_eq!(second_tree.root_after, transfer_tree_inputs[1]);
    assert_eq!(transfer_tree_inputs[2], transfer_commit);

    let sender_final_d = BoundedNum::new(Num::from(19u64));
    let sender_final = Account {
        d: sender_final_d,
        p_d: derive_key_p_d(sender_final_d.to_num(), sender_eta, &*POOL_PARAMS).x,
        i: BoundedNum::new(Num::from(256u64)),
        b: BoundedNum::ZERO,
        e: BoundedNum::new(Num::from(192 * BALANCE)),
    };
    let final_hashes = output_hashes(sender_final, &zero_notes);
    let sender_withdraw_inputs = prior_operations[1]["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    let sender_withdraw_tree_inputs = prior_operations[1]["treeUpdate"]["publicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_num)
        .collect::<Vec<_>>();
    assert_eq!(sender_withdraw_inputs[0], state.root());
    assert_eq!(
        sender_withdraw_inputs[2],
        out_commitment_hash(&final_hashes, &*POOL_PARAMS)
    );
    let (third_tree, _) = state.append_witness(sender_withdraw_inputs[2]);
    assert_eq!(third_tree.root_after, sender_withdraw_tree_inputs[1]);
    assert_eq!(sender_withdraw_tree_inputs[2], sender_withdraw_inputs[2]);

    let note_proof = state.note_proof(1, &transfer_hashes, 0);
    let note_position = note_proof
        .path
        .iter()
        .enumerate()
        .fold(0u64, |index, (bit, is_set)| {
            if *is_set {
                index | (1u64 << bit)
            } else {
                index
            }
        });
    assert_eq!(note_position, 129);
    let initial_d = BoundedNum::new(Num::from(POOL_ID));
    let initial_account = Account {
        d: initial_d,
        p_d: derive_key_p_d(initial_d.to_num(), recipient_eta, &*POOL_PARAMS).x,
        i: BoundedNum::ZERO,
        b: BoundedNum::ZERO,
        e: BoundedNum::ZERO,
    };
    let output_d = BoundedNum::new(Num::from(41u64));
    let output_account = Account {
        d: output_d,
        p_d: derive_key_p_d(output_d.to_num(), recipient_eta, &*POOL_PARAMS).x,
        i: BoundedNum::new(Num::from(384u64)),
        b: BoundedNum::ZERO,
        e: BoundedNum::new(Num::from(HALF * (384 - 129))),
    };
    let output_hashes = output_hashes(output_account, &zero_notes);
    let recipient_secret = TransferSec {
        tx: Tx {
            input: (
                initial_account,
                std::iter::once(recipient_note)
                    .chain((1..constants::IN).map(|_| dummy_note(recipient_eta)))
                    .collect(),
            ),
            output: (output_account, zero_notes),
        },
        in_proof: (
            dummy_proof(),
            std::iter::once(note_proof)
                .chain((1..constants::IN).map(|_| dummy_proof()))
                .collect(),
        ),
        eddsa_s: Num::ZERO,
        eddsa_r: Num::ZERO,
        eddsa_a: derive_key_a(recipient_key, &*POOL_PARAMS).x,
    };
    let mut public_recipient = [0u8; 20];
    public_recipient[18..].copy_from_slice(&[0xca, 0xfe]);
    let witness = WithdrawalWitness {
        public: TransferPub {
            root: state.root(),
            nullifier: nullifier(
                initial_account.hash(&*POOL_PARAMS),
                recipient_eta,
                Num::ZERO,
                &*POOL_PARAMS,
            ),
            out_commit: out_commitment_hash(&output_hashes, &*POOL_PARAMS),
            delta: make_delta(
                -Num::from(HALF),
                Num::ZERO,
                Num::from(384u64),
                Num::from(POOL_ID),
            ),
            memo: Num::ZERO,
        },
        secret: recipient_secret,
        signing_key: recipient_key,
        pool_id: POOL_ID,
        amount: HALF,
        fee: 0,
        recipient: public_recipient,
        proxy: proxy(),
    };
    let finalized = finalize_withdrawal(witness).unwrap();
    assert_eq!(&finalized.memo[16..36], &public_recipient);
    let cs = DebugCS::rc_new();
    let public = CTransferPub::alloc(&cs, Some(&finalized.public));
    let secret = CTransferSec::alloc(&cs, Some(&finalized.secret));
    c_transfer(&public, &secret, &*POOL_PARAMS);

    let transfer_mpc = read_stage("UNSAFE_PR7_STAGE0_TRANSFER", TRANSFER_STAGE_HASH);
    let transfer_parameters = transfer_parameters(&transfer_mpc);
    let transfer_vk = transfer_parameters.get_vk();
    let expected_vk: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(std::env::var("UNSAFE_PR7_STAGE0_TRANSFER_VK").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(&transfer_vk).unwrap(), expected_vk);
    let result = prove_finalized_with_unchecked_key(&transfer_parameters, finalized);
    assert!(verify(&transfer_vk, &result.proof, &result.public_inputs));
    assert_eq!(result.public_inputs[0], sender_withdraw_tree_inputs[1]);
    assert_ne!(result.public_inputs[1], first_inputs[1]);
    assert_ne!(result.public_inputs[1], transfer_inputs[1]);
    assert_ne!(result.public_inputs[1], sender_withdraw_inputs[1]);

    let tree_mpc = read_stage("UNSAFE_PR7_STAGE0_TREE", TREE_STAGE_HASH);
    let tree_parameters = tree_parameters(&tree_mpc);
    let tree_vk = tree_parameters.get_vk();
    let expected_tree_vk: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(std::env::var("UNSAFE_PR7_STAGE0_TREE_VK").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(&tree_vk).unwrap(), expected_tree_vk);
    let (tree_public, tree_secret) = state.append_witness(result.public.out_commit);
    let (tree_inputs, tree_proof) = prove(
        &tree_parameters,
        &tree_public,
        &tree_secret,
        |public, secret| tree_update(&public, &secret, &*POOL_PARAMS),
    );
    assert!(verify(&tree_vk, &tree_proof, &tree_inputs));
    assert_eq!(tree_inputs[0], result.public_inputs[0]);
    assert_eq!(tree_inputs[2], result.public_inputs[2]);

    let output = serde_json::json!({
        "schema": "telos-pr7-wallet-adapter-unsafe-recipient-spend-v1",
        "testOnly": true,
        "unsafeZeroContribution": true,
        "sourceTree": SOURCE_TREE,
        "transferStage0Sha256": TRANSFER_STAGE_HASH,
        "treeStage0Sha256": TREE_STAGE_HASH,
        "firstDepositProofSha256": DEPOSIT_HASH,
        "previousFundedProofSha256": PRIOR_FUNDED_HASH,
        "poolId": POOL_ID,
        "poolAddress": "0x000000000000000000000000000000000000F003",
        "notePosition": 129,
        "noteValueZkUnits": HALF,
        "receiverDecryptMatches": true,
        "senderIncomingDecryptRejected": true,
        "kind": "withdraw",
        "recipient": "0x000000000000000000000000000000000000cAFE",
        "memoDataHex": format!("0x{}", hex::encode(result.memo)),
        "publicInputs": result.public_inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "proof": result.proof,
        "treeUpdate": {
            "publicInputs": tree_inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "proof": tree_proof,
            "verifiedAgainstSealedStage0Vk": true,
        },
        "verifiedAgainstSealedStage0Vk": true,
    });
    let out_path =
        std::env::var("UNSAFE_PR7_RECIPIENT_SPEND_OUT").expect("new recipient spend output path");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_path)
        .unwrap();
    serde_json::to_writer_pretty(&mut file, &output).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
