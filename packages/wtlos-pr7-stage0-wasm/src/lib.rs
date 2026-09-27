//! Browser-callable, explicitly unsafe Stage 0 wrapper for the pinned PR7 adapter.
//!
//! This crate never loads legacy wallet witness types or accepts arbitrary
//! proving keys. It is a local integration fixture, not a production prover.

use libzeropool_pr7::{
    fawkes_crypto::{
        backend::bellman_groth16::{engines::Bn256, Parameters},
        engines::bn256::{Fr, Fs},
        ff_uint::Num,
    },
    native::tx::{TransferPub, TransferSec},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wtlos_pr7_proof::{
    finalize_private_transfer, finalize_withdrawal, prove_deposit_with_unchecked_key,
    prove_finalized_with_unchecked_key, DepositWitness, PrivateTransferWitness, TransactionProof,
    WithdrawalWitness, SOURCE_TREE,
};

/// SHA-256 of the sealed *unqualified* transfer Stage 0 `mpc-params.bin`.
pub const UNSAFE_TRANSFER_STAGE0_MPC_SHA256: &str =
    "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30";

/// SHA-256 of the source-matched conversion into Fawkes Groth16 Parameters.
/// The conversion test checked the sealed Stage 0 transcript and exact VK.
pub const UNSAFE_TRANSFER_STAGE0_BROWSER_KEY_SHA256: &str =
    "44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1";

fn check_stage0_mpc_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    if hex::encode(Sha256::digest(bytes)) == UNSAFE_TRANSFER_STAGE0_MPC_SHA256 {
        Ok(())
    } else {
        Err("WTLOS PR7 Stage 0 MPC SHA-256 mismatch")
    }
}

fn parse_stage0_browser_key(bytes: &[u8]) -> Result<Parameters<Bn256>, &'static str> {
    if hex::encode(Sha256::digest(bytes)) != UNSAFE_TRANSFER_STAGE0_BROWSER_KEY_SHA256 {
        return Err("WTLOS PR7 converted Stage 0 key SHA-256 mismatch");
    }
    let mut cursor = bytes;
    let inner = Parameters::<Bn256>::read(&mut cursor, true, true)
        .map_err(|_| "invalid PR7 converted Stage 0 key")?;
    if !cursor.is_empty() {
        return Err("trailing PR7 converted Stage 0 key bytes");
    }
    Ok(inner)
}

fn decimal_u64(value: &str) -> Result<u64, JsValue> {
    if value.is_empty()
        || !value.bytes().all(|c| c.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(JsValue::from_str(
            "amount or fee is not canonical decimal u64",
        ));
    }
    value
        .parse()
        .map_err(|_| JsValue::from_str("amount or fee exceeds u64"))
}

fn address20(value: Vec<u8>, field: &str) -> Result<[u8; 20], JsValue> {
    value
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field} must be 20 bytes")))
}

#[derive(Deserialize)]
struct DepositInput {
    public: TransferPub<Fr>,
    secret: TransferSec<Fr>,
    signing_key: Num<Fs>,
    pool_id: u32,
    amount: String,
    fee: String,
    proxy: Vec<u8>,
}

#[derive(Deserialize)]
struct TransferInput {
    public: TransferPub<Fr>,
    secret: TransferSec<Fr>,
    signing_key: Num<Fs>,
    pool_id: u32,
    fee: String,
    proxy: Vec<u8>,
}

#[derive(Deserialize)]
struct WithdrawalInput {
    public: TransferPub<Fr>,
    secret: TransferSec<Fr>,
    signing_key: Num<Fs>,
    pool_id: u32,
    amount: String,
    fee: String,
    recipient: Vec<u8>,
    proxy: Vec<u8>,
}

#[derive(Serialize)]
struct PublicProof<'a> {
    source_tree: &'static str,
    converted_params_sha256: &'static str,
    stage0_mpc_sha256: &'static str,
    unsafe_stage0_only: bool,
    public: &'a TransferPub<Fr>,
    memo: &'a [u8],
    inputs: &'a [Num<Fr>],
    proof: &'a libzeropool_pr7::fawkes_crypto::backend::bellman_groth16::prover::Proof<Bn256>,
}

fn public_proof(value: &TransactionProof) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&PublicProof {
        source_tree: SOURCE_TREE,
        converted_params_sha256: UNSAFE_TRANSFER_STAGE0_BROWSER_KEY_SHA256,
        stage0_mpc_sha256: UNSAFE_TRANSFER_STAGE0_MPC_SHA256,
        unsafe_stage0_only: true,
        public: &value.public,
        memo: &value.memo,
        inputs: &value.public_inputs,
        proof: &value.proof,
    })
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub struct UnsafeStage0Params {
    inner: Parameters<Bn256>,
}

#[wasm_bindgen]
impl UnsafeStage0Params {
    #[wasm_bindgen(js_name = "sourceTree")]
    pub fn source_tree() -> String {
        SOURCE_TREE.to_string()
    }

    #[wasm_bindgen(js_name = "parameterSha256")]
    pub fn parameter_sha256() -> String {
        UNSAFE_TRANSFER_STAGE0_BROWSER_KEY_SHA256.to_string()
    }

    #[wasm_bindgen(js_name = "fromBinary")]
    pub fn from_binary(bytes: &[u8]) -> Result<UnsafeStage0Params, JsValue> {
        let inner = parse_stage0_browser_key(bytes).map_err(JsValue::from_str)?;
        Ok(Self { inner })
    }

    /// This method requires a PR7-native witness object. It cannot accept
    /// legacy `Proof.tx` or legacy `libzkbob-rs` wallet witness values.
    #[wasm_bindgen(js_name = "unsafeStage0Tx")]
    pub fn unsafe_stage0_tx(&self, kind: &str, witness: JsValue) -> Result<JsValue, JsValue> {
        let proof = match kind {
            "deposit" => {
                let input: DepositInput = serde_wasm_bindgen::from_value(witness)?;
                prove_deposit_with_unchecked_key(
                    &self.inner,
                    DepositWitness {
                        public: input.public,
                        secret: input.secret,
                        signing_key: input.signing_key,
                        pool_id: input.pool_id,
                        amount: decimal_u64(&input.amount)?,
                        fee: decimal_u64(&input.fee)?,
                        proxy: address20(input.proxy, "proxy")?,
                    },
                )
                .map_err(|err| JsValue::from_str(&format!("PR7 deposit rejected: {err:?}")))?
            }
            "transfer" => {
                let input: TransferInput = serde_wasm_bindgen::from_value(witness)?;
                let finalized = finalize_private_transfer(PrivateTransferWitness {
                    public: input.public,
                    secret: input.secret,
                    signing_key: input.signing_key,
                    pool_id: input.pool_id,
                    fee: decimal_u64(&input.fee)?,
                    proxy: address20(input.proxy, "proxy")?,
                })
                .map_err(|err| JsValue::from_str(&format!("PR7 transfer rejected: {err:?}")))?;
                prove_finalized_with_unchecked_key(&self.inner, finalized)
            }
            "withdrawal" => {
                let input: WithdrawalInput = serde_wasm_bindgen::from_value(witness)?;
                let finalized = finalize_withdrawal(WithdrawalWitness {
                    public: input.public,
                    secret: input.secret,
                    signing_key: input.signing_key,
                    pool_id: input.pool_id,
                    amount: decimal_u64(&input.amount)?,
                    fee: decimal_u64(&input.fee)?,
                    recipient: address20(input.recipient, "recipient")?,
                    proxy: address20(input.proxy, "proxy")?,
                })
                .map_err(|err| JsValue::from_str(&format!("PR7 withdrawal rejected: {err:?}")))?;
                prove_finalized_with_unchecked_key(&self.inner, finalized)
            }
            _ => return Err(JsValue::from_str("unsupported PR7 transaction kind")),
        };
        public_proof(&proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_and_key_are_the_sealed_stage0_test_identity() {
        assert_eq!(SOURCE_TREE, "7a22196e1d4a791b452a6140bdfa915298f3f1da");
        assert_eq!(UNSAFE_TRANSFER_STAGE0_MPC_SHA256.len(), 64);
        assert_eq!(UNSAFE_TRANSFER_STAGE0_BROWSER_KEY_SHA256.len(), 64);
        assert!(check_stage0_mpc_bytes(b"not the Stage 0 file").is_err());
    }

    #[test]
    fn bound_hash_comparison_is_exact() {
        assert_eq!(
            hex::encode(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(check_stage0_mpc_bytes(b"abc").is_err());
    }

    #[test]
    #[ignore = "explicit opt-in unsafe Stage 0 conversion fixture"]
    fn convert_exact_stage0_for_browser() {
        use fawkes_crypto_phase2::parameters::MPCParameters;
        use libzeropool_pr7::{
            circuit::tx::{c_transfer, CTransferPub, CTransferSec},
            fawkes_crypto::{circuit::cs::BuildCS, core::signal::Signal, BorshSerialize},
            POOL_PARAMS,
        };
        use std::io::Write;

        let path = std::env::var("UNSAFE_PR7_STAGE0_TRANSFER")
            .expect("set exact sealed Stage 0 transfer path");
        let vk_path = std::env::var("UNSAFE_PR7_STAGE0_TRANSFER_VK")
            .expect("set exact sealed Stage 0 transfer VK path");
        let out_path = std::env::var("UNSAFE_PR7_CONVERTED_KEY_OUT")
            .expect("set new converted key output path");
        let bytes = std::fs::read(path).expect("read Stage 0 transfer file");
        check_stage0_mpc_bytes(&bytes).expect("exact sealed Stage 0 digest");
        let mut cursor = bytes.as_slice();
        let mpc = MPCParameters::read(&mut cursor, true, true).expect("checked Stage 0 MPC read");
        assert!(cursor.is_empty(), "trailing Stage 0 MPC bytes");

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
        let parameters = Parameters::<Bn256>(
            mpc.get_params().clone(),
            cs.gates.len() as u32,
            compressed,
            cs.const_tracker.clone(),
        );
        drop(cs);
        let expected_vk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vk_path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(parameters.get_vk()).unwrap(),
            expected_vk
        );
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out_path)
            .expect("create new converted key");
        parameters.write(&mut out).expect("write converted key");
        out.sync_all().expect("flush converted key");
        println!(
            "converted_key_sha256={}",
            hex::encode(Sha256::digest(std::fs::read(&out_path).unwrap()))
        );
    }

    #[test]
    #[ignore = "explicit opt-in unsafe Stage 0 converted key fixture"]
    fn parse_exact_converted_browser_key_and_reject_mutation() {
        let path = std::env::var("UNSAFE_PR7_CONVERTED_KEY")
            .expect("set exact converted Stage 0 key path");
        let bytes = std::fs::read(path).expect("read converted Stage 0 key");
        let parsed = parse_stage0_browser_key(&bytes).expect("parse exact converted Stage 0 key");
        assert_eq!(parsed.1, 196327, "source-matched transfer gate count");
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(parse_stage0_browser_key(&changed).is_err());
        changed[0] ^= 1;
        changed.push(0);
        assert!(parse_stage0_browser_key(&changed).is_err());
    }
}
