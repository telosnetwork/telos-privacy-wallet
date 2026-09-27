mod evm_verifier;
mod circuit_identity;
mod ceremony_input;
mod ceremony_verify;
#[cfg(unix)]
mod ceremony_contribute;

use libzeropool_zkbob::{
    circuit::delegated_deposit::{
        check_delegated_deposit_batch, CDelegatedDepositBatchPub, CDelegatedDepositBatchSec,
    },
    circuit::tree::{tree_update, CTreePub, CTreeSec},
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    clap::Clap,
    POOL_PARAMS,
};

use fawkes_crypto::backend::bellman_groth16::{
    prover::{prove, Proof},
    verifier::{verify, VK},
    Parameters,
};
use fawkes_crypto::circuit::cs::CS;
use fawkes_crypto::engines::bn256::Fr;
use fawkes_crypto::ff_uint::Num;
use fawkes_crypto::rand::rngs::OsRng;
use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use libzeropool_zkbob::helpers::sample_data::{
    random_sample_delegated_deposit, random_sample_tree_update, State,
};

#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Generate a SNARK proof
    Prove(ProveOpts),
    /// Verify a SNARK proof
    Verify(VerifyOpts),
    /// Generate trusted setup parameters
    Setup(SetupOpts),
    /// Generate trusted setup parameters
    Contribute(ContributeOpts),
    /// Generate trusted setup parameters
    GenerateVK(GenerateVKOpts),
    /// Generate verifier smart contract
    GenerateVerifier(GenerateVerifierOpts),
    /// Generate test object
    GenerateTestData(GenerateTestDataOpts),
    /// Read-only circuit-bound verification of a Phase 2 transcript.
    VerifyCeremony(ceremony_verify::VerifyCeremonyOpts),
    /// Create an unsafe, zero-contribution Phase 2 stage from an approved public radix.
    #[cfg(unix)]
    InitializePhase2(ceremony_contribute::InitializeOpts),
    /// Offline private-entropy contribution to a new immutable Phase 2 stage.
    #[cfg(unix)]
    ContributePhase2(ceremony_contribute::ContributeOpts),
    /// Independently recheck one Phase 2 stage transition and its byte-chain receipt.
    #[cfg(unix)]
    VerifyTransition(ceremony_contribute::VerifyTransitionOpts),
}

/// A subcommand for generating a SNARK proof
#[derive(Clap)]
struct ProveOpts {
    /// Circuit for prooving (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params")]
    params: Option<String>,
    /// Input object JSON file
    #[clap(short = "o", long = "object")]
    object: Option<String>,
    /// Output file for proof JSON
    #[clap(short = "r", long = "proof")]
    proof: Option<String>,
    /// Output file for public inputs JSON
    #[clap(short = "i", long = "inputs")]
    inputs: Option<String>,
}

/// A subcommand for verifying a SNARK proof
#[derive(Clap)]
struct VerifyOpts {
    /// Circuit for verifying (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark verification key
    #[clap(short = "v", long = "vk")]
    vk: Option<String>,
    /// Proof JSON file
    #[clap(short = "r", long = "proof")]
    proof: Option<String>,
    /// Public inputs JSON file
    #[clap(short = "i", long = "inputs")]
    inputs: Option<String>,
}

/// A subcommand for generating a trusted setup parameters
#[derive(Clap)]
struct SetupOpts {
    /// Circuit for parameter generation (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Radix file path
    #[clap(short = "r", long = "radix")]
    radix: String,
}

/// A subcommand for generating a trusted setup parameters
#[derive(Clap)]
struct ContributeOpts {
    /// Circuit name (the legacy contribution handler is disabled).
    #[clap(short = "c", long = "circuit")]
    circuit: String,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVKOpts {
    /// Circuit
    #[clap(short = "c", long = "circuit")]
    circuit: String,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVerifierOpts {
    /// Circuit for verifying (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark verification key
    #[clap(short = "v", long = "vk")]
    vk: Option<String>,
    /// Smart contract name
    #[clap(short = "n", long = "name")]
    contract_name: Option<String>,
    /// Output file name
    #[clap(short = "s", long = "solidity")]
    solidity: Option<String>,
}

#[derive(Clap)]
struct GenerateTestDataOpts {
    /// Circuit for testing (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Input object JSON file
    #[clap(short = "o", long = "object")]
    object: Option<String>,
}

fn tree_circuit<C: CS<Fr = Fr>>(public: CTreePub<C>, secret: CTreeSec<C>) {
    tree_update(&public, &secret, &*POOL_PARAMS);
}

fn tx_circuit<C: CS<Fr = Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
    c_transfer(&public, &secret, &*POOL_PARAMS);
}

fn delegated_deposit_circuit<C: CS<Fr = Fr>>(
    public: CDelegatedDepositBatchPub<C>,
    secret: CDelegatedDepositBatchSec<C>,
) {
    check_delegated_deposit_batch(&public, &secret, &*POOL_PARAMS);
}

fn cli_contribute(o: ContributeOpts) {
    panic!("legacy contribute for {} is disabled: use a separately reviewed, private-entropy, non-overwriting contribution tool", o.circuit);
}

fn cli_generate_vk(o: GenerateVKOpts) {
    panic!("legacy generate-vk for {} is disabled: final artifacts require full verify-ceremony with approved anchors", o.circuit);
}

fn cli_setup(o: SetupOpts) {
    panic!("legacy setup for {} is disabled: initialize only from a separately verified radix with a reviewed coordinator", o.circuit);
}

fn cli_generate_verifier(o: GenerateVerifierOpts) {
    panic!("legacy generate-verifier for {} is disabled: derive Solidity only from a fully verified ceremony", o.circuit);
}

fn cli_verify(o: VerifyOpts) {
    let proof_path = o.proof.unwrap_or(format!("{}_proof.json", o.circuit));
    let vk_path =
        o.vk.unwrap_or(format!("{}_verification_key.json", o.circuit));
    let inputs_path = o.inputs.unwrap_or(format!("{}_inputs.json", o.circuit));

    let vk_str = std::fs::read_to_string(vk_path).unwrap();
    let proof_str = std::fs::read_to_string(proof_path).unwrap();
    let public_inputs_str = std::fs::read_to_string(inputs_path).unwrap();

    let vk: VK<Bn256> = serde_json::from_str(&vk_str).unwrap();
    let proof: Proof<Bn256> = serde_json::from_str(&proof_str).unwrap();
    let public_inputs: Vec<Num<Fr>> = serde_json::from_str(&public_inputs_str).unwrap();

    println!("Verify result is {}.", verify(&vk, &proof, &public_inputs))
}

fn cli_generate_test_data(o: GenerateTestDataOpts) {
    let object_path = o.object.unwrap_or(format!("{}_object.json", o.circuit));
    let mut rng = OsRng::default();
    let data_str = match o.circuit.as_str() {
        "transfer" => {
            let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
            let data = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);
            serde_json::to_string_pretty(&data).unwrap()
        }
        "tree_update" => {
            let data = random_sample_tree_update(&mut rng, &*POOL_PARAMS);
            serde_json::to_string_pretty(&data).unwrap()
        }
        "delegated_deposit" => {
            let data = random_sample_delegated_deposit(&mut rng, &*POOL_PARAMS);
            serde_json::to_string_pretty(&data).unwrap()
        }
        _ => panic!("Wrong cicruit parameter"),
    };
    std::fs::write(object_path, &data_str.into_bytes()).unwrap();

    println!("Test data generated")
}

fn cli_prove(o: ProveOpts) {
    let params_path = o.params.unwrap_or(format!("{}_params.bin", o.circuit));
    let object_path = o.object.unwrap_or(format!("{}_object.json", o.circuit));
    let proof_path = o.proof.unwrap_or(format!("{}_proof.json", o.circuit));
    let inputs_path = o.inputs.unwrap_or(format!("{}_inputs.json", o.circuit));

    let params_data = std::fs::read(params_path).unwrap();
    let mut params_data_cur = &params_data[..];

    let params = Parameters::<Bn256>::read(&mut params_data_cur, false, true).unwrap();
    let object_str = std::fs::read_to_string(object_path).unwrap();
    let (inputs, snark_proof) = match o.circuit.as_str() {
        "transfer" => {
            let (public, secret) = serde_json::from_str(&object_str).unwrap();
            prove(&params, &public, &secret, tx_circuit)
        }
        "tree_update" => {
            let (public, secret) = serde_json::from_str(&object_str).unwrap();
            prove(&params, &public, &secret, tree_circuit)
        }
        "delegated_deposit" => {
            let (public, secret) = serde_json::from_str(&object_str).unwrap();
            prove(&params, &public, &secret, delegated_deposit_circuit)
        }
        _ => panic!("Wrong cicruit parameter"),
    };

    let proof_str = serde_json::to_string_pretty(&snark_proof).unwrap();
    let inputs_str = serde_json::to_string_pretty(&inputs).unwrap();

    std::fs::write(proof_path, &proof_str.into_bytes()).unwrap();
    std::fs::write(inputs_path, &inputs_str.into_bytes()).unwrap();

    println!("proved")
}

pub fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Prove(o) => cli_prove(o),
        SubCommand::Verify(o) => cli_verify(o),
        SubCommand::Setup(o) => cli_setup(o),
        SubCommand::Contribute(o) => cli_contribute(o),
        SubCommand::GenerateVK(o) => cli_generate_vk(o),
        SubCommand::GenerateVerifier(o) => cli_generate_verifier(o),
        SubCommand::GenerateTestData(o) => cli_generate_test_data(o),
        SubCommand::VerifyCeremony(o) => ceremony_verify::run(o).unwrap(),
        #[cfg(unix)]
        SubCommand::InitializePhase2(o) => ceremony_contribute::initialize(o).unwrap(),
        #[cfg(unix)]
        SubCommand::ContributePhase2(o) => ceremony_contribute::contribute(o).unwrap(),
        #[cfg(unix)]
        SubCommand::VerifyTransition(o) => ceremony_contribute::verify_transition(o).unwrap(),
    }
}

#[cfg(test)]
mod ceremony_cli_tests {
    use super::*;

    #[test]
    fn legacy_argv_entropy_is_rejected_by_parser() {
        let args = ["libzeropool-setup", "contribute", "--circuit", "transfer",
            "--entropy", "inert-test-marker"];
        assert!(Opts::try_parse_from(args).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn new_contributor_rejects_secret_entropy_in_argv() {
        let pin = "11".repeat(32);
        let args = ["libzeropool-setup", "contribute-phase2", "--circuit", "transfer",
            "--before", "old.bin", "--before-receipt", "old.json",
            "--expected-before-sha256", &pin, "--expected-identity", &pin,
            "--expected-radix-sha256", &pin, "--stage-index", "1",
            "--stage-directory", "new-stage", "--entropy", "inert-test-marker"];
        assert!(Opts::try_parse_from(args).is_err());
    }

    #[test]
    fn verification_requires_independent_anchors() {
        let args = ["libzeropool-setup", "verify-ceremony", "--circuit", "transfer",
            "--params", "inert-params", "--radix", "inert-radix"];
        assert!(Opts::try_parse_from(args).is_err());
    }

    #[test]
    fn legacy_artifact_handlers_fail_before_file_access() {
        assert!(std::panic::catch_unwind(|| cli_setup(SetupOpts { circuit:"transfer".into(), radix:"inert-radix".into() })).is_err());
        assert!(std::panic::catch_unwind(|| cli_contribute(ContributeOpts { circuit:"transfer".into() })).is_err());
        assert!(std::panic::catch_unwind(|| cli_generate_vk(GenerateVKOpts { circuit:"transfer".into() })).is_err());
        assert!(std::panic::catch_unwind(|| cli_generate_verifier(GenerateVerifierOpts {
            circuit:"transfer".into(), vk:None, contract_name:None, solidity:None,
        })).is_err());
    }
}
