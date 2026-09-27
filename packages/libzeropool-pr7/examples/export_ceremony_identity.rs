//! Read-only export of the exact setup-shaped circuit identity.
#[cfg(not(all(feature = "in3out127", feature = "cli_libzeropool_setup")))]
compile_error!("ceremony identity export requires in3out127 and cli_libzeropool_setup");
#[cfg(any(feature = "in1out127", feature = "in7ount127", feature = "in15out127"))]
compile_error!("ceremony identity export requires only in3out127");

#[path = "../src/setup/circuit_identity.rs"]
mod circuit_identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let circuit = args.next().unwrap_or_else(|| "transfer".to_owned());
    if args.next().is_some() || !matches!(circuit.as_str(), "transfer" | "tree_update") {
        return Err("expected optional circuit: transfer or tree_update".into());
    }
    let (cs, metadata) = circuit_identity::build(&circuit)?;
    let identity = circuit_identity::describe(&cs.borrow(), metadata, std::io::sink())?;
    println!("{}", serde_json::to_string_pretty(&identity)?);
    Ok(())
}
