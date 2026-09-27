# Initial-account position constraint

An initial account is exempt from the input Merkle membership check. Its
nullifier includes the input position. The transfer circuit now constrains
that position to zero when `is_initial` is true.

`examples/export_initial_position_r1cs.rs` synthesizes the same guard helper
called by `c_transfer`. Its export has one Boolean allocation gate and two
helper gates for multiplication and the zero assertion. The JSON export is
pinned by SHA-256 in `check_initial_position.py`. The checker verifies that
those gates imply zero position for an initial account, while allowing the
canonical initial path and a noninitial path. It uses symbolic field
constraints and does not create a transaction or proof.

Run `python3 formal/check_initial_position.py` with Z3 4.16.0 on PATH to check the
recorded export. Add `--check-export` to rebuild it using the pinned Rust
toolchain and `Cargo.lock`, then compare the exact R1CS before running Z3.
The pull-request workflow runs that rebuild and check on Ubuntu 24.04 using
the pinned official Z3 4.16.0 release archive and verifies its SHA-256 before
execution.
The recorded export comes from the separately pinned Telos Privacy development
candidate; without `--check-export`, the script does not rebuild the Rust code.
The fixture allocates an independent Boolean. It does not establish the
full-transfer derivation of `is_initial` or the entire transfer row layout.

This scoped check does not prove full transfer correctness, account ownership,
nullifier uniqueness, Groth16 security, or compatibility with an existing
proving key. Changing this relation requires matching proving parameters and
verifier artifacts before any production use.
