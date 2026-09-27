#!/usr/bin/env python3
"""Check two exact emitted R1CS slices and their narrow nonidentity claims.

This is a helper-level check. It does not prove the entire transfer relation,
the subgroup gadget, a Groth16 proof, or verifier/deployment integration.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def linear(terms):
    result = {}
    for term in terms:
        name = term["variable"]
        result[name] = (result.get(name, 0) + int(term["coefficient"])) % FR
    return {name: value for name, value in result.items() if value}


def gate(export, i):
    return tuple(linear(export["gates"][i][side]) for side in ("a", "b", "c"))


def compiled_export(name):
    command = ["cargo", "run", "--locked", "--offline", "--quiet", "--example", name]
    result = subprocess.run(command, cwd=ROOT, env=os.environ.copy(),
                            capture_output=True, check=True, timeout=1800)
    return json.loads(result.stdout), hashlib.sha256(result.stdout).hexdigest()


def verify_eta(export):
    require(export["format"] == "fawkes-r1cs-canonical-eta-slice-v1", "eta format")
    require(int(export["field_modulus"]) == FR, "eta field")
    require((export["num_inputs"], export["num_aux"], len(export["gates"])) ==
            (1, 3048, 3062), "eta shape")
    a, b, c = gate(export, -1)
    require(a == linear(export["eta_scalar_lc"]), "eta scalar is not final row factor")
    require(b == {"aux_3047": 1} and c == {"input_0": 1}, "eta inverse row")


def verify_funded(export):
    require(export["format"] == "fawkes-r1cs-funded-output-nonidentity-slice-v1",
            "funded format")
    require(int(export["field_modulus"]) == FR, "funded field")
    require((export["num_inputs"], export["num_aux"], len(export["gates"])) ==
            (1, 6, 5), "funded shape")
    require((export["amount"], export["p_d"], export["constant_one"]) ==
            ("aux_0", "aux_1", "input_0"), "funded wire roles")
    minus_one = FR - 1
    expected = [
        ({"aux_2": minus_one}, {"aux_1": 1}, {"aux_3": 1}),
        ({"input_0": 1, "aux_3": 1}, {"aux_1": 1}, {"aux_4": 1}),
        ({"aux_4": 1}, {"input_0": 1}, {}),
        ({"input_0": 1, "aux_3": 1}, {"aux_0": 1}, {"aux_5": 1}),
        ({"aux_5": 1}, {"input_0": 1}, {}),
    ]
    require([gate(export, i) for i in range(5)] == expected, "funded R1CS rows")


def smt_lc(terms):
    products = [f'(* {t["coefficient"]} {t["variable"]})' for t in terms]
    return "0" if not products else products[0] if len(products) == 1 else \
        f'(+ {" ".join(products)})'


def solve_funded(export, extra):
    lines = ["(set-logic QF_NIA)", f"(define-fun p () Int {FR})",
             "(declare-const input_0 Int)", "(assert (= input_0 1))"]
    for i in range(export["num_aux"]):
        lines.extend([f"(declare-const aux_{i} Int)",
                      f"(assert (and (<= 0 aux_{i}) (< aux_{i} p)))"])
    for item in export["gates"]:
        a, b, c = (smt_lc(item[k]) for k in ("a", "b", "c"))
        lines.append(f"(assert (= (mod (* {a} {b}) p) (mod {c} p)))")
    lines.extend(extra + ["(check-sat)"])
    result = subprocess.run(["z3", "-in"], input="\n".join(lines) + "\n",
                            text=True, capture_output=True, check=True, timeout=30)
    require(result.stderr == "" and result.stdout.strip() in {"sat", "unsat"},
            "funded solver inconclusive")
    return result.stdout.strip()


def solve_eta_final_row(scalar, inverse):
    script = "\n".join([
        "(set-logic QF_NIA)", f"(define-fun p () Int {FR})",
        "(declare-const scalar Int)", "(declare-const inverse Int)",
        "(assert (and (<= 0 scalar) (< scalar p)))",
        "(assert (and (<= 0 inverse) (< inverse p)))",
        "(assert (= (mod (* scalar inverse) p) 1))",
        f"(assert (= scalar {scalar}))",
        *([] if inverse is None else [f"(assert (= inverse {inverse}))"]),
        "(check-sat)", "",
    ])
    result = subprocess.run(["z3", "-in"], input=script, text=True,
                            capture_output=True, check=True, timeout=30)
    require(result.stderr == "" and result.stdout.strip() in {"sat", "unsat"},
            "eta solver inconclusive")
    return result.stdout.strip()


def main():
    eta, eta_sha = compiled_export("export_canonical_eta_r1cs")
    funded, funded_sha = compiled_export("export_funded_output_guard_r1cs")
    verify_eta(eta)
    verify_funded(funded)

    # Mutation controls ensure the structural checks are non-vacuous.
    eta_mutation = copy.deepcopy(eta)
    eta_mutation["gates"].pop()
    try:
        verify_eta(eta_mutation)
    except AssertionError:
        pass
    else:
        raise AssertionError("missing eta inverse row was accepted")
    funded_mutation = copy.deepcopy(funded)
    funded_mutation["gates"][-1]["c"] = funded_mutation["gates"][-1]["a"]
    try:
        verify_funded(funded_mutation)
    except AssertionError:
        pass
    else:
        raise AssertionError("missing funded-output zero row was accepted")

    eta_cases = {"zero-remainder": solve_eta_final_row(0, None),
                 "unit-remainder": solve_eta_final_row(1, 1)}
    funded_cases = {
        "funded-identity": solve_funded(funded, [
            "(assert (= aux_1 0))", "(assert (not (= aux_0 0)))"]),
        "zero-padding": solve_funded(funded, [
            *(f"(assert (= aux_{i} 0))" for i in range(6))]),
        "funded-nonidentity": solve_funded(funded, [
            "(assert (= aux_0 1))", "(assert (= aux_1 1))",
            "(assert (= aux_2 1))", f"(assert (= aux_3 {FR - 1}))",
            "(assert (= aux_4 0))", "(assert (= aux_5 0))"]),
    }
    require(eta_cases == {"zero-remainder": "unsat", "unit-remainder": "sat"},
            "eta cases")
    require(funded_cases == {"funded-identity": "unsat", "zero-padding": "sat",
                             "funded-nonidentity": "sat"}, "funded cases")
    tx_source = (ROOT / "src/circuit/tx.rs").read_bytes()
    require(tx_source.count(b"        c_enforce_funded_output_note_nonidentity(") == 1,
            "funded guard must be called once from c_transfer")
    print(json.dumps({
        "status": "PASS", "scope": "two emitted R1CS helper slices",
        "canonicalEta": {"gates": len(eta["gates"]), "r1csSha256": eta_sha,
                         "cases": eta_cases},
        "fundedOutput": {"gates": len(funded["gates"]), "r1csSha256": funded_sha,
                         "cases": funded_cases},
        "mutationChecks": 2,
        "sourceSha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                         for name in ("src/circuit/key.rs", "src/circuit/tx.rs",
                                      "formal/check_nonidentity_guards.py")},
        "premises": ["Fawkes R1CS gates are enforced over BN254 Fr",
                     "c_transfer invokes the two checked helpers on its witnesses"],
    }, indent=2))


if __name__ == "__main__":
    main()
