#!/usr/bin/env python3
"""Check the allocated Boolean and initial-account guard relation.

Only the public Boolean-allocation and two-helper-gate R1CS slice is read. No transfer witness, proof,
parameter file, key, point, or deployed contract is used.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SOURCE_SHA = 'f1d5b75211712dd6ee2f456364dddf498e19ce44ba3c6976cea715a4badcb017'
EXPORT_SHA = '50fab4cb7ba5047a839f1e816b95742d56b0098d3e89bf4325a14e5028f29442'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def load(data):
    return json.loads(data, object_pairs_hook=pairs)

def verify_export(export):
    require(set(export) == {'format', 'modulus', 'constant_one', 'position',
                            'is_initial', 'num_inputs', 'num_aux', 'gates'}, 'export schema')
    require(export['format'] == 'fawkes-r1cs-slice-v1', 'export format')
    require(export['modulus'] == str(FIELD), 'field modulus')
    require(export['constant_one'] == 'input_0' and export['position'] == 'aux_0'
            and export['is_initial'] == 'aux_1', 'wire roles')
    require(type(export['num_inputs']) is int and export['num_inputs'] == 1
            and type(export['num_aux']) is int and export['num_aux'] == 3, 'wire counts')
    require(type(export['gates']) is list and len(export['gates']) == 3, 'gate count')
    names = {'input_0', 'aux_0', 'aux_1', 'aux_2'}
    for gate in export['gates']:
        require(type(gate) is dict and set(gate) == {'a', 'b', 'c'}, 'gate schema')
        for key in ['a', 'b', 'c']:
            require(type(gate[key]) is list, 'linear combination shape')
            for term in gate[key]:
                require(type(term) is dict and set(term) == {'variable', 'coefficient'}, 'term schema')
                require(term['variable'] in names, 'wire outside export')
                coefficient = term['coefficient']
                require(type(coefficient) is str and re.fullmatch(r'0|[1-9][0-9]*', coefficient)
                        and int(coefficient) < FIELD, 'noncanonical coefficient')

def linear_combination(terms):
    if not terms:
        return '0'
    products = [f'(* {t["coefficient"]} {t["variable"]})' for t in terms]
    return products[0] if len(products) == 1 else f'(+ {" ".join(products)})'

def solver_case(export, extra):
    lines = ['(set-logic QF_NIA)', f'(define-fun p () Int {FIELD})']
    for name in ['input_0', 'aux_0', 'aux_1', 'aux_2']:
        lines += [f'(declare-const {name} Int)', f'(assert (and (<= 0 {name}) (< {name} p)))']
    lines += ['(assert (= input_0 1))']
    for gate in export['gates']:
        a, b, c = (linear_combination(gate[k]) for k in ['a', 'b', 'c'])
        lines += [f'(assert (= (mod (* {a} {b}) p) (mod {c} p)))']
    lines += extra + ['(check-sat)']
    z3 = shutil.which('z3')
    require(z3 is not None, 'Z3 is required')
    result = subprocess.run([z3, '-in'], input='\n'.join(lines) + '\n',
                            text=True, capture_output=True, timeout=40, check=True)
    require(result.stderr == '', 'Z3 diagnostic')
    require(result.stdout.strip() in {'sat', 'unsat'}, 'inconclusive solver result')
    return result.stdout.strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-export', action='store_true',
                        help='also recompile the shared Rust guard and compare its R1CS')
    args = parser.parse_args()
    require(sha((ROOT / 'src/circuit/tx.rs').read_bytes()) == SOURCE_SHA, 'guard source differs')
    data = (ROOT / 'formal/initial-position-r1cs.json').read_bytes()
    require(sha(data) == EXPORT_SHA, 'recorded R1CS changed')
    expected = load(data)
    verify_export(expected)
    z3 = shutil.which('z3')
    require(z3 is not None, 'Z3 is required')
    version = subprocess.run([z3, '--version'], capture_output=True, text=True,
                             timeout=10, check=True).stdout.strip()
    require(version.startswith('Z3 version 4.16.0 '), 'Z3 4.16.0 is required')
    if args.check_export:
        require((ROOT / 'examples/export_initial_position_r1cs.rs').is_file(), 'exporter missing')
        completed = subprocess.run(['cargo', 'run', '--locked', '--quiet', '--example',
                                    'export_initial_position_r1cs'], cwd=ROOT,
                                   capture_output=True, text=True, timeout=1800, check=True)
        require(load(completed.stdout) == expected, 'compiled R1CS differs')
    cases = [
        ('initial-position-zero', ['(assert (= aux_1 1))', '(assert (not (= aux_0 0)))'], 'unsat'),
        ('canonical-initial-liveness', ['(assert (= aux_1 1))', '(assert (= aux_0 0))'], 'sat'),
        ('noninitial-position-liveness', ['(assert (= aux_1 0))', '(assert (= aux_0 123))'], 'sat'),
    ]
    outcomes = []
    for name, extra, expected_status in cases:
        actual = solver_case(expected, extra)
        require(actual == expected_status, f'{name}: {actual}')
        outcomes.append({'name': name, 'expected': expected_status, 'actual': actual})
    print(json.dumps({'status': 'PASS', 'scope': 'allocated Boolean plus two helper gates',
                      'sourceSha256': SOURCE_SHA, 'r1csSha256': EXPORT_SHA,
                      'compiledExportCompared': args.check_export,
                      'z3Version': version, 'cases': outcomes}, indent=2))

if __name__ == '__main__':
    main()
