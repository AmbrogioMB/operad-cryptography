# Cryptanalysis of operad-based cryptography: code

This repository contains the code accompanying the paper

> A. M. Bernardelli, *Cryptanalysis of operad-based cryptography*, preprint, 2026.

The paper shows that the public-key protocols built on commutative operads in [1, 2] reduce to an
interpolation problem (key agreement) and a division problem (key exchange, encryption) over the
centralizer of the public operations. On the operad platforms proposed in [1, 2], the relevant problems
can be solved in polynomial time under the paper's input assumptions, including finite tropical data.
The authentication protocol does not
authenticate: as stated it accepts every prover, and with a registered public key the expected
response is computable from public data. Verification in the masked variant requires the secret mask;
on the concrete string platforms, one observed session with an invertible challenge entry suffices
for forgery. The scripts
implement the honest protocols and the attacks on representative platforms, and reproduce every
number in the experiments section of the paper.

## Requirements

- Python 3 (tested with Python 3.14). Only the standard library is used.
- No installation is needed.

## Quick start

```bash
python run_experiments.py
```

This runs all correctness and scaling experiments, prints both tables, and writes
`results/correctness.csv` and `results/scaling.csv`. On a laptop (Intel Core i7-1185G7, single
thread) it takes between about 40 seconds and two minutes, depending on power management; most of
the time is spent on the largest Gaussian eliminations in the scaling study.

Each attack module can also be run on its own for a short demonstration:

```bash
python protocol1_attack.py
python masked_tropical_attack.py
python protocols234_attack.py
```

## Contents

| File | What it does | Results in the paper |
|---|---|---|
| `protocol1_attack.py` | Protocol 1 (common secret key) on the string operad over GF(2^61−1), over the integers (attack solved over the rationals) and over the tropical semiring with finite entries | Theorem "Protocol 1 reduces to Int", Corollary on interpolation for the proposed algebras |
| `masked_tropical_attack.py` | Protocol 1 with masking by a secret element and the tropical algebras with secret exponents and offsets of [2]; also checks that these structures fail the unit and associativity axioms unless the offsets are trivial | Theorem "Secret parameters are absorbed", Proposition "On [2, Lemma 1]" |
| `protocols234_attack.py` | Exact checks of the commutativity, equivariance and factorization identities with the explicit permutations of the paper; Protocols 2–4 (key exchange, encryption, authentication) over Z/2^12, with public elements chosen so that division is not unique; Protocol 4 as originally stated (any prover is accepted), with a registered public key (attack through division, and forgery from public data only), and masked (forgery after one observed transcript) | Definition of commutative operad, Lemma "Factorization", Theorem "Protocols 2–4 reduce to Div", Propositions "Protocol 4 does not authenticate" and "One transcript suffices on string operads" |
| `run_experiments.py` | Experiment driver: 10 random trials per configuration (seeds 0–9) and an attacker-only scaling study (3 trials per size, seeds 100–102) | Tables 1 and 2 |
| `results/` | CSV output of `run_experiments.py`, as reported in the paper | Tables 1 and 2 |

## What the experiments check

Each trial draws a fresh random instance, simulates the honest parties, gives the attacker only the
public data and the transmitted messages, and checks the attacker's output for **exact equality**
with the honest value:

- Protocols 1 and 2: the shared key;
- Protocol 3: the receiver's decryption value;
- Protocol 4 with a registered public key: the response accepted by the verifier, computed either
  through the division problem or from public data only;
- masked Protocol 4: the accepted response to a fresh challenge after one observed transcript;
- Protocol 4 as originally stated: acceptance of an impostor who uses her own secret.

Whenever two values are compared "up to a public permutation", the code applies the explicit
permutation of the paper (a permutation moves the entry in position r to position sigma(r)); it never
compares multisets. The identity checks of the factorization lemma fail if the permutation is
replaced by its inverse.

Not implemented: the interpolation problem for convexors (a linear program) and over residue rings;
for these cases the paper relies on the proofs and on standard algorithms.

The experiments also record whether the attacker's solution happens to coincide with the secret.
It often does not, which illustrates that recovering the secret is never needed.

## Reproducibility

All random choices are seeded, so success counts and "solution = secret" counts are deterministic.
Running times depend on the hardware and on the Python version. The division in Z/2^12 is done by
exhaustive search over the 2^12 residues for simplicity; in general it is a system of linear
congruences.

## Scope

The code targets the academic proposals [1, 2] and the toy parameter sizes needed to verify the
results of the paper. It is not intended as a general-purpose cryptanalysis tool.

## References

1. A. R. Gaynullina, S. N. Tronin, *Towards an operad-based cryptography: applications of
   commutative operads*, Lobachevskii Journal of Mathematics 37(3) (2016) 234–239.
   doi:10.1134/S1995080216030100
2. A. R. Gaynullina, S. N. Tronin, *Some new platforms for algebraic cryptography and one method
   of increasing the security*, Lobachevskii Journal of Mathematics 37(6) (2016) 768–776.
   doi:10.1134/S1995080216060123

## Citation

If you use this code, please cite the paper above. Citation metadata is in `CITATION.cff`.

## License

MIT, see `LICENSE`.
