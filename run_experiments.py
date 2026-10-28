"""Experiments for the paper: correctness over several seeds, and attacker-only scaling.

Usage:  python run_experiments.py
Writes results/correctness.csv and results/scaling.csv and prints both tables.

Every trial draws a fresh random instance, simulates the honest parties, runs the attack,
and checks the attacker's output for exact equality with the honest value (shared key,
decryption value, or accepted response).  Timings measure the attacker's computation only.
"""

import csv
import os
import random
import statistics
import sys
import time
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I

import protocol1_attack as P1  # noqa: E402
import protocols234_attack as P234  # noqa: E402

TRIALS = 10
SCALING_TRIALS = 3
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


# ---------------------------------------------------------------- Protocol 1, semirings

def p1_linear(rng, field, rand, power, n, m, d, k):
    add, mul = field["add"], field["mul"]

    def act(coeffs, vecs):
        out = [field["zero"]] * d
        for c, v in zip(coeffs, vecs):
            out = [add(o, mul(c, vi)) for o, vi in zip(out, v)]
        return out

    a = [[[rand() for _ in range(d)] for _ in range(m)] for _ in range(n)]
    x = [power(rand(), k) for _ in range(n)]
    y = [power(rand(), k) for _ in range(m)]
    alpha = [act(x, [a[i][j] for i in range(n)]) for j in range(m)]
    beta = [act(y, a[i]) for i in range(n)]
    key = act(x, beta)

    t0 = time.perf_counter()
    rows = [[a[i][j][t] for i in range(n)] for j in range(m) for t in range(d)]
    rhs = [alpha[j][t] for j in range(m) for t in range(d)]
    u = P1.solve_linear(rows, rhs, field)
    key_eve = act(u, beta)
    return key_eve == key, u == x, time.perf_counter() - t0


def p1_field(rng, n, m, d, k):
    return p1_linear(rng, P1.GFp, lambda: rng.randrange(1, P1.P), lambda v, e: pow(v, e, P1.P), n, m, d, k)


def p1_integers(rng, n, m, d, k):
    return p1_linear(rng, P1.Q, lambda: Fraction(rng.randint(1, 50)), lambda v, e: v ** e, n, m, d, k)


def p1_tropical(rng, n, m, d, k, masked=False, kmax=10**6):
    R = lambda: rng.randint(-10**6, 10**6)
    if masked:
        ks = [rng.randint(1, kmax) for _ in range(d)]
        ys = [R() for _ in range(d)]
        c = R()
    else:
        ks, ys, c = [k] * d, [0] * d, 0

    def act(w, vecs):
        return [min(v[t] + ks[t] * (wj + c) + ys[t] for wj, v in zip(w, vecs)) for t in range(d)]

    a = [[[R() for _ in range(d)] for _ in range(m)] for _ in range(n)]
    x = [R() for _ in range(n)]
    g = [R() for _ in range(m)]
    alpha = [act(x, [a[i][j] for i in range(n)]) for j in range(m)]
    beta = [act(g, a[i]) for i in range(n)]
    key = act(x, beta)

    t0 = time.perf_counter()
    key_eve = []
    u_all = []
    for t in range(d):
        u = [max(alpha[j][t] - a[i][j][t] for j in range(m)) for i in range(n)]
        u_all.append(u)
        key_eve.append(min(beta[i][t] + u[i] for i in range(n)))
    elapsed = time.perf_counter() - t0
    same = all(u_all[t] == [ks[t] * (xi + c) + ys[t] for xi in x] for t in range(d))
    return key_eve == key, same, elapsed


# ---------------------------------------------------------------- Protocols 2-4, Z/2^12

def timed_protocol(fn):
    def run(rng, *sizes):
        t0 = time.perf_counter()
        ok, same = fn(rng, *sizes)
        return ok, same, time.perf_counter() - t0
    return run


# ---------------------------------------------------------------- driver

CORRECTNESS = [
    ("1", "GF(2^61-1)", p1_field, [(5, 5, 5, 3), (40, 30, 2, 7), (60, 4, 3, 2)]),
    ("1", "Z via Q", p1_integers, [(5, 5, 5, 3), (40, 30, 2, 7), (60, 4, 3, 2)]),
    ("1", "tropical", lambda r, *s: p1_tropical(r, *s), [(5, 5, 5, 3), (40, 30, 2, 7), (60, 4, 3, 2)]),
    ("1 masked", "tropical", lambda r, n, m, d: p1_tropical(r, n, m, d, None, masked=True),
     [(5, 5, 5), (40, 30, 8), (60, 4, 3)]),
    ("2", "Z/2^12", timed_protocol(P234.protocol2), [(3, 4, 5), (6, 3, 2)]),
    ("3", "Z/2^12", timed_protocol(P234.protocol3), [(3, 4, 5), (6, 3, 2)]),
    ("4 repaired", "Z/2^12", timed_protocol(P234.protocol4), [(3, 4, 5), (6, 3, 2)]),
    ("4 as written", "Z/2^12", timed_protocol(P234.protocol4_as_written), [(3, 4, 5), (6, 3, 2)]),
    ("4 masked", "Z/2^12", timed_protocol(P234.protocol4_masked), [(3, 4, 5), (6, 3, 2)]),
]

SCALING = [
    ("1", "GF(2^61-1)", lambda r, n: p1_field(r, n, n // 2, 2, 5), [25, 50, 100, 200]),
    ("1 masked", "tropical", lambda r, n: p1_tropical(r, n, n, 8, None, masked=True), [100, 200, 400, 800]),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []
    print(f"{'protocol':<13}{'platform':<12}{'sizes':<16}{'success':>8}{'=secret':>9}{'median s':>11}")
    for proto, platform, fn, sizes in CORRECTNESS:
        for s in sizes:
            res = [fn(random.Random(seed), *s) for seed in range(TRIALS)]
            succ = sum(r[0] for r in res)
            same = sum(r[1] for r in res)
            med = statistics.median(r[2] for r in res)
            rows.append([proto, platform, s, succ, same, TRIALS, med])
            print(f"{proto:<13}{platform:<12}{str(s):<16}{succ:>5}/{TRIALS}{same:>6}/{TRIALS}{med:>11.4f}")
    with open(os.path.join(OUT, "correctness.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "platform", "sizes", "successes", "solution_equals_secret", "trials",
                    "median_seconds"])
        w.writerows(rows)

    print()
    rows = []
    print(f"{'protocol':<13}{'platform':<12}{'n':>6}{'success':>10}{'median s':>11}")
    for proto, platform, fn, ns in SCALING:
        for n in ns:
            res = [fn(random.Random(100 + seed), n) for seed in range(SCALING_TRIALS)]
            succ = sum(r[0] for r in res)
            med = statistics.median(r[2] for r in res)
            rows.append([proto, platform, n, succ, SCALING_TRIALS, med])
            print(f"{proto:<13}{platform:<12}{n:>6}{succ:>7}/{SCALING_TRIALS}{med:>11.3f}")
    with open(os.path.join(OUT, "scaling.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "platform", "n", "successes", "trials", "median_seconds"])
        w.writerows(rows)


if __name__ == "__main__":
    main()
