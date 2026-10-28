"""Attack on Protocol 1 (common secret key) of Gaynullina--Tronin (2016).

Platform: the commutative operad Z(n) = K^n built from a commutative (semi)ring K
(Example 2/5 of the paper), its suboperad R of k-th powers, and the R-algebra
A = K^d with action  (x_1..x_n) . (a_1..a_n) = sum_i x_i^k a_i.

Alice's secret x in R(n), Bob's secret y in R(m), public a[i][j] in A.
  alpha_j = x . (a_1j..a_nj)          (sent by Alice)
  beta_i  = y . (a_i1..a_im)          (sent by Bob)
  key     = x . (beta_1..beta_n) = y . (alpha_1..alpha_m)

Attack: find ANY u in K^n with  sum_i u_i a_ij = alpha_j  for all j.  This is a
one-sided linear system in u (the k-th powers and the restriction to R(n) are
irrelevant).  Then sum_i u_i beta_i = key by commutativity of Z.
"""

import random
from fractions import Fraction


# ---------------------------------------------------------------- GF(p) / Q

def solve_linear(rows, rhs, field):
    """Return one solution u of rows @ u = rhs, or None.  `field` gives inv/zero."""
    n = len(rows[0])
    M = [list(r) + [b] for r, b in zip(rows, rhs)]
    piv_cols, r = [], 0
    for c in range(n):
        p = next((i for i in range(r, len(M)) if M[i][c] != 0), None)
        if p is None:
            continue
        M[r], M[p] = M[p], M[r]
        inv = field["inv"](M[r][c])
        M[r] = [field["mul"](v, inv) for v in M[r]]
        for i in range(len(M)):
            if i != r and M[i][c] != 0:
                f = M[i][c]
                M[i] = [field["sub"](vi, field["mul"](f, vr)) for vi, vr in zip(M[i], M[r])]
        piv_cols.append(c)
        r += 1
    if any(all(v == 0 for v in row[:-1]) and row[-1] != 0 for row in M):
        return None
    u = [field["zero"]] * n  # free variables set to zero
    for i, c in enumerate(piv_cols):
        u[c] = M[i][-1]
    return u


def run_ring(name, field, rand, power, n, m, d, k):
    add, mul = field["add"], field["mul"]

    def act(coeffs, vecs):  # sum_i coeffs_i * vecs_i in K^d
        out = [field["zero"]] * d
        for c, v in zip(coeffs, vecs):
            out = [add(o, mul(c, vi)) for o, vi in zip(out, v)]
        return out

    a = [[[rand() for _ in range(d)] for _ in range(m)] for _ in range(n)]
    x = [power(rand(), k) for _ in range(n)]  # element of R(n)
    y = [power(rand(), k) for _ in range(m)]  # element of R(m)
    alpha = [act(x, [a[i][j] for i in range(n)]) for j in range(m)]
    beta = [act(y, a[i]) for i in range(n)]
    key_alice = act(x, beta)
    key_bob = act(y, alpha)
    assert key_alice == key_bob

    # Eve: unknowns u_1..u_n, one equation per (j, t)
    rows = [[a[i][j][t] for i in range(n)] for j in range(m) for t in range(d)]
    rhs = [alpha[j][t] for j in range(m) for t in range(d)]
    u = solve_linear(rows, rhs, field)
    key_eve = act(u, beta)
    print(f"{name:>10}  n={n} m={m} d={d} k={k}  shared key recovered: {key_eve == key_alice}"
          f"   (u == x: {u == x})")


P = (1 << 61) - 1
GFp = dict(add=lambda a, b: (a + b) % P, sub=lambda a, b: (a - b) % P,
           mul=lambda a, b: (a * b) % P, inv=lambda a: pow(a, P - 2, P), zero=0)
Q = dict(add=lambda a, b: a + b, sub=lambda a, b: a - b, mul=lambda a, b: a * b,
         inv=lambda a: 1 / Fraction(a), zero=Fraction(0))


# ---------------------------------------------------------------- tropical

def run_tropical(n, m, d, k):
    """(min,+) semiring: x^k = k*x, sum = min, product = +."""
    def act(coeffs, vecs):
        return [min(c + v[t] for c, v in zip(coeffs, vecs)) for t in range(d)]

    rand = lambda: random.randint(-10**6, 10**6)
    a = [[[rand() for _ in range(d)] for _ in range(m)] for _ in range(n)]
    x = [k * rand() for _ in range(n)]
    y = [k * rand() for _ in range(m)]
    alpha = [act(x, [a[i][j] for i in range(n)]) for j in range(m)]
    beta = [act(y, a[i]) for i in range(n)]
    key = act(x, beta)
    assert key == act(y, alpha)

    # principal solution of the one-sided min-plus system  min_i(u_i + a_ij[t]) = alpha_j[t]
    u = [max(alpha[j][t] - a[i][j][t] for j in range(m) for t in range(d)) for i in range(n)]
    print(f"{'tropical':>10}  n={n} m={m} d={d} k={k}  shared key recovered: {act(u, beta) == key}"
          f"   (u == x: {u == x})")


if __name__ == "__main__":
    random.seed(0)
    for (n, m, d, k) in [(5, 5, 5, 3), (40, 30, 2, 7), (60, 4, 3, 2)]:
        run_ring("GF(2^61-1)", GFp, lambda: random.randrange(1, P), lambda v, e: pow(v, e, P), n, m, d, k)
        # over Z: Eve solves over Q (no Diophantine solving needed), key is still exact
        run_ring("Z (via Q)", Q, lambda: Fraction(random.randint(1, 50)), lambda v, e: v ** e, n, m, d, k)
        run_tropical(n, m, d, k)
