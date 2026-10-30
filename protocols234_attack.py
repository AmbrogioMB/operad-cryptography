"""Attacks on Protocols 2-4 of Gaynullina--Tronin (2016), Lobachevskii J. Math. 37(3).

Platform: the commutative operad Z(n) = K^n of Example 2/5 with K = Z/N (N = 2^12),
gamma(x; y_1..y_m) = (x_1 y_1, ..., x_m y_m)  (concatenation of scaled strings).
All three protocols publish y = x[g] := gamma(x; g, ..., g) for a secret x and public g.

Permutations follow the conventions of the paper: a permutation sigma moves the entry in
position r to position sigma(r).  sigma_{m,n} transposes an m x n array, and sigma<n>
permutes blocks of size n.  Every comparison "up to a public permutation" below uses the
explicit permutation tau = sigma_{m,d}<n> of the factorization lemma, never a multiset test.

Attack (Protocols 2, 3, and 4 with a registered public key): find ANY x' with x'[g] = y.
By the factorization lemma,
x'[h[g]] = (h[x'[g]]) tau depends on x' only through x'[g], which is all Eve needs.  We pick g
with only even entries, so division in Z/N is not unique and x' usually differs from x.

Also checked: Protocol 4 as stated accepts any prover; with a registered public key, the
expected response (k[y]) tau is computable from public data alone; the masked Protocol 4
(Gaynullina--Tronin 37(6)) is forged after observing one transcript.
"""

import random

N = 1 << 12


def gamma(x, ys):
    return [xi * v % N for xi, y in zip(x, ys) for v in y]


def power(x, g, times):
    """x[g] := gamma(x; g, ..., g) with `times` = len(x) copies of g."""
    return gamma(x, [g] * times)


# ---------------------------------------------------------------- permutations (0-indexed)

def sigma(m, n):
    """sigma_{m,n}: position i + j*m  ->  j + i*n   (i < m, j < n)."""
    p = [0] * (m * n)
    for i in range(m):
        for j in range(n):
            p[i + j * m] = j + i * n
    return p


def blocks(p, n):
    """p<n>: moves block r (of size n) to block p(r)."""
    return [p[r] * n + s for r in range(len(p)) for s in range(n)]


def act(z, p):
    """Right action used in the paper: the entry in position r moves to position p(r)."""
    out = [None] * len(z)
    for r, v in enumerate(z):
        out[p[r]] = v
    return out


def tau(m, d, n):
    """tau = sigma_{m,d}<n> of the factorization lemma, for f in Z(m), h in Z(d), g in Z(n)."""
    return blocks(sigma(m, d), n)


# ---------------------------------------------------------------- helpers

def divide(y, g, m):
    """Some x' in (Z/N)^m with power(x', g, m) == y; exhaustive search per coordinate."""
    n = len(g)
    xp = []
    for i in range(m):
        block = y[i * n:(i + 1) * n]
        xp.append(next(c for c in range(N) if all(c * gj % N == b for gj, b in zip(g, block))))
    return xp


def rand_elem(rng, size, even=False):
    return [rng.randrange(0, N, 2) if even else rng.randrange(N) for _ in range(size)]


# ---------------------------------------------------------------- conventions

def check_conventions(rng, m, d, n):
    """Definition 2.1, equivariance, and Lemma 3.6 as exact identities on random elements."""
    f, h, g = rand_elem(rng, m), rand_elem(rng, d), rand_elem(rng, n)
    comm = power(f, h, m) == act(power(h, f, d), sigma(m, d))            # f[h] = (h[f]) sigma_{m,d}
    p = list(range(m))
    rng.shuffle(p)
    equiv = power(act(f, p), g, m) == act(power(f, g, m), blocks(p, n))   # (f p)[g] = (f[g]) p<n>
    lemma = power(f, power(h, g, d), m) == act(power(h, power(f, g, m), d), tau(m, d, n))
    return comm and equiv and lemma, False


# ---------------------------------------------------------------- protocols

def protocol2(rng, n, m, k):
    omega = rand_elem(rng, n, even=True)
    alpha, beta = rand_elem(rng, m), rand_elem(rng, k)
    A, B = power(alpha, omega, m), power(beta, omega, k)
    key_alice = power(alpha, B, m)
    key_bob = power(beta, A, k)
    assert key_alice == act(key_bob, tau(m, k, n))       # Alice's key = (Bob's key) tau
    alpha_eve = divide(A, omega, m)
    return power(alpha_eve, B, m) == key_alice, alpha_eve == alpha


def protocol3(rng, n, m, d):
    g = rand_elem(rng, n, even=True)
    x = rand_elem(rng, m)
    y = power(x, g, m)                    # public key
    k = rand_elem(rng, d)                 # session key
    c1 = power(k, g, d)
    shared = power(x, c1, m)              # receiver's value, equal to (k[y]) tau
    assert shared == act(power(k, y, d), tau(m, d, n))
    x_eve = divide(y, g, m)
    return power(x_eve, c1, m) == shared, x_eve == x


def protocol4(rng, n, m, l):
    """Registered public key y = x[g]; attack through the division problem (Theorem 3.7(c))."""
    x = rand_elem(rng, n)                 # Alice's secret
    g = rand_elem(rng, m, even=True)      # fixed public element
    y = power(x, g, n)                    # registered public key
    k = rand_elem(rng, l)                 # challenge
    z = power(power(x, k, n), g, n * l)   # honest response
    assert z == act(power(k, y, l), tau(n, l, m))          # what the verifier checks
    x_eve = divide(y, g, n)
    z_eve = power(power(x_eve, k, n), g, n * l)
    return z_eve == z, x_eve == x


def protocol4_public_forgery(rng, n, m, l):
    """Registered public key: the expected response (k[y]) tau uses public data only."""
    x = rand_elem(rng, n)
    g = rand_elem(rng, m)
    y = power(x, g, n)
    k = rand_elem(rng, l)
    z = power(power(x, k, n), g, n * l)   # honest response
    z_forged = act(power(k, y, l), tau(n, l, m))
    return z_forged == z, False


def protocol4_as_written(rng, n, m, l):
    """Bob holds no data tied to Alice: an impostor with her own x'' passes."""
    g = rand_elem(rng, m)                 # Bob's first message
    x_imp = rand_elem(rng, n)             # impostor's own secret
    y_imp = power(x_imp, g, n)
    k = rand_elem(rng, l)
    z_imp = power(power(x_imp, k, n), g, n * l)
    accepted = z_imp == act(power(k, y_imp, l), tau(n, l, m))   # verifier's check, exact
    return accepted, False


def gamma_masked(c, w, ys):
    """[w; y_1..y_m]_c = gamma(w[c]; y_1..y_m)."""
    return gamma(power(w, [c], len(w)), ys)


def protocol4_masked(rng, n, m, l):
    """Masked Protocol 4: g, y public; the verifier knows c.  One transcript -> forgery."""
    c = rng.randrange(1, N, 2)            # invertible mask (odd)
    g = rand_elem(rng, m, even=True)
    x = rand_elem(rng, n)
    y = gamma_masked(c, x, [g] * n)       # public key
    respond = lambda kk: gamma_masked(c, gamma_masked(c, x, [kk] * n), [g] * (n * l))
    t = tau(n, l, m)
    expected = lambda kk, cc: act(power(power(kk, [cc], l), y, l), t)   # ((k[c])[y]) tau

    k = rand_elem(rng, l)
    k[0] |= 1                             # one entry of the challenge is a unit
    z = respond(k)                        # observed transcript (k, z)
    assert z == expected(k, c)
    c_eve = next(cc for cc in range(N) if expected(k, cc) == z)

    k_new = rand_elem(rng, l)             # fresh challenge
    return expected(k_new, c_eve) == respond(k_new), c_eve == c


if __name__ == "__main__":
    rng = random.Random(0)
    for name, run, sizes in [("Conventions (Lemma 3.6)", check_conventions, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 2 (key)", protocol2, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 3 (decrypt)", protocol3, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 via Div", protocol4, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 public forgery", protocol4_public_forgery, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 as stated", protocol4_as_written, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 masked", protocol4_masked, [(3, 4, 5), (6, 3, 2)])]:
        for s in sizes:
            ok, same = run(rng, *s)
            print(f"{name:<26} sizes={s}: success = {ok}   (x' or c' == secret: {same})")
