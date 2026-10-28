"""Attack on Protocols 2-4 of Gaynullina--Tronin (2016), Lobachevskii J. Math. 37(3).

Platform: the commutative operad Z(n) = K^n of Example 2/5 with K = Z/N (N = 2^12),
gamma(x; y_1..y_m) = (x_1 y_1, ..., x_m y_m)  (concatenation of scaled strings).
All three protocols publish y = gamma(x; g, ..., g) for a secret x and public g.

Attack: find ANY x' with gamma(x'; g, ..., g) = y.  By the factorization lemma,
gamma(x'; gamma(h; g^d), ...) = gamma(x; gamma(h; g^d), ...) for every h, which is
all Eve needs.  We pick g with only even entries, so division in Z/N is not unique
and the x' found is in general different from the secret x.

Also checked: Protocol 4 as written accepts any prover (Bob holds nothing tied to
Alice), and the repaired masked Protocol 4 (Gaynullina--Tronin 37(6) masking, g and y
public, verifier knows the mask c) is forged after observing one transcript.
"""

import random

N = 1 << 12


def gamma(x, ys):
    return [xi * v % N for xi, y in zip(x, ys) for v in y]


def power(x, g, times):
    """x g^times := gamma(x; g, ..., g)."""
    return gamma(x, [g] * times)


def divide(y, g, m):
    """Some x' in (Z/N)^m with power(x', g, m) == y; brute force per coordinate."""
    n = len(g)
    xp = []
    for i in range(m):
        block = y[i * n:(i + 1) * n]
        xp.append(next(c for c in range(N) if all(c * gj % N == b for gj, b in zip(g, block))))
    return xp


def rand_elem(rng, size, even=False):
    return [rng.randrange(0, N, 2) if even else rng.randrange(N) for _ in range(size)]


def protocol2(rng, n, m, k):
    omega = rand_elem(rng, n, even=True)
    alpha, beta = rand_elem(rng, m), rand_elem(rng, k)
    A, B = power(alpha, omega, m), power(beta, omega, k)
    key_alice = power(alpha, B, m)
    key_bob = power(beta, A, k)
    assert sorted(key_alice) == sorted(key_bob)  # equal up to the permutation sigma'
    alpha_eve = divide(A, omega, m)
    return power(alpha_eve, B, m) == key_alice, alpha_eve == alpha


def protocol3(rng, n, m, d):
    g = rand_elem(rng, n, even=True)
    x = rand_elem(rng, m)
    y = power(x, g, m)                    # public key
    k = rand_elem(rng, d)                 # session key
    c1 = power(k, g, d)
    shared = power(x, c1, m)              # what the receiver hashes (before sigma)
    x_eve = divide(y, g, m)
    return power(x_eve, c1, m) == shared, x_eve == x


def protocol4(rng, n, m, l):
    x = rand_elem(rng, n)                 # Alice's secret
    g = rand_elem(rng, m, even=True)      # Bob's challenge
    y = power(x, g, n)
    k = rand_elem(rng, l)
    z = power(power(x, k, n), g, n * l)   # honest response
    x_eve = divide(y, g, n)
    z_eve = power(power(x_eve, k, n), g, n * l)
    return z_eve == z, x_eve == x


def protocol4_as_written(rng, n, m, l):
    """Bob holds no data tied to Alice: an impostor with her own x'' passes."""
    g = rand_elem(rng, m)                 # Bob's challenge
    x_imp = rand_elem(rng, n)             # impostor's own secret
    y_imp = power(x_imp, g, n)
    k = rand_elem(rng, l)
    z_imp = power(power(x_imp, k, n), g, n * l)
    accepted = sorted(z_imp) == sorted(power(k, y_imp, l))  # check up to the public permutation
    return accepted, False


def gamma_masked(c, w, ys):
    """[w; y_1..y_m]_c = gamma(w[c]; y_1..y_m)."""
    return gamma(power(w, [c], len(w)), ys)


def protocol4_masked(rng, n, m, l):
    """Repaired masked Protocol 4: g, y public; verifier knows c.  One transcript -> forgery."""
    c = rng.randrange(1, N, 2)            # invertible mask (odd)
    g = rand_elem(rng, m, even=True)
    x = rand_elem(rng, n)
    y = gamma_masked(c, x, [g] * n)       # public key
    respond = lambda kk: gamma_masked(c, gamma_masked(c, x, [kk] * n), [g] * (n * l))

    k = rand_elem(rng, l)
    k[0] |= 1                             # make sure one entry of the challenge is a unit
    z = respond(k)                        # observed transcript (k, z)

    u = divide(y, g, n)                   # u[g] = y, u plays the role of x[c]
    forge = lambda kk, cc: power(u, power(power(kk, [cc], l), g, l), n)
    c_eve = next(cc for cc in range(N) if forge(k, cc) == z)

    k_new = rand_elem(rng, l)             # fresh challenge
    return forge(k_new, c_eve) == respond(k_new), c_eve == c


if __name__ == "__main__":
    rng = random.Random(0)
    for name, run, sizes in [("Protocol 2 (key)", protocol2, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 3 (decrypt)", protocol3, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 (forge)", protocol4, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 as written", protocol4_as_written, [(3, 4, 5), (6, 3, 2)]),
                             ("Protocol 4 masked", protocol4_masked, [(3, 4, 5), (6, 3, 2)])]:
        for s in sizes:
            ok, same = run(rng, *s)
            print(f"{name:<22} sizes={s}: attack succeeds = {ok}   (x' or c' == secret: {same})")
