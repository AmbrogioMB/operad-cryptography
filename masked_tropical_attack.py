"""Attack on the masked tropical variant of Protocol 1, Gaynullina--Tronin (2016b),
Lobachevskii J. Math. 37(6), Section 4, Theorem 4.

Tropical semiring (min,+). Algebra A({k_t};{y_t}) on K^d, masked by c in R(1):
  [w . (a_1..a_n)]_t = min_j ( a_{j,t} + k_t*(w_j + c) + y_t ),   t = 1..d
with k_t, y_t, c SECRET (shared by Alice and Bob through earlier protocols).
The paper claims security rests on the nonlinear system (5) in x, k, y, c.

Attack: for each component t, u^(t)_j := k_t*(x_j + c) + y_t enters linearly, so
alpha_{j',t} = min_i(a_{i,j',t} + u^(t)_i) is a one-sided min-plus system in u^(t).
Its principal solution gives the key; x, k, y, c are never recovered.
"""

import random


def run(n, m, d, kmax, rng):
    R = lambda: rng.randint(-10**6, 10**6)
    k = [rng.randint(1, kmax) for _ in range(d)]
    y = [R() for _ in range(d)]
    c = R()

    def act(w, vecs):
        return [min(v[t] + k[t] * (wj + c) + y[t] for wj, v in zip(w, vecs)) for t in range(d)]

    a = [[[R() for _ in range(d)] for _ in range(m)] for _ in range(n)]
    x = [R() for _ in range(n)]  # Alice
    g = [R() for _ in range(m)]  # Bob
    alpha = [act(x, [a[i][j] for i in range(n)]) for j in range(m)]
    beta = [act(g, a[i]) for i in range(n)]
    key = act(x, beta)
    assert key == act(g, alpha), "protocol does not agree"

    key_eve = []
    for t in range(d):
        u = [max(alpha[j][t] - a[i][j][t] for j in range(m)) for i in range(n)]
        key_eve.append(min(beta[i][t] + u[i] for i in range(n)))
    return key_eve == key


def lemma1_is_algebra(rng):
    """Check the unit and associativity axioms for A({k};{y}) with y != 0 (tropical unit is 0)."""
    k, y, d = [2], [5], 1
    act = lambda w, vecs: [min(v[0] + k[0] * wj + y[0] for wj, v in zip(w, vecs))]
    a = [rng.randint(-50, 50)]
    unit_ok = act([0], [a]) == a  # operad unit of Z is (0,) in min-plus
    x, w1, w2 = [3, 7], [1, 4], [2]
    b = [[rng.randint(-50, 50)] for _ in range(3)]
    comp = [x[0] + v for v in w1] + [x[1] + v for v in w2]  # gamma(x; w1, w2)
    lhs = act(comp, b)
    rhs = act(x, [act(w1, b[:2]), act(w2, b[2:])])
    return unit_ok, lhs == rhs


if __name__ == "__main__":
    rng = random.Random(0)
    for (n, m, d, kmax) in [(5, 5, 5, 10), (40, 30, 8, 1000), (60, 4, 3, 10**6)]:
        print(f"n={n} m={m} d={d} k<= {kmax}: key recovered = {run(n, m, d, kmax, rng)}")
    print("Lemma 1 (y=5): unit axiom holds = %s, associativity holds = %s" % lemma1_is_algebra(rng))
