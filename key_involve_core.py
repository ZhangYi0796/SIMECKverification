#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
key_involve_core.py -- shared engine for the per-bit key-dependency checkers
key_involve32.py / key_involve48.py / key_involve64.py.

The three scripts differ only in their PARAMETERS block (instance data
transcribed by hand from the paper and from result.txt); everything below is
cipher-independent.

================================================================================
1. WHAT IS COMPUTED
================================================================================
For a single bit of a state, of a difference, or of one of the four matching
objects A, Atilde, B, Btilde, the program returns the set of ROUND-KEY BITS
k^(r)_j that an attacker must know in order to compute that bit.  The answer is
a purely combinatorial fact, so the program never runs the cipher and never
samples keys.

Two questions are distinguished throughout:

  * compute  -- what does it cost to evaluate this bit;
  * verify   -- what does it cost to CHECK that a probabilistic-extension bit
                really is zero.  This is the paper's k_gamma and it differs
                from "compute", because the trail may already fix the bit
                (compute -> free) while a verification still has to recompute
                it from the boundary (verify -> not free).

================================================================================
2. ROUND FUNCTION AND INDEX CONVENTION
================================================================================
SIMECK word pair (X^r, X^(r-1)), one round:

    X^(r+1) = F(X^r) ^ X^(r-1) ^ k^(r),     F(x)_j = x_j x_(j-5) ^ x_(j-1)

All bit indices are taken modulo n.  The 2n-bit state index used on the command
line is: 0..n-1 -> left word X^r, n..2n-1 -> right word X^(r-1).

================================================================================
3. LAYER 0 -- TRUNCATED TRAIL
================================================================================
A difference bit is one of 0, 1, 2 (= unknown, written '*').

    [F'(D)]_j is determined  <=>  D_j = D_(j-5) = 0 and none of D_j, D_(j-5),
                                   D_(j-1) is '*';  then it equals D_(j-1).
    DX^(r+1)_j = [F'(DX^r)]_j ^ DX^(r-1)_j

Gamma_in  : from delta_in  at (X^rIN, X^(rIN-1)) towards the plaintext.
Gamma_out : from delta_out at (X^rOUT, X^(rOUT-1)) towards the ciphertext.
PE points : forced to 0 and the propagation continues (probabilistic extension;
            each point costs a factor 2^-1).
GS/GD     : bits that the state-test / difference-test technique hands to the
            attacker directly.  They terminate every recursion below.

The set of trail-determined bits is what the attacker gets for free; the set of
bits determined to 0 is also what prunes the product terms of layer 2.

================================================================================
4. LAYER 1 -- PER-BIT KEY DEPENDENCY (out side)
================================================================================
A = (X^rA, X^(rA-1)) is ENUMERATED by the matching structure, so it costs no
key.  Two recursions follow the trail from A towards the ciphertext:

  state      X^r_j = F(X^(r+1))_j ^ X^(r+2)_j ^ k^(r+1)_j
             dep(X^r_j) = dep(X^(r+1)_{j,j-5,j-1}) | dep(X^(r+2)_j) | {k^(r+1)_j}

  difference DX^r_j = [F'(DX^(r-1))]_j ^ DX^(r-2)_j
             dep(DX^r_j) = dep(DX^(r-1)_{j,j-5,j-1}) | dep(DX^(r-2)_j)
                         | (DX^(r-1)_j   != 0 ? dep(X^(r-1)_{j-5}) : nothing)
                         | (DX^(r-1)_{j-5} != 0 ? dep(X^(r-1)_j)   : nothing)

The two conditional terms are the non-linear part of the round: a state bit is
only requested when the OTHER factor of the product is not known to be zero.
This is why a determined 0 saves keys while a determined 1 does not.

Atilde_j = A_j ^ DA_j, so the dependency of Atilde is the dependency of the
difference chain at the A boundary; A itself is free.

================================================================================
5. LAYER 1' -- PP LAYER AND THE KEYLESS BOUNDARY ROUNDS
================================================================================
The attack splits E as

    E = Ein1' o RF* o E_c o RF* o Eout0' o E_dist o Ein0

where E_c is the parallel-partitioning layer (A -> B) and the two round
functions glued to it are used WITHOUT their round keys ("RFwithoutRK" in
1data.mzn; no_key_round = {rB} for the in side, {rA-1} for the out side).
Algebraically the boundary key is folded into the state:

    A^L = X^rA      ^ k^(rA-1) = F(X^(rA-1)) ^ X^(rA-2)      (out side, free)
    B^R = X^(rB-1)  ^ k^(rB)   = F(X^(rB))   ^ X^(rB+1)      (in  side, free)
    B^L = X^(rB)   = C^R                                     (ciphertext word)

The folded keys reappear only in the matching equations, e.g. the recovery
step  A^L ^ B^R = k^(rA-1) ^ k^(rA+1).

CONSEQUENCE: computing B and Btilde costs ZERO round-key bits.  The in-side
recursion therefore returns the empty set at the boundary layer rB-1, and only
starts charging keys again if one insists on going deeper (which the attack
does not do).

================================================================================
6. LAYER 1'' -- IN-SIDE PLAINTEXT PART
================================================================================
The plaintext side runs the difference chain in the opposite direction:

    DX^r_j = [F'(DX^(r+1))]_j ^ DX^(r+2)_j

with the coefficient states computed from the plaintext, X^r_j =
F(X^(r-1))_j ^ X^(r-2)_j ^ k^(r-1)_j.  This is where k^(1) enters: a
determined 1 in the trail makes the coefficient state necessary.

================================================================================
7. LAYER 1''' -- PE VERIFICATION (k_gamma)
================================================================================
To verify "DX^(r)_j = 0" one cannot use the trail's own verdict, so the target
bit is treated as unknown and recomputed from delta_out.  The recursion is the
difference recursion above, but a term is dropped whenever the trail DETERMINES
the corresponding difference (that part of the knowledge is genuine):
a determined 0 removes the whole monomial, a determined 1 removes only the
difference factor and leaves the coefficient state.  This reproduces the
k_gamma sets printed in 2x/attack_details.pdf exactly.

================================================================================
8. LAYER 2 -- THE CHECK
================================================================================
    S_out = union over j of dep(Atilde_j)                      subset of k_out ?
    S_in  = union over j of dep(B_j), dep(Btilde_j)            subset of k_in  ?
    S_pt  = union over j of dep(DP_j)                          subset of k_in  ?

The criterion is CONTAINMENT, not equality: the paper declares extra key bits
for the matching filter, the key-schedule closure and the master-key recovery,
so a strict subset is expected and correct.
"""

import sys

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
STAR = 2                      # the '*' of the truncated propagation


def word_bits(value, n):
    """integer -> list of n bits, index 0 = least significant."""
    return [(value >> j) & 1 for j in range(n)]


def show(S):
    """{(round, bit)} -> 'k^(19)_{6,12}  k^(20)_{1,5,6}'."""
    if not S:
        return "empty"
    out = []
    for r in sorted({r for r, _ in S}):
        bits = ",".join(str(j) for j in sorted(jj for rr, jj in S if rr == r))
        out.append("k^(%d)_{%s}" % (r, bits))
    return "  ".join(out)


def show_short(S):
    return show(S)


# ---------------------------------------------------------------------------
# layer 0 -- truncated trail
# ---------------------------------------------------------------------------
def deriv_det(P, L, j):
    """Is [F'(L)]_j determined?  (True, value) if yes."""
    a, b, c = L[j % P.N], L[(j - P.RB) % P.N], L[(j - P.RC) % P.N]
    if a == STAR or b == STAR or c == STAR or a != 0 or b != 0:
        return False, 0
    return True, c


def step_fwd(P, L, R):
    """one round towards the ciphertext: new_j = [F'(L)]_j ^ R_j."""
    out = []
    for j in range(P.N):
        det, val = deriv_det(P, L, j)
        out.append(STAR if (not det or R[j] == STAR) else val ^ R[j])
    return out


def step_bwd(P, new, L):
    """one round towards the plaintext: R_j = [F'(L)]_j ^ new_j."""
    out = []
    for j in range(P.N):
        det, val = deriv_det(P, L, j)
        out.append(STAR if (not det or new[j] == STAR) else val ^ new[j])
    return out


def build_trail(P):
    """Gamma_in downwards from delta_in, Gamma_out upwards from delta_out.

    The probabilistic-extension points are forced to 0 AFTER the row has been
    produced, so that the forced zeros are what the next rounds propagate.
    """
    T = {}
    T[P.rIN] = word_bits(P.DELTA_IN[P.rIN], P.N)
    T[P.rIN - 1] = word_bits(P.DELTA_IN[P.rIN - 1], P.N)
    for i in range(P.rIN - 1, 0, -1):
        T[i - 1] = step_bwd(P, T[i + 1], T[i])

    T[P.rOUT] = word_bits(P.DELTA_OUT[P.rOUT], P.N)
    T[P.rOUT - 1] = word_bits(P.DELTA_OUT[P.rOUT - 1], P.N)
    for i in range(P.rOUT, P.RR):
        T[i + 1] = step_fwd(P, T[i], T[i - 1])
        for (rr, jj) in P.PE:
            if rr == i + 1:
                T[rr][jj] = 0
    return T


def trail_str(row):
    if row is None:
        return "(not propagated)"
    return "".join("*" if row[j] == STAR else str(row[j]) for j in reversed(range(len(row))))


# ---------------------------------------------------------------------------
# layer 1 -- per-bit key dependency
# ---------------------------------------------------------------------------
class Dep:
    """All recurrences.  Every return value is a frozenset of (round, bit)."""

    def __init__(self, P, trail):
        self.P = P
        self.T = trail
        self.Z = {(i, j) for i, row in trail.items()
                  for j in range(P.N) if row[j] == 0}
        self._xout, self._dout = {}, {}
        self._xin, self._xf, self._din = {}, {}, {}
        self._pe = {}

    @staticmethod
    def k(i, j, n):
        return frozenset({(i, j % n)})

    def val(self, r, j):
        row = self.T.get(r)
        return None if row is None else row[j % self.P.N]

    # ---- out side: A is enumerated, (rA-1, rA-2) are the seeds -------------
    def Xout(self, i, j):
        """X^i from the A side: X^i = F(X^(i+1)) ^ X^(i+2) ^ k^(i+1)."""
        P = self.P
        j %= P.N
        if (i, j) in P.GS_OUT:
            return frozenset()
        if (i, j) in self._xout:
            return self._xout[(i, j)]
        if i in (P.rA - 1, P.rA - 2) or i > P.RR:
            v = frozenset()                       # part of A / the ciphertext
        else:
            v = (self.Xout(i + 2, j)
                 | self.Xout(i + 1, j) | self.Xout(i + 1, j - P.RB) | self.Xout(i + 1, j - P.RC)
                 | self.k(i + 1, j, P.N))
        self._xout[(i, j)] = v
        return v

    def Dout(self, i, j):
        """Difference DX^i from the delta_out side (compute semantics)."""
        P = self.P
        j %= P.N
        if (i, j) in P.GD_OUT:
            return frozenset()
        if (i, j) in self._dout:
            return self._dout[(i, j)]
        row = self.T.get(i)
        if row is not None and row[j] != STAR:
            v = frozenset()                       # fixed by the trail: free
        elif i <= P.rOUT:
            v = frozenset()                       # delta_out itself
        else:
            v = (self.Dout(i - 1, j)
                 | self.Dout(i - 1, j - P.RB) | self.Dout(i - 1, j - P.RC)
                 | self.Dout(i - 2, j))
            if (i - 1, j) not in self.Z:          # term DX_(j) * X_(j-5)
                v = v | self.Xout(i - 1, j - P.RB)
            if (i - 1, (j - P.RB) % P.N) not in self.Z:   # term X_j * DX_(j-5)
                v = v | self.Xout(i - 1, j)
        self._dout[(i, j)] = v
        return v

    # ---- in side: the ciphertext is (X^RR, X^(RR-1)) ----------------------
    def Xin(self, i, j):
        """State on the in side, with the folded boundary key.

        The PP boundary round is keyless: layer rB-1 is available as
        X^(rB-1) ^ k^(rB) = F(X^(rB)) ^ X^(rB+1), so it costs nothing.
        Going one layer deeper forces the fold to be undone, which brings both
        k^(rB) and k^(rB-1) back -- the attack never does this.
        """
        P = self.P
        j %= P.N
        if (i, j) in P.GS_IN:
            return frozenset()
        if (i, j) in self._xin:
            return self._xin[(i, j)]
        if i >= P.RR - 1:
            v = frozenset()                       # X^RR, X^(RR-1) = ciphertext
        elif i == P.rB - 1:
            v = frozenset()                       # folded: keyless boundary
        elif i == P.rB - 2:
            v = (self.k(P.rB, j, P.N) | self.k(P.rB, j - P.RB, P.N)
                 | self.k(P.rB, j - P.RC, P.N) | self.k(P.rB - 1, j, P.N))
        else:
            v = (self.Xin(i + 1, j)
                 | self.Xin(i + 1, j - P.RB) | self.Xin(i + 1, j - P.RC)
                 | self.Xin(i + 2, j)
                 | self.k(i + 1, j, P.N))
        self._xin[(i, j)] = v
        return v

    def Xf(self, i, j):
        """State on the in side computed from the plaintext (X^1, X^0)."""
        P = self.P
        j %= P.N
        if (i, j) in P.GS_IN:
            return frozenset()
        if (i, j) in self._xf:
            return self._xf[(i, j)]
        if i <= 1:
            v = frozenset()
        else:
            v = (self.Xf(i - 1, j)
                 | self.Xf(i - 1, j - P.RB) | self.Xf(i - 1, j - P.RC)
                 | self.Xf(i - 2, j)
                 | self.k(i - 1, j, P.N))
        self._xf[(i, j)] = v
        return v

    def Din(self, i, j):
        """Difference towards the plaintext: DX^i from DX^(i+1), DX^(i+2)."""
        P = self.P
        j %= P.N
        if (i, j) in P.GD_IN:
            return frozenset()
        if (i, j) in self._din:
            return self._din[(i, j)]
        row = self.T.get(i)
        if row is not None and row[j] != STAR:
            v = frozenset()
        elif i >= P.rIN:
            v = frozenset()                       # delta_in itself
        else:
            up = self.T.get(i + 1)
            v = (self.Din(i + 1, j)
                 | self.Din(i + 1, j - P.RB) | self.Din(i + 1, j - P.RC)
                 | self.Din(i + 2, j))
            if up is not None and up[j] != 0:               # term D_j * X_(j-5)
                v = v | self.Xf(i + 1, j - P.RB)
            if up is not None and up[(j - P.RB) % P.N] != 0:  # term X_j * D_(j-5)
                v = v | self.Xf(i + 1, j)
        self._din[(i, j)] = v
        return v

    # ---- PE / GD verification (k_gamma, k_dout) --------------------------
    def pe(self, r, j, use_gd=True):
        """Keys needed to VERIFY DX^(r)_j = 0.

        The target bit is recomputed from delta_out instead of being read off
        the trail; every other trail-determined bit is still used as knowledge,
        because the trail is a proof and not an assumption.

        use_gd: whether a bit listed in GD (the difference-test bits that the
        attack guesses outright) still terminates the recursion.  For the
        k_gamma row it does -- the attack simply guesses those bits.  For the
        k_dout row (the keys that *would* be needed to compute them) it must be
        switched off, which is what pe_gd does.
        """
        P = self.P
        j %= P.N
        if use_gd and (r, j) in P.GD_OUT:
            return frozenset()
        if (r, j, use_gd) in self._pe:
            return self._pe[(r, j, use_gd)]
        if r <= P.rOUT:
            v = frozenset()
        else:
            v = frozenset()
            d2 = self.val(r - 2, j)
            if d2 is None or d2 == STAR:                     # ^ DX^(r-2)_j
                v = v | self.pe(r - 2, j, use_gd)
            dj, dj5 = self.val(r - 1, j), self.val(r - 1, j - P.RB)
            dj1 = self.val(r - 1, j - P.RC)
            if dj is None or dj == STAR:                     # term D_j * X_(j-5)
                v = v | self.pe(r - 1, j, use_gd) | self.Xout(r - 1, j - P.RB)
            elif dj == 1:
                v = v | self.Xout(r - 1, j - P.RB)
            if dj5 is None or dj5 == STAR:                   # term X_j * D_(j-5)
                v = v | self.pe(r - 1, j - P.RB, use_gd) | self.Xout(r - 1, j)
            elif dj5 == 1:
                v = v | self.Xout(r - 1, j)
            if (dj is None or dj == STAR) and (dj5 is None or dj5 == STAR):
                v = v | self.pe(r - 1, j, use_gd) | self.pe(r - 1, j - P.RB, use_gd)
            elif (dj is None or dj == STAR) and dj5 == 1:
                v = v | self.pe(r - 1, j, use_gd)
            elif dj == 1 and (dj5 is None or dj5 == STAR):
                v = v | self.pe(r - 1, j - P.RB, use_gd)
            if dj1 is None or dj1 == STAR:                   # term D_(j-1)
                v = v | self.pe(r - 1, j - P.RC, use_gd)
        self._pe[(r, j, use_gd)] = v
        return v

    def pe_gd(self, r, j):
        """Keys that would be needed to COMPUTE a guessed difference bit."""
        return self.pe(r, j, use_gd=False)

    # ---- the four matching objects ---------------------------------------
    def object(self, name, j):
        """2n-bit state index -> key dependency of that object bit."""
        P = self.P
        j %= 2 * P.N
        left, b = j < P.N, j % P.N
        if name == "A":
            return frozenset()                        # enumerated
        if name == "B":
            return self.Xin(P.rB, b) if left else self.Xin(P.rB - 1, b)
        if name == "At":
            return self.Dout(P.rA, b) if left else self.Dout(P.rA - 1, b)
        if name == "Bt":
            return self.Xin(P.rB, b) if left else self.Xin(P.rB - 1, b)
        raise KeyError(name)


# ---------------------------------------------------------------------------
# report sections
# ---------------------------------------------------------------------------
def part_trail(P, T):
    print("[0] truncated trails (Gamma_in from delta_in, Gamma_out from delta_out)")
    print("    probabilistic-extension points forced to 0: %s"
          % (", ".join("DX^(%d)_%d" % p for p in P.PE) if P.PE else "none"))
    print("    state-test bits (GS): %s" % (show(P.GS_IN | P.GS_OUT) if (P.GS_IN or P.GS_OUT) else "none"))
    print("    difference-test bits (GD): %s" % (show(P.GD_IN | P.GD_OUT) if (P.GD_IN or P.GD_OUT) else "none"))
    print("    row    X^r (left word)            X^(r-1) (right word)   note")
    for r in sorted(T):
        row, row2 = T[r], T.get(r - 1)
        note = ""
        if r == P.rIN:
            note = "delta_in given at (X^%d, X^%d)" % (P.rIN, P.rIN - 1)
        elif r == P.rOUT:
            note = "delta_out given at (X^%d, X^%d)" % (P.rOUT, P.rOUT - 1)
        elif r == P.rA:
            note = "A = (X^%d, X^%d)" % (P.rA, P.rA - 1)
        elif r == P.rB:
            note = "B = (X^%d, X^%d)" % (P.rB, P.rB - 1)
        elif r == P.RR:
            note = "ciphertext C = (X^%d, X^%d)" % (P.RR, P.RR - 1)
        elif r == P.rSTART:
            note = "plaintext P = (X^%d, X^%d)" % (P.rSTART, P.rSTART - 1)
        print("    X^%-3d %s  %-22s %s" % (r, trail_str(row), trail_str(row2), note))
    det = lambda r: sum(1 for j in range(P.N) if T[r][j] != STAR)
    print("    determined bits: n_P = %d, n_B = %d" % (det(1) + det(0), det(P.rB) + det(P.rB - 1)))
    print()


def part_bits(P, dep):
    print("[1] per-bit key dependency (number = key bits involved by that bit)")
    print("    out side: A enumerated, Atilde = A ^ DA along the difference chain")
    print("      A^L  bits 0..%d : zero (enumerated)" % (P.N - 1))
    left = [dep.object("At", j) for j in range(P.N)]
    right = [dep.object("At", j + P.N) for j in range(P.N)]
    print("      At^L bits 0..%d : %s   union %d"
          % (P.N - 1, " ".join("%2d" % len(s) for s in left),
             len(frozenset().union(*left))))
    print("      At^R bits 0..%d : %s   union %d"
          % (P.N - 1, " ".join("%2d" % len(s) for s in right),
             len(frozenset().union(*right))))
    print("    in side: (X^%d, X^%d) is the ciphertext; the boundary round folds k^(%d)"
          % (P.RR, P.RR - 1, P.rB))
    for name, lab in (("B", "B"), ("Bt", "Btilde")):
        left = [dep.object(name, j) for j in range(P.N)]
        right = [dep.object(name, j + P.N) for j in range(P.N)]
        print("      %-6s^L bits 0..%d : %s   union %d"
              % (lab, P.N - 1, " ".join("%2d" % len(s) for s in left),
                 len(frozenset().union(*left))))
        print("      %-6s^R bits 0..%d : %s   union %d"
              % (lab, P.N - 1, " ".join("%2d" % len(s) for s in right),
                 len(frozenset().union(*right))))
    lp = [dep.Din(1, j) for j in range(P.N)]
    rp = [dep.Din(0, j) for j in range(P.N)]
    print("    plaintext side: DP check (a determined 1 in the trail forces the")
    print("    coefficient state, hence k^(1))")
    print("      DP^L bits 0..%d : %s   union %d"
          % (P.N - 1, " ".join("%2d" % len(s) for s in lp),
             len(frozenset().union(*(lp + rp)))))
    print("      DP^R bits 0..%d : %s" % (P.N - 1, " ".join("%2d" % len(s) for s in rp)))
    print()


def dependency_sets(P, dep):
    S_out = frozenset().union(*[dep.object("At", j) for j in sorted(P.J_OUT)])
    S_in = frozenset().union(*[dep.object(nm, j) for nm in ("B", "Bt") for j in sorted(P.J_IN)])
    S_pt = frozenset().union(*[dep.Din(i, j) for i in (1, 0) for j in range(P.N)])
    return S_out, S_in, S_pt


def part_check(P, dep):
    S_out, S_in, S_pt = dependency_sets(P, dep)
    print("[2] check against the declared key sets (criterion: containment)")
    print("  S_out = union dep(Atilde)   = %2d bits : %s" % (len(S_out), show(S_out)))
    print("  k_out                       = %2d bits" % len(P.K_OUT))
    mo = set(S_out) - P.K_OUT
    print("  S_out subset of k_out       : %s%s"
          % ("yes" if not mo else "NO", "" if not mo else "   outside: " + show(mo)))
    print()
    print("  in side (the PP boundary round itself needs no round key):")
    print("  S_in  = union dep(B), dep(Btilde) = %2d bits" % len(S_in))
    print("  S_pt  = union dep(DP)             = %2d bits : %s" % (len(S_pt), show(S_pt)))
    print("  k_in                              = %2d bits : %s" % (len(P.K_IN), show(P.K_IN)))
    mi = (set(S_in) | set(S_pt)) - P.K_IN
    print("  S_in | S_pt subset of k_in        : %s%s"
          % ("yes" if not mi else "NO", "" if not mi else "   outside: " + show(mi)))
    print()
    cover = P.K_IN - (set(S_in) | set(S_pt))
    print("  where the %d bits of k_in come from:" % len(P.K_IN))
    print("    B / Btilde   -> %2d bits : %s" % (len(S_in), show(S_in)))
    print("    plaintext    -> %2d bits : %s" % (len(S_pt), show(S_pt)))
    print("    declared (matching correction / key-schedule closure): %2d bits : %s"
          % (len(cover), show(cover)))
    print("    (the last group is taken from the paper; see README, section SCOPE)")
    print()
    ok = not mo and not mi
    print("  RESULT: key-dependency check %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def part_kgamma(P, dep):
    print("[3] k_gamma check: keys needed to verify the probabilistic-extension bits")
    print("    reference: the attack-details sheet shipped with the paper")
    print("-" * 76)
    ok = True
    for label, pos, ref in P.KGAMMA:
        got = set(frozenset().union(*[dep.pe(r, j) for (r, j) in pos]))
        ref = set(ref)
        same = got == ref
        ok = ok and same
        print("%-40s %2d bits  %s" % (label, len(got), "matches the sheet" if same else "MISMATCH"))
        print("    derived : %s" % show(got))
        if not same:
            print("    sheet   : %s" % show(ref))
            print("    diff    : %s" % show(got ^ ref))
        print("    subset of k_out: %s" % ("yes" if got <= P.K_OUT else "no"))
    print("-" * 76)
    print("k_gamma check %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def part_kdout(P, dep):
    ref = getattr(P, "KDOUT", [])
    print("[4] k_dout check: keys needed to COMPUTE the difference-test bits")
    print("    reference: the attack-details sheet shipped with the paper")
    print("-" * 76)
    if not ref:
        print("this instance guesses no difference bit (d_out = empty),")
        print("so there is no k_dout row to reproduce")
        print("-" * 76)
        return 0
    ok = True
    for label, pos, expected in ref:
        got = set(frozenset().union(*[dep.pe_gd(r, j) for (r, j) in pos]))
        expected = set(expected)
        same = got == expected
        ok = ok and same
        print("%-40s %2d bits  %s" % (label, len(got), "matches the sheet" if same else "MISMATCH"))
        print("    derived : %s" % show(got))
        if not same:
            print("    sheet   : %s" % show(expected))
            print("    diff    : %s" % show(got ^ expected))
        print("    subset of k_out: %s" % ("yes" if got <= P.K_OUT else "no"))
    print("-" * 76)
    print("k_dout check %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_bits(s, limit):
    """'5' / '5,12' / '0-15' / 'all' -> sorted list of bit indices."""
    s = s.strip().lower()
    if s in ("all", "*"):
        return list(range(limit))
    out = set()
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    bad = [j for j in out if not (0 <= j < limit)]
    if bad:
        raise ValueError("bit index %s outside 0..%d" % (bad, limit - 1))
    return sorted(out)


def fmt_bits(bits):
    if len(bits) == 1:
        return "[%d]" % bits[0]
    if bits == list(range(bits[0], bits[-1] + 1)):
        return "[%d..%d]" % (bits[0], bits[-1])
    return "[%s]" % ",".join(str(j) for j in bits)


def emit(entries, K, side):
    union = frozenset().union(*[s for _, s in entries]) if entries else frozenset()
    if len(entries) <= 4:
        for name, S in entries:
            print("  %-16s : %2d bits   %s" % (name, len(S), show_short(S)))
    else:
        print("  per-bit counts   : " + " ".join("%s:%d" % (n, len(s)) for n, s in entries))
    print("  %-16s : %2d bits   %s" % ("union", len(union), show_short(union)))
    bad = set(union) - K
    print("  subset of k_%-5s: %s%s" % (side, "yes" if not bad else "no",
                                       "" if not bad else "   outside: " + show(bad)))
    return 0 if not bad else 1


def q_object(P, dep, kind, spec):
    name = {"atA": "At", "atB": "Bt", "B": "B", "A": "A"}[kind]
    bits = parse_bits(spec, 2 * P.N)
    side = "out" if name in ("A", "At") else "in"
    K = P.K_OUT if side == "out" else P.K_IN
    label = {"A": "A", "At": "Atilde", "B": "B", "Bt": "Btilde"}[name]
    print("%s%s (%s side, %d bit(s); index 0..%d = left word, %d..%d = right word)"
          % (label, fmt_bits(bits), side, len(bits), P.N - 1, P.N, 2 * P.N - 1))
    entries = [("%s[%d]" % (label, j), dep.object(name, j)) for j in bits]
    return emit(entries, K, side)


def q_state(P, dep, kind, r, spec):
    bits = parse_bits(spec, P.N)
    if kind == "sin":
        if r <= P.rIN:
            f, sym = dep.Xf, "X"
            print("in-side state X^(%d)_j: computed from the plaintext" % r)
        elif r >= P.rB - 1:
            f, sym = dep.Xin, "X"
            print("in-side state X^(%d)_j: computed from the ciphertext "
                  "(boundary key k^(%d) folded into the state)" % (r, P.rB))
        else:
            print("in-side state X^(%d)_j: inside the distinguisher, the attack does "
                  "not compute this layer" % r)
            print("(the figures below are the cost IF one insisted, i.e. after "
                  "unfolding k^(%d))" % P.rB)
            entries = [("X^(%d)_%d" % (r, j), dep.Xin(r, j)) for j in bits]
            return emit(entries, P.K_IN, "in")
    else:
        f = {"sout": dep.Xout, "dout": dep.Dout, "din": dep.Din}[kind]
        sym = "X" if kind == "sout" else "DX"
        print({"sout": "out-side state X^(%d)_j: from A towards the ciphertext",
               "dout": "out-side difference DX^(%d)_j: from delta_out towards A",
               "din": "in-side difference DX^(%d)_j: from delta_in towards the plaintext"}[kind] % r)
    entries = [("%s^(%d)_%d" % (sym, r, j), f(r, j)) for j in bits]
    K = P.K_IN if kind in ("sin", "din") else P.K_OUT
    return emit(entries, K, "in" if kind in ("sin", "din") else "out")


def q_pe(P, dep, r, spec):
    bits = parse_bits(spec, P.N)
    print("PE verification: keys needed to verify DX^(%d)_j = 0 (k_gamma semantics)" % r)
    entries = [("DX^(%d)_%d" % (r, j), dep.pe(r, j)) for j in bits]
    return emit(entries, P.K_OUT, "out")


def cmd_verify(P, dep):
    S_out, S_in, S_pt = dependency_sets(P, dep)
    line = "-" * 72
    print(line)
    print(" overall check: %s" % P.NAME)
    print(line)
    miss_o = set(S_out) - P.K_OUT
    miss_i = set(S_in) - P.K_IN
    miss_p = set(S_pt) - P.K_IN
    print("  Atilde      : %2d key bits  subset of k_out(%d) : %s%s"
          % (len(S_out), len(P.K_OUT), "yes" if not miss_o else "NO",
             "" if not miss_o else "   outside: " + show(miss_o)))
    print("  B, Btilde   : %2d key bits  subset of k_in(%d)  : %s%s"
          % (len(S_in), len(P.K_IN), "yes" if not miss_i else "NO",
             "" if not miss_i else "   outside: " + show(miss_i)))
    if P.rB == P.RR - 1:
        print("                (X^%d is a ciphertext word and the boundary key is "
              "folded: 0 is expected)" % P.rB)
    else:
        print("                (X^%d is not a ciphertext word, so it is recovered "
              "through round %d;" % (P.rB, P.rB + 1))
        print("                 the PP boundary round %d itself still charges nothing)" % P.rB)
    print("  DP (in side): %2d key bits  subset of k_in(%d)  : %s%s"
          % (len(S_pt), len(P.K_IN), "yes" if not miss_p else "NO",
             "" if not miss_p else "   outside: " + show(miss_p)))
    ok = not miss_o and not miss_i and not miss_p
    print(line)
    print(" RESULT: %s" % ("PASS -- every key needed by Atilde, B, Btilde is declared"
                           if ok else "FAIL -- keys outside the declared sets"))
    print(line)
    return 0 if ok else 1


def selftest(P, dep):
    print("negative test: the checker must be able to say NO")
    print("-" * 72)
    S1 = dep.object("At", 5 % (2 * P.N))
    print("[1] a covered bit, Atilde[%d]" % (5 % (2 * P.N)))
    print("    %s  subset of k_out: %s" % (show_short(S1), "yes" if set(S1) <= P.K_OUT else "NO"))
    S2 = dep.object("B", P.N + 5)
    print("[2] an in-side bit, B[%d]" % (P.N + 5))
    print("    %s  subset of k_in : %s" % (show_short(S2), "yes" if set(S2) <= P.K_IN else "NO"))
    S3 = dep.Dout(P.RR, 0)
    print("[3] a difference beyond the attack window, DX^(%d)_0" % P.RR)
    print("    %d bits  subset of k_out: %s" % (len(S3), "yes" if set(S3) <= P.K_OUT else "NO"))
    print("[4] B and Btilde must stay inside k_in (over the bits J_in selects)")
    S4 = frozenset().union(*[dep.object(nm, j) for nm in ("B", "Bt")
                             for j in sorted(P.J_IN)])
    print("    S_in = %s (%d bits)" % (show_short(S4), len(S4)))
    print("    subset of k_in: %s" % ("yes" if set(S4) <= P.K_IN else "NO"))
    ok = ((set(S1) <= P.K_OUT) and (set(S2) <= P.K_IN)
          and not (set(S3) <= P.K_OUT) and set(S4) <= P.K_IN)
    print("-" * 72)
    print("negative test %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def usage(P):
    p = P.PROG
    print("usage (J/BIT may be 5, 5,12, 0-15 or all):")
    print("  python %s                     full report" % p)
    print("  python %s verify              overall check (PASS/FAIL)" % p)
    print("  python %s kgamma              k_gamma check against the attack sheet" % p)
    print("  python %s kdout               k_dout check (guessed difference bits)" % p)
    print("  python %s --selftest          negative test" % p)
    print("  python %s atA|atB|B|A J       one or more bits of an object" % p)
    print("  python %s sin|sout|din|dout R J" % p)
    print("  python %s pe R J              keys needed to verify DX^(R)_J = 0" % p)
    print("  python %s --help              full documentation" % p)


def run(P, argv):
    T = build_trail(P)
    dep = Dep(P, T)
    if not argv:
        line = "=" * 78
        print(line)
        print(" %s -- per-bit key dependency and matching-key check" % P.NAME)
        print(line)
        print("n=%d  rounds=%d  r_in=%d  r_out=%d  r_A=%d  r_B=%d  C=(X^%d, X^%d)"
              % (P.N, P.R, P.rIN, P.rOUT, P.rA, P.rB, P.RR, P.RR - 1))
        print("|k_in|=%d  |k_out|=%d  |PE|=%d" % (len(P.K_IN), len(P.K_OUT), len(P.PE)))
        if getattr(P, "SOURCE", None):
            print("source: %s" % P.SOURCE)
        print()
        part_trail(P, T)
        part_bits(P, dep)
        rc = part_check(P, dep)
        print()
        part_kgamma(P, dep)
        print()
        rc = max(rc, part_kdout(P, dep))
        print()
        usage(P)
        return rc

    cmd = argv[0]
    try:
        if cmd == "verify":
            return cmd_verify(P, dep)
        if cmd in ("kgamma", "--kgamma"):
            return part_kgamma(P, dep)
        if cmd in ("kdout", "--kdout"):
            return part_kdout(P, dep)
        if cmd == "--selftest":
            return selftest(P, dep)
        if cmd in ("-h", "--help"):
            print(__doc__)
            return 0
        if cmd in ("atA", "atB", "B", "A") and len(argv) == 2:
            return q_object(P, dep, cmd, argv[1])
        if cmd in ("sin", "sout", "din", "dout") and len(argv) == 3:
            return q_state(P, dep, cmd, int(argv[1]), argv[2])
        if cmd == "pe" and len(argv) == 3:
            return q_pe(P, dep, int(argv[1]), argv[2])
    except ValueError as e:
        print("bad argument: %s" % e)
        print("(ROUND/BIT must be integers; J may be 5, 5,12, 0-15 or all)")
        return 2
    print("unknown command: %s" % " ".join(argv))
    usage(P)
    return 2
