# Per-bit key dependency and matching-key check

`key_involve32.py`, `key_involve48.py`, `key_involve64.py` (+ the shared engine
`key_involve_core.py`) answer three questions about the differential
meet-in-the-middle attacks on SIMECK:

1. which round-key bits are needed to compute one given bit of `A`, `Atilde`,
   `B`, `Btilde`, of a state `X^r`, or of a difference `DX^r`;
2. which round-key bits are needed to *verify* a probabilistic-extension bit,
   i.e. to check that a chosen truncated-difference bit really is zero
   (this is the paper's `k_gamma`);
3. whether the union of those bits over everything the attack needs is
   contained in the key sets the paper declares (`k_in`, `k_out`).

Nothing is executed and no key is sampled: every answer is a symbolic
(eq. combinatorial) fact about the SIMECK round function and the key schedule.

```
./  (the folder that contains these four files)
  key_involve_core.py    engine: trail, four recurrences, PE rule, reports, CLI
  key_involve32.py       24-round SIMECK32,  A = (X^23, X^22), B = (X^24, X^23)
  key_involve48.py       33-round SIMECK48,  A = (X^32, X^31), B = (X^33, X^32)
  key_involve64.py       42-round SIMECK64,  A = (X^40, X^39), B = (X^41, X^40)
```

The three scripts contain only a parameter block; the model lives in the core.

All commands below are run **from that folder**: in the source repository it is
`verification/`, in the submission package it is the top level of `materials/`.

---

## 1. Quick start

```
python key_involve32.py            full report
python key_involve32.py verify     one-line verdict
python key_involve32.py kgamma     compare with the attack sheet
python key_involve32.py kdout      k_dout row (only SIMECK48 has one)
python key_involve32.py --selftest negative test
```

The same commands exist for 48 and 64 (`key_involve48.py`, ...).

Exit codes: `0` = the derived set is contained in the declared set,
`1` = it is not (the offending bits are printed), `2` = bad argument.

A complete green run is

```
python key_involve32.py verify && python key_involve32.py kgamma && python key_involve32.py kdout && python key_involve32.py --selftest
```

(repeat with 48 and 64).

---

## 2. Query commands

`J` and `BIT` accept a single index (`5`), a list (`5,12`), a range (`0-15`)
and `all`. For 2n-bit objects, indices `0..n-1` are the left word `X^r` and
`n..2n-1` the right word `X^(r-1)`.

| command | returns |
|---|---|
| `atA J` | keys for bit `J` of `Atilde` (out side) |
| `atB J` | keys for bit `J` of `Btilde` (in side) |
| `B J`, `A J` | keys for bit `J` of `B`, `A` |
| `sout R J` | keys for the out-side state bit `X^(R)_J` |
| `sin R J` | keys for the in-side state bit `X^(R)_J` |
| `dout R J` | keys to *compute* the out-side difference `DX^(R)_J` |
| `din R J` | keys to compute the in-side difference `DX^(R)_J` |
| `pe R J` | keys to *verify* `DX^(R)_J = 0` (the `k_gamma` reading) |

`dout` and `pe` are deliberately different. If the trail already determines
`DX^(R)_J`, then `dout` prints `empty` (computing it is free), while `pe` still
recomputes the bit from `delta_out`, which is what an attacker must do to
justify a probabilistic-extension assumption.

### Example: one bit of Atilde

```
$ python key_involve32.py atA 5
Atilde[5] (out side, 1 bit(s); index 0..15 = left word, 16..31 = right word)
  Atilde[5]        : 19 bits   k^(19)_{6,12}  k^(20)_{1,5,6,7,11,12}  k^(21)_{0,1,2,4,5,6,7,10,11,12,14}
  union            : 19 bits   ...
  subset of k_out  : yes
```

### Example: many bits at once

```
$ python key_involve32.py atA 0-15
Atilde[0..15] (out side, 16 bit(s); ...)
  per-bit counts   : Atilde[0]:18 Atilde[1]:18 Atilde[2]:19 ...
  union            : 20 bits   k^(19)_{6,12}  k^(20)_{1,5,6,7,11,12}  k^(21)_{0,1,2,4,5,6,7,8,10,11,12,14}
  subset of k_out  : yes
```

### Example: a probabilistic-extension bit

```
$ python key_involve32.py pe 20 2
PE verification: keys needed to verify DX^(20)_j = 0 (k_gamma semantics)
  DX^(20)_2        : 13 bits   k^(19)_{12}  k^(20)_{7,11,12,13}  k^(21)_{2,6,7,8,10,11,12,13}
  union            : 13 bits   ...
  subset of k_out  : no   outside: k^(20)_{13}  k^(21)_{13}
```

### Example: a bit outside the attack

```
$ python key_involve32.py dout 25 0
out-side difference DX^(25)_0: from delta_out towards A
  DX^(25)_0        : 46 bits   ... k^(24)_{0,6,10,11,15} k^(25)_{...} k^(26)_{...}
  subset of k_out  : no   outside: k^(24)_{0,10,15} k^(25)_{...} k^(26)_{...}
```

The tool therefore reports keys that the paper does not declare, which is the
intended negative behaviour.

---

## 3. The overall check

```
$ python key_involve32.py verify
------------------------------------------------------------------------
 overall check: SIMECK32 / 24 rounds
------------------------------------------------------------------------
  Atilde      : 20 key bits  subset of k_out(28) : yes
  B, Btilde   :  0 key bits  subset of k_in(18)  : yes
                (X^24 is a ciphertext word and the boundary key is folded: 0 is expected)
  DP (in side):  2 key bits  subset of k_in(18)  : yes
------------------------------------------------------------------------
 RESULT: PASS -- every key needed by Atilde, B, Btilde is declared
------------------------------------------------------------------------
```

Criterion is **containment**, not equality: the paper declares additional bits
for the matching filter, for the key-schedule closure and for master-key
recovery, so a strict subset is the expected outcome.

Results of the three instances:

| instance | `S_out` vs `k_out` | `S_in` vs `k_in` | `S_pt` (DP) vs `k_in` | `k_gamma` |
|---|---|---|---|---|
| SIMECK32 | 20 / 28 | 0 / 18 | 2 / 18 | 3 of 3 match the sheet |
| SIMECK48 | 23 / 41 | 0 / 15 | 2 / 15 | 3 of 3 groups match |
| SIMECK64 | 32 / 68 | 19 / 59 | 2 / 59 | 3 of 3 groups match |

For SIMECK64 the in side costs 19 bits of `k^(42)`: `X^41` is not a ciphertext
word there (`r_B = 41`, `RR = 43`), so it has to be recovered through round 42.
For SIMECK32 and SIMECK48 `X^rB` *is* a ciphertext word, hence 0.

---

## 4. Why B and Btilde (almost) cost nothing: the keyless boundary round

The attack decomposes the cipher as

```
E = Ein1' o RF* o E_c o RF* o Eout0' o E_dist o Ein0
```

where `E_c` is the parallel-partitioning layer `A -> B` and the two round
functions glued to it are used **without their round keys** (`RFwithoutRK` in
`1data.mzn`; `no_key_round = {rB}` on the in side, `{rA-1}` on the out side).
The boundary keys are folded into the matched states:

```
A^L = X^rA      ^ k^(rA-1) = F(X^(rA-1)) ^ X^(rA-2)     (out side, free)
B^R = X^(rB-1)  ^ k^(rB)   = F(X^(rB))   ^ X^(rB+1)     (in  side, free)
```

so computing `B^R` needs no key at all. The folded keys reappear only in the
matching equations; e.g. the recovery step of the 24-round attack is

```
A^L ^ B^R = k^(22) ^ k^(24)
```

This is why `verify` prints `0` for `B, Btilde` on SIMECK32/48, and why the
earlier naive model (which charged `k^(24)` for computing `X^23`) was wrong.

The plaintext part is the only place where the in side pays: the trail has a
determined `1` at `DX^2_0`, so the coefficient states `X^2_5` and `X^2_11`
must be evaluated, which costs `k^(1)_5` and `k^(1)_11`.

---

## 5. The model, rule by rule

Round function and indexing:

```
X^(r+1) = F(X^r) ^ X^(r-1) ^ k^(r),     F(x)_j = x_j x_(j-5) ^ x_(j-1)
```

**R0 - truncated trail.** Difference bits are `0`, `1` or `*`. `[F'(D)]_j` is
determined iff `D_j = D_(j-5) = 0` and none of `D_j, D_(j-5), D_(j-1)` is `*`;
then it equals `D_(j-1)`. `Gamma_in` runs from `delta_in` towards the plaintext,
`Gamma_out` from `delta_out` towards the ciphertext, and the
probabilistic-extension points are forced to 0 and re-propagated.

**R1 - state, out side.** `dep(X^r_j) = dep(X^(r+1)_{j,j-5,j-1}) |
dep(X^(r+2)_j) | {k^(r+1)_j}`, seeded at `A = (X^rA, X^(rA-1))`, which the
matching structure enumerates.

**R2 - difference, out side.** `dep(DX^r_j)` collects the same four predecessor
differences plus the two coefficient states, and a coefficient state is
requested only when the other factor of the product is not a determined zero.
This is why determined zeros save keys and determined ones do not.

**R3 - in side.** Ciphertext direction with the folded boundary (section 4),
plaintext direction for the `DP` part, and the difference chain towards the
plaintext for `din`.

**R4 - PE verification.** Same as R2 but the target bit is recomputed from
`delta_out` instead of being read off the trail; trail-determined values are
still used as knowledge (a determined 0 kills the monomial, a determined 1
keeps the coefficient state). This reproduces the `k_gamma` sets of the
`2x/3x/4x attack_details` sheets exactly.

**R5 - check.** `S_out` over `J_out`, `S_in` and `S_pt` over `J_in`, then
containment in `k_out` / `k_in`.

`GS`/`GD` (state-test / difference-test bits) terminate every recursion, and
`J_in` restricts which state bits the in side actually evaluates (this matters
for SIMECK64 only).

---

## 6. The `kgamma` command

The attack sheets group the probabilistic-extension bits into relations. The
`k_gamma` check reproduces those groups and compares the union bit by bit:

```
$ python key_involve32.py kgamma
DX^(20)_2 = DX^(19)_1 ^ X^(19)_-3    13 bits  matches the sheet
DX^(18)_0 = X^(17)_-5                20 bits  matches the sheet
DX^(18)_5 = X^(17)_5                 20 bits  matches the sheet
k_gamma check PASSED
```

For SIMECK48 and SIMECK64 the sheet gives three *grouped* relations (six PE
bits), e.g. for 48:

```
DX^(28)_5 || DX^(27)_6 = X^(27)_5 || X^(26)_6                                   20 bits
DX^(28)_0 || DX^(26)_5 || DX^(26)_0 = X^(27)_-5 || X^(25)_5 || X^(25)_-5        56 bits
DX^(27)_1 = X^(26)_-1                                                           20 bits
```

Each is compared as a union. Note that `k_gamma` is **not** contained in
`k_out`; the check prints this explicitly, because it is exactly the reason the
paper ends up with `gamma'_out = empty` and `lambda_out = p_out`.

---

## 7. The `kdout` command — the difference-test bits

SIMECK48 additionally guesses two difference bits outright
(`d_out = DX_2^(29) || DX_2^(28)`, the difference-test technique). The paper
reports the keys that would be needed to *compute* them as the row `k_dout` of
`tab:sim48`, and that row is also printed in the `key4GS.mzn` box of
`33attack_details.pdf`. The `kdout` check reproduces it:

```
$ python key_involve48.py kdout
DX^(29)_2 || DX^(28)_2                   10 bits  matches the sheet
    derived : k^(28)_{21}  k^(29)_{16,20,21}  k^(30)_{11,15,16,19,20,21}
    subset of k_out: no
k_dout check PASSED
```

Mechanically it is the same recursion as `pe` with one switch flipped: for
`kgamma` a bit listed in `GD` terminates the recursion (the attack simply
guesses it), while for `kdout` the guess is disabled (`use_gd = False`) so that
the keys a computation would cost are exposed. As with `k_gamma`, these keys
lie outside `k_out^stab` — that is precisely why the difference-test technique
is needed.

SIMECK32 and SIMECK64 guess no difference bit (`d_out = empty`), and the same
command then prints that there is no `k_dout` row to reproduce.

---

## 8. Parameters

Every parameter is transcribed by hand from the paper tables (`tab:sim32`,
`tab:sim48`, `tab:sim64`) and from the final block of `result.txt`:

| field | meaning |
|---|---|
| `N`, `RA/RB/RC`, `R`, `RR` | half block size, rotation constants, rounds, ciphertext round |
| `rSTART`, `rIN`, `rOUT`, `rEND`, `rA`, `rB` | attack layout |
| `DELTA_IN`, `DELTA_OUT` | the distinguisher differences as word values |
| `PE` | probabilistic-extension points (`gamma_out`) |
| `K_IN`, `K_OUT` | the declared `k_in^stab`, `k_out^stab` |
| `GS_IN/GD_IN/GS_OUT/GD_OUT` | state-test / difference-test bits |
| `J_IN`, `J_OUT` | the 2n-bit positions the attack really needs |
| `KGAMMA` | reference sets transcribed from the attack-details sheet |

---

## 9. Scope and known data caveats

* **Derived here**: the truncated trail, every per-bit dependency, the
  `k_gamma` sets, and hence `S_out`, `S_in`, `S_pt`.
* **Taken from the paper**: the declared `k_in`/`k_out` and the `k_gamma`
  reference sets. The `verify` output labels the part of `k_in` that is not
  re-derived ("declared (matching correction / key-schedule closure)"), i.e.
  the bits used by the recovery stage and by `F_in(k_in) = F_out(k_out)`.
* **Which block of `result.txt` is used.** SIMECK32 and SIMECK48 take the last
  block of their log. SIMECK64 takes the SECOND-TO-LAST block, because the CP
  model minimises `T1` alone while the memory-reduction technique divides the
  memory by `2^|k_in^gen cap k_out^gen|`, so the quantity that is actually
  optimised is `T1 - |common|`:

  | instance | block of `result.txt` | `T1` | `k_in` | `k_out` | `common` |
  |---|---|---|---|---|---|
  | SIMECK32 | last | 5106 | 18 | 28 | 6 |
  | SIMECK48 | last | 6242 | 15 | 41 | 3 |
  | SIMECK64 | second-to-last | 10441 | 59 | 68 | 19 |

  For SIMECK64 the last block gives `10341 - 1200 = 9141`, while the
  second-to-last gives `10441 - 1900 = 8541`: the second-to-last block is the
  memory-optimal solution and is exactly the one printed in the paper table
  (`k_in^stab` 59 bits, `k_out^stab` 68 bits,
  `|k_in^gen cap k_out^gen| = 19`).
* The three scripts verify the *dependency* facts. They do not re-run the CP
  optimisation, so they cannot certify that `k_in`/`k_out` are minimal.

---

## 10. Reproduction

Python 3.7+, no third-party packages, no files read or written. Each script is
independent apart from importing `key_involve_core.py` from its own directory.

```
python key_involve32.py
python key_involve48.py
python key_involve64.py
```
