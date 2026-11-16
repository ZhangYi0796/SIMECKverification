# Material for "Partial Enumeration-Matching Trade-offs in Multiple Differential Meet-in-the-Middle Attacks: Application to SIMECK"

This package contains everything behind the attack parameters reported in the
paper for the three SIMECK instances (24-round SIMECK32, 33-round SIMECK48,
42-round SIMECK64):

* the solver output of the constraint-programming search (`models/result.txt`);
* runnable MiniZinc checkers that print the key bits behind the
  probabilistic-extension points and the guessed difference bits
  (`check_mode/`);
* a readable dump of the attack that the paper reports, for each instance
  (`24attack_details.pdf`, `33attack_details.pdf`, `42attack_details.pdf`);
* the matching relations `G_in(B, Btilde, k_in) = G_out(A, Atilde, k_out)`
  written out for every filter bit (`L_relations.txt`);
* an independent Python suite that re-derives the per-bit key involvement and
  checks them against the declared key sets (`key_involve*.py`).

Two independent routes lead to the same numbers. The CP model *searches* for
the cheapest attack; the Python programs *re-derive* the truncated trail and
the key involvement from the cipher's own equations, without MiniZinc and
without running the cipher. They agree bit for bit on all three instances.

---

## 1. Layout

```
materials/
├── README.md                     this file
├── README_key_involve.md         detailed documentation of the Python suite
├── key_involve_core.py           shared engine of the Python suite
├── key_involve32.py              SIMECK32 parameters (24 rounds)
├── key_involve48.py              SIMECK48 parameters (33 rounds)
├── key_involve64.py              SIMECK64 parameters (42 rounds)
├── L_relations.txt               explicit G_in / G_out of every filter bit
├── SIMECK32/
│   ├── models/
│   │   └── result.txt            solver log (sequence of solutions)
│   ├── check_mode/               1data.mzn, 2var.mzn, 3diff_propagation.mzn,
│   │                            4key_involve.mzn, key4PE.mzn
│   └── 24attack_details.pdf      dump of the reported attack
├── SIMECK48/
│   ├── models/
│   │   └── result.txt
│   ├── check_mode/               as above, plus key4GS.mzn
│   └── 33attack_details.pdf
└── SIMECK64/
    ├── models/
    │   └── result.txt
    ├── check_mode/               as above
    ├── 42attack_details.pdf
    └── 42attack_detail.py        step-by-step recovery of the extra key bits
```

`models/` holds only the solver output; the search driver itself is not part of
this package. Everything needed to re-run the *key-involvement* queries is in
`check_mode/`, which is self-contained (it contains the first-layer dependency
model `4key_involve.mzn` and its prerequisites).

---

## 2. `models/result.txt` — the solver log

`result.txt` was produced with

```
minizinc --solver cp-sat -p 20 -a 6main.mzn
```

`-a` prints every solution that improves the objective, so the file is a
*sequence* of complete and valid attacks with decreasing `T1`, not a single
one. Each block is self-contained: layout (`rstart`, `rin`, `rout`, `rend`,
`rA`, `rB`, `RR`), `remain_k_num`, `T1`..`T5`, the truncated trail `DT`, the
probabilistic-extension points `PD`, the involvement sets `DIN/SIN/KIN`,
`DOUT/SOUT/KOUT`, the key-schedule closures (`fullkin`, `fullkout`,
`fullkinout`), the generating subsets (`min_kin`, `min_kout`), `common_k`,
`cross_k`, the guessed bits `GDin/GSin/GDout/GSout`, and the four filter sets
`dAL_filter`, `AL_filter`, `dAR_filter`, `AR_filter`.

The block reported in the paper is:

| instance | rounds | block of `result.txt` | `T1` | `T2` | `T3` | `T5` | `T4` | `remain_k_num` |
|---|---|---|---|---|---|---|---|---|
| SIMECK32 | 24 | last | 5106 | 5500 | 6306 | 6406 | 9706 | 34 |
| SIMECK48 | 33 | last | 6242 | 8800 | 9542 | 9542 | 14742 | 52 |
| SIMECK64 | 42 | **second-to-last** | 10441 | 11900 | 12741 | 12641 | 18141 | 54 |

`T1`..`T5` are scaled by 100, i.e. `5106` means 51.06 bits.

**Why SIMECK64 uses the second-to-last block.** The model minimises `T1`
alone, but the memory-reduction technique stores only one `k_in` (resp.
`k_out`) per value of `F_in` (resp. `F_out`), which divides the memory by
`2^|k_in^gen cap k_out^gen|`. The quantity that is actually optimised is
therefore `T1 - |common|`:

| block | `T1` | `|common|` | `T1 - |common|` |
|---|---|---|
| last | 10341 | 12 | 9141 |
| second-to-last | 10441 | 19 | **8541** |

so the second-to-last block is the memory-optimal solution, and it is the one
reported in the paper (`k_in^stab` 59 bits, `k_out^stab` 68 bits,
`|k_in^gen cap k_out^gen| = 19`, `min_kin = 54`, `min_kout = 51`,
`min_kinout = 76`, filters `AL_filter` of 13 bits so that
`2 + 13 + 32 + 32 = 79`). For SIMECK32 and SIMECK48 the last block is reported
(`|common|` = 6 and 3 respectively).

---

## 3. `check_mode/` — runnable key-involvement checkers

`check_mode/1data.mzn` sets `solveORcheck = false`, which turns the model into
a *checker*: instead of searching for an attack it takes fixed target bits and
reports which key bits they need.

| driver | prints |
|---|---|
| `key4PE.mzn` | the key bits needed for the probabilistically extended difference bits (`PD`, the paper's `gamma_out`) — the row `k_gamma` of the paper's tables |
| `key4GS.mzn` (SIMECK48 only) | the key bits needed for the difference bits that are guessed directly (`GDout`, i.e. `DeltaX_2^(28)` and `DeltaX_2^(29)`) — the row `k_dout` |

Run, for example:

```
cd SIMECK48/check_mode
minizinc --solver cp-sat -p 20 key4PE.mzn
```

The output is a set of `KOUT[r] = [...]` lines, one group per PE relation. These
keys deliberately go **beyond** `k_out^stab`: the attack never computes those
bits (one group is assumed, the other is guessed), which is exactly why the
probabilistic-extension and difference-guessing techniques are needed. The
checker prints them so that the model's own accounting can be verified; the
next section shows how the Python suite reproduces the same sets independently.

---

## 4. `*attack_details.pdf` and `42attack_detail.py`

Each `*attack_details.pdf` is the full, human-readable dump of the block used
in the paper: the distinguisher differentials, `gamma_in`/`gamma_out`, the
truncated trail round by round (two words per round, `0`/`1`/`*`), the data
set, the matching equations, the `k_gamma` groups together with the key sets
computed by `key4PE.mzn`, and the recovery steps (1)-(6)/(1)-(7) that extract
the remaining key bits after matching.

`SIMECK64/42attack_detail.py` is a short script that walks through that last
stage explicitly: starting from the printed sets it applies the matching
relations `AL ^ BR = k39 ^ k41` and `AR ^ k40 ^ BL = F(AL ^ k39)` and the key
schedule one step at a time, printing the key bits obtained at each step. It
documents why the last bits of `k_in | k_out` are redundant (the model's
`cross_k` count).

---

## 5. `L_relations.txt` — the matching relations in explicit form

`L_relations.txt` (540 lines) writes out, for **every** filter bit of the three
instances, the two sides of the matching relation

```
G_in(B, Btilde, k_in)  =  G_out(A, Atilde, k_out)
```

in full. It is generated from the four bit-wise equations of the appendix
(`eq:BL`, `eq:BR`, `eq:DeltBL`, `eq:DeltBR`) by expanding each equation into
monomials and assigning every monomial to the side that alone can evaluate it:
a monomial that is a function of `(A, pi_Jout(Atilde), k_out)` goes to `G_out`,
one that is a function of `(pi_Jin(B), pi_Jin(Btilde), k_in)` goes to `G_in`,
and a bit `j` enters the filter only if every one of its monomials can be
assigned. This is exactly the rule used to obtain the sets `L_0..L_3` of the
paper's tables.

Conventions used in the file (`+` = XOR, `*` = AND, all indices mod n):

```
AL[j], AR[j]     left / right half of A = X^(rA);  At / Bt are the tilde states
dAL[j] = AL[j] + ALt[j]      (likewise dAR, dBL, dBR)      differences
kin[r,j], kout[r,j]          the round-key bit k^(r)_j owned by the in / out side
L1..L4 in the file = L_0..L_3 of the paper (same order)
```

Example, SIMECK32, filter bit 6 of `L_0`:

```
j=6
   Gin (B,Bt,kin)  = BL[6] + (BR[5]+kin[24,5]) + (BR[6]+kin[24,6])*(BR[1]+kin[24,1])
   Gout(A,At,kout) = AR[6] + kout[23,6]
```

Size of the filter per instance (identical to the paper's `L` values, and
reproducible from the `dAL_filter` .. `AR_filter` lines of `models/result.txt`):

| instance | `L_0` | `L_1` | `L_2` | `L_3` | total |
|---|---|---|---|---|---|
| SIMECK32 | 2 (`j = 6,12`) | 0 | 16 | 16 | 34 |
| SIMECK48 | 1 (`j = 7`) | 3 (`j = 2,7,8`) | 24 | 24 | 52 |
| SIMECK64 | 2 (`j = 7,29`) | 13 | 32 | 32 | 79 |

The relations are useful in two ways: they show *which* monomial each side is
responsible for (and hence why a bit does or does not enter the filter), and
they can be checked term by term against the key sets produced by `check_mode/`
and by `pe R J` of the Python suite.

---

## 6. `key_involve*.py` — independent Python suite

Pure Python 3, standard library only, no MiniZinc, no encryption. For a single
bit of `A`, `Atilde`, `B`, `Btilde`, of a state `X^r`, or of a difference
`DX^r`, the programs print the round-key bits that bit depends on, and check
the union against the declared `k_in` / `k_out`.

```
python key_involve32.py            full report (trail, per-bit table, check)
python key_involve32.py verify     one-line verdict
python key_involve32.py kgamma     compare with the attack-details sheet
python key_involve32.py kdout      the k_dout row (only SIMECK48 has one)
python key_involve32.py --selftest negative test
```

The same commands exist for `key_involve48.py` and `key_involve64.py`.
Query commands (`J` may be `5`, `5,12`, `0-15` or `all`):

| command | returns |
|---|---|
| `atA J`, `atB J`, `B J`, `A J` | keys for one or more bits of the four matching objects |
| `sin R J`, `sout R J` | keys for an in-side / out-side state bit `X^(R)_J` |
| `din R J`, `dout R J` | keys to compute a difference bit |
| `pe R J` | keys to *verify* `DX^(R)_J = 0` (the `k_gamma` reading) |

`dout` and `pe` differ on purpose: if the trail already determines the bit,
computing it is free (`dout` prints `empty`) while verifying it still requires
recomputing it from `delta_out` (`pe`), which is what an attacker must do to
justify a probabilistic-extension assumption.

The difference-test bits of SIMECK48 (`d_out = DX_2^(29) || DX_2^(28)`) are
covered by the `kdout` check, which reproduces the `k_dout` row of `tab:sim48`
and of the `key4GS.mzn` box in `33attack_details.pdf`:

```
$ python key_involve48.py kdout
DX^(29)_2 || DX^(28)_2                   10 bits  matches the sheet
    derived : k^(28)_{21}  k^(29)_{16,20,21}  k^(30)_{11,15,16,19,20,21}
    subset of k_out: no
k_dout check PASSED
```

SIMECK32 and SIMECK64 guess no difference bit, and the command then says that
there is no `k_dout` row to reproduce. Like `k_gamma`, these keys lie outside
`k_out^stab`, which is exactly why the difference-test technique is needed.

Reference output:

| instance | `Atilde` vs `k_out` | `B, Btilde` vs `k_in` | `DP` vs `k_in` | `k_gamma` | `k_dout` |
|---|---|---|---|---|---|
| SIMECK32 | 20 / 28 | 0 / 18 | 2 / 18 | 3 of 3 match | no guessed bit |
| SIMECK48 | 23 / 41 | 0 / 15 | 2 / 15 | 3 of 3 groups match | 10 bits, matches |
| SIMECK64 | 32 / 68 | 19 / 59 | 2 / 59 | 3 of 3 groups match | no guessed bit |

The criterion is containment, not equality: the paper declares extra bits for
the matching filter, for the key-schedule closure and for master-key recovery,
so a strict subset is the expected outcome. For SIMECK64 the in side costs 19
bits of `k^(42)` (there `X^41` is not a ciphertext word, so it has to be
recovered through round 42), while for SIMECK32/48 `X^rB` *is* a ciphertext
word and the folded boundary round makes the in-side computation free.

`README_key_involve.md` documents the underlying model (truncated trail,
per-bit recursions, the keyless PP boundary rounds, the PE rule), the parameter
blocks, the exact command syntax and the scope of the check.

---

## 7. How the parts fit together

| question | answered by |
|---|---|
| which difference bits are fixed to zero by the differential (`PD`) | `models/result.txt` (trail `DT`, `PD` lines) |
| which key bits must be guessed (`k_in`, `k_out`) | `models/result.txt` (`KIN`, `KOUT`, `fullkin`, `fullkout`, `min_kin`, `min_kout`) |
| how large the matching filters are | `models/result.txt` (`dAL_filter` .. `AR_filter`) |
| the keys behind the PE bits and the guessed differences | `check_mode/key4PE.mzn`, `key4GS.mzn`, and `key_involveXX.py pe` |
| the matching equations actually used, bit by bit | `L_relations.txt` (`G_in = G_out` for every filter bit) |
| the attack as reported, step by step | `SIMECKXX/*attack_details.pdf`, `42attack_detail.py` |
| that the model's answer is correct | `key_involveXX.py` (independent, bit for bit) |

---

## 8. Requirements

* MiniZinc 2.10 with the OR-Tools CP-SAT solver (CP-SAT 9.15 was used) for
  `check_mode/`; about 20 s / 2 min / 5 min for the three instances on 20
  threads.
* Python >= 3.8 for the `key_involve*.py` suite (standard library only).

## 9. Provenance

`models/result.txt` and `check_mode/` are the files used for the paper, and the
`*attack_details.pdf` dumps are taken from the same runs. The Python suite was
written afterwards and is deliberately independent: it shares no code with the
MiniZinc model and recomputes the trail and the key dependencies from scratch,
so agreement between the two is evidence that the reported key sets are
correct.
