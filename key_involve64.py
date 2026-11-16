#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
key_involve64.py -- per-bit key dependency check for the 42-round SIMECK64
attack (n = 32, r_A = 40, r_B = 41).

Run  python key_involve64.py            for the full report
     python key_involve64.py --help     for the command list
     python key_involve64.py verify     for the one-line verdict

Parameters are transcribed by hand from the paper (Table tab:sim64) and from
result.txt.  For this instance the SECOND-TO-LAST block of result.txt is used
(T1 = 10441), not the last one (T1 = 10341):

  the CP model minimises T1 only.  The memory-reduction technique stores one
  k_in (resp. k_out) per value of F_in (resp. F_out), which costs a factor
  2^-|k_in^gen cap k_out^gen|, so the figure that matters is  T1 - |common|.
  Last block          : 10341 - 1200 = 9141   (|common| = 12)
  Second-to-last block: 10441 - 1900 = 8541   (|common| = 19)
  hence the second-to-last block is the memory-optimal solution and is the one
  reported in the paper table (k_in^stab 59 bits, k_out^stab 68 bits,
  |k_in^gen cap k_out^gen| = 19).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from key_involve_core import run          # noqa: E402


class _P:
    pass


P = _P()
P.PROG = os.path.basename(__file__)
P.NAME = "SIMECK64 / 42 rounds"
P.SOURCE = ("result.txt, second-to-last block, T1 = 10441 "
            "(last block T1 = 10341 ignores the memory reduction)")

# --- cipher and layout -----------------------------------------------------
P.N = 32
P.RA, P.RB, P.RC = 0, 5, 1
P.R = 42
P.RR = 43                   # ciphertext C = (X^43, X^42)
P.rSTART = 1
P.rIN, P.rOUT = 3, 33
P.rEND = 39
P.rA, P.rB = 40, 41         # A = (X^40, X^39), B = (X^41, X^40)

# --- distinguisher differences --------------------------------------------
P.DELTA_IN = {P.rIN: 0x00000000, P.rIN - 1: 0x00000001}     # (0, 1)
P.DELTA_OUT = {P.rOUT: 0x00000001, P.rOUT - 1: 0x00000000}  # (1, 0)

# --- probabilistic-extension points ---------------------------------------
P.PE = [(34, 0), (34, 5), (35, 1), (35, 6), (36, 0), (36, 5)]


def K(r, *bits):
    return {(r, j) for j in bits}


FULL42 = set(range(32)) - {16, 20, 21, 26}

# --- declared key sets (k_in^stab 59 bits, k_out^stab 68 bits) -------------
P.K_IN = (K(1, 5, 27)
          | K(38, 3, 8, 13, 25, 30)
          | K(39, 2, 3, 7, 8, 12, 13, 14, 19, 20, 24, 25, 29, 30)
          | K(41, 2, 3, 7, 8, 13, 14, 15, 19, 24, 29, 30)
          | K(42, *FULL42))
P.K_OUT = (K(36, 7, 29)
           | K(37, 2, 6, 7, 8, 12, 24, 28, 29, 30)
           | K(38, 1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 17, 19, 23, 24, 25,
                 27, 28, 29, 30, 31)
           | K(39, 0, 1, 4, 5, 6, 9, 10, 11, 12, 16, 17, 18, 20, 22, 23, 26,
                 27, 28, 31)
           | K(40, 7, 29)
           | K(41, 2, 6, 7, 8, 12, 24, 28, 29, 30)
           | K(42, 1, 6, 11, 17, 23, 28))

# --- state-test / difference-test bits (empty for this instance) -----------
P.GS_IN, P.GD_IN = set(), set()
P.GS_OUT, P.GD_OUT = set(), set()

# --- the 2n bits the attack needs -----------------------------------------
# J_in is NOT the full state here: the paper gives
#   J_in = {63..0} \ {0,5,11,16,17,18,20,21,22,25,26,27,31, 48,52,53,58}
# so the in side never evaluates those bits of B / Btilde.
_JIN_DROP_LEFT = {0, 5, 11, 16, 17, 18, 20, 21, 22, 25, 26, 27, 31}
_JIN_DROP_RIGHT = {48, 52, 53, 58}
P.J_IN = set(range(2 * P.N)) - _JIN_DROP_LEFT - _JIN_DROP_RIGHT
P.J_OUT = set(range(2 * P.N))

# --- k_gamma reference: 42attack_details.pdf, three grouped relations ------
P.KGAMMA = [
    ("DX^(36)_5 || DX^(35)_6 = X^(35)_5 || X^(34)_6",
     [(36, 5), (35, 6)],
     K(35, 6) | K(36, 1, 5, 6) | K(37, 0, 1, 4, 5, 6, 28)
     | K(38, 0, 1, 3, 4, 5, 6, 23, 27, 28, 31)),
    ("DX^(36)_0 || DX^(35)_1 || DX^(34)_5 = X^(35)_-5 || X^(34)_-4 || X^(33)_5",
     [(36, 0), (35, 1), (34, 5)],
     K(34, 5) | K(35, 0, 4, 5, 28)
     | K(36, 0, 3, 4, 5, 23, 27, 28, 31)
     | K(37, 0, 2, 3, 4, 5, 18, 22, 23, 26, 27, 28, 30, 31)
     | K(38, 0, 1, 2, 3, 4, 5, 13, 17, 18, 21, 22, 23, 25, 26, 27, 28, 29,
         30, 31)),
    ("DX^(34)_0 = X^(33)_-5", [(34, 0)],
     K(34, 27) | K(35, 22, 26, 27) | K(36, 17, 21, 22, 25, 26, 27)
     | K(37, 12, 16, 17, 20, 21, 22, 24, 25, 26, 27)
     | K(38, 7, 11, 12, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27)),
]

if __name__ == "__main__":
    sys.exit(run(P, sys.argv[1:]))
