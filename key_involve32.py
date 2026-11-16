#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
key_involve32.py -- per-bit key dependency check for the 24-round SIMECK32
attack (n = 16, r_A = 23, r_B = 24).

Run  python key_involve32.py            for the full report
     python key_involve32.py --help     for the command list
     python key_involve32.py verify     for the one-line verdict

All numbers below are transcribed by hand from the paper (Table tab:sim32) and
from result.txt of the CP model, exactly as in verify_simeck32.py.  The engine
is key_involve_core.py.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from key_involve_core import run          # noqa: E402


class _P:
    pass


P = _P()
P.PROG = os.path.basename(__file__)
P.NAME = "SIMECK32 / 24 rounds"
P.SOURCE = "result.txt, last block, T1 = 5106"

# --- cipher and layout -----------------------------------------------------
P.N = 16                    # half block size
P.RA, P.RB, P.RC = 0, 5, 1  # F(x) = (x<<<RA & x<<<RB) ^ (x<<<RC)
P.R = 24                    # number of rounds
P.RR = 25                   # ciphertext round: C = (X^25, X^24)
P.rSTART = 1                # plaintext P = (X^1, X^0)
P.rIN, P.rOUT = 3, 17       # distinguisher boundaries
P.rEND = 22                 # end of E_out0
P.rA, P.rB = 23, 24         # matching layer: A = (X^23, X^22), B = (X^24, X^23)

# --- distinguisher differences --------------------------------------------
P.DELTA_IN = {P.rIN: 0x0000, P.rIN - 1: 0x0001}    # (0, 1)
P.DELTA_OUT = {P.rOUT: 0x0001, P.rOUT - 1: 0x0000}  # (1, 0)

# --- probabilistic-extension points (the paper's gamma_out) ----------------
P.PE = [(18, 0), (18, 5), (20, 2)]

# --- declared key sets (k_in^stab, k_out^stab) -----------------------------
def K(r, *bits):
    return {(r, j) for j in bits}


P.K_IN = K(1, 5, 11) | K(24, *range(16))
P.K_OUT = (K(19, 6, 12)
           | K(20, 1, 5, 6, 7, 11, 12)
           | K(21, 0, 1, 2, 4, 5, 6, 7, 8, 10, 11, 12, 14)
           | K(23, 6, 12)
           | K(24, 1, 5, 6, 7, 11, 12))

# --- state-test / difference-test bits (empty for this instance) -----------
P.GS_IN, P.GD_IN = set(), set()
P.GS_OUT, P.GD_OUT = set(), set()

# --- the 2n bits the attack needs -----------------------------------------
P.J_IN = set(range(2 * P.N))
P.J_OUT = set(range(2 * P.N))

# --- k_gamma reference: 24attack_details.pdf, one entry per PE bit --------
P.KGAMMA = [
    ("DX^(20)_2 = DX^(19)_1 ^ X^(19)_-3", [(20, 2)],
     K(19, 12) | K(20, 7, 11, 12, 13) | K(21, 2, 6, 7, 8, 10, 11, 12, 13)),
    ("DX^(18)_0 = X^(17)_-5", [(18, 0)],
     K(18, 11) | K(19, 6, 10, 11) | K(20, 1, 5, 6, 9, 10, 11)
     | K(21, 0, 1, 4, 5, 6, 8, 9, 10, 11, 12)),
    ("DX^(18)_5 = X^(17)_5", [(18, 5)],
     K(18, 5) | K(19, 0, 4, 5) | K(20, 0, 3, 4, 5, 11, 15)
     | K(21, 0, 2, 3, 4, 5, 6, 10, 11, 14, 15)),
]

if __name__ == "__main__":
    sys.exit(run(P, sys.argv[1:]))
