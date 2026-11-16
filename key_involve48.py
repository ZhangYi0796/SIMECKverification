#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
key_involve48.py -- per-bit key dependency check for the 33-round SIMECK48
attack (n = 24, r_A = 32, r_B = 33).

Run  python key_involve48.py            for the full report
     python key_involve48.py --help     for the command list
     python key_involve48.py verify     for the one-line verdict

Parameters are transcribed by hand from the paper (Table tab:sim48) and from
result.txt (final block, T1 = 6242).  The engine is key_involve_core.py.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from key_involve_core import run          # noqa: E402


class _P:
    pass


P = _P()
P.PROG = os.path.basename(__file__)
P.NAME = "SIMECK48 / 33 rounds"
P.SOURCE = "result.txt, last block, T1 = 6242"

# --- cipher and layout -----------------------------------------------------
P.N = 24
P.RA, P.RB, P.RC = 0, 5, 1
P.R = 33
P.RR = 34                   # ciphertext C = (X^34, X^33)
P.rSTART = 1
P.rIN, P.rOUT = 3, 25
P.rEND = 31
P.rA, P.rB = 32, 33         # A = (X^32, X^31), B = (X^33, X^32)

# --- distinguisher differences --------------------------------------------
P.DELTA_IN = {P.rIN: 0x000000, P.rIN - 1: 0x000001}     # (0, 1)
P.DELTA_OUT = {P.rOUT: 0x000001, P.rOUT - 1: 0x000000}  # (1, 0)

# --- probabilistic-extension points (six, see tab:sim48) -------------------
P.PE = [(26, 0), (26, 5), (27, 1), (27, 6), (28, 0), (28, 5)]


def K(r, *bits):
    return {(r, j) for j in bits}


# --- declared key sets (k_in^stab 15 bits, k_out^stab 41 bits) ------------
P.K_IN = (K(1, 5, 19)
          | K(33, 4, 6, 9, 10, 11, 12, 15, 16, 17, 19, 20, 21, 22))
P.K_OUT = (K(28, 7)
           | K(29, 2, 6, 7, 8, 12, 22)
           | K(30, 1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 17, 19, 21, 22, 23)
           | K(31, 0, 1, 2, 3, 5, 7, 8, 13, 14, 18, 23)
           | K(32, 7)
           | K(33, 2, 6, 7, 8, 12, 22))

# --- difference-test bits: the attack guesses DX^(28)_2 and DX^(29)_2 ------
P.GS_IN, P.GD_IN = set(), set()
P.GS_OUT = set()
P.GD_OUT = {(28, 2), (29, 2)}

# k_dout reference: 33attack_details.pdf, the "key4GS.mzn" box,
# "DX^(29)_2 || DX^(28)_2 are involved with KOUT[28], KOUT[29], KOUT[30]".
P.KDOUT = [
    ("DX^(29)_2 || DX^(28)_2", [(29, 2), (28, 2)],
     K(28, 21) | K(29, 16, 20, 21) | K(30, 11, 15, 16, 19, 20, 21)),
]

# --- the 2n bits the attack needs -----------------------------------------
P.J_IN = set(range(2 * P.N))
P.J_OUT = set(range(2 * P.N))

# --- k_gamma reference: 33attack_details.pdf groups the six PE bits in ----
# --- three relations; each group is compared as a union.                   -
P.KGAMMA = [
    ("DX^(28)_5 || DX^(27)_6 = X^(27)_5 || X^(26)_6",
     [(28, 5), (27, 6)],
     K(27, 6) | K(28, 1, 5, 6) | K(29, 0, 1, 4, 5, 6, 20)
     | K(30, 0, 1, 3, 4, 5, 6, 15, 19, 20, 23)),
    ("DX^(28)_0 || DX^(26)_5 || DX^(26)_0 = X^(27)_-5 || X^(25)_5 || X^(25)_-5",
     [(28, 0), (26, 5), (26, 0)],
     K(26, 5, 19) | K(27, 0, 4, 5, 14, 18, 19)
     | K(28, 0, 3, 4, 5, 9, 13, 14, 17, 18, 19, 23)
     | K(29, 0, 2, 3, 4, 5, 8, 9, 12, 13, 14, 16, 17, 18, 19, 22, 23)
     | K(30, 0, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19,
         21, 22, 23)),
    ("DX^(27)_1 = X^(26)_-1", [(27, 1)],
     K(27, 20) | K(28, 15, 19, 20) | K(29, 10, 14, 15, 18, 19, 20)
     | K(30, 5, 9, 10, 13, 14, 15, 17, 18, 19, 20)),
]

if __name__ == "__main__":
    sys.exit(run(P, sys.argv[1:]))
