"""Given the following parameters

 SIN: (145-bit)]
   SIN[ 0]( 32-bit)=   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, ]
   SIN[ 1]( 32-bit)=   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, ]
   SIN[ 2](  2-bit)=   [5, 27, ]
   SIN[40]( 19-bit)=   [1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13, 14, 15, 19, 23, 24, 28, 29, 30, ]
   SIN[41]( 28-bit)=   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 22, 23, 24, 25, 27, 28, 29, 30, 31, ]
   SIN[42]( 32-bit)=   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, ]

fin_fout: (108-bit)]
  fin_fout[ 1](  2-bit)=   [5, 27, ]
  fin_fout[36](  2-bit)=   [7, 29, ]
  fin_fout[37](  9-bit)=   [2, 6, 7, 8, 12, 24, 28, 29, 30, ]
  fin_fout[38]( 21-bit)=   [1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 17, 19, 23, 24, 25, 27, 28, 29, 30, 31, ]
  fin_fout[39]( 30-bit)=   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, ]
  fin_fout[40](  2-bit)=   [7, 29, ]
  fin_fout[41]( 14-bit)=   [2, 3, 6, 7, 8, 12, 13, 14, 15, 19, 24, 28, 29, 30, ]
  fin_fout[42]( 28-bit)=   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 22, 23, 24, 25, 27, 28, 29, 30, 31, ]

dAL_filter: (32-bit)  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
AL_filter: (13-bit)  2, 3, 6, 7, 8, 12, 13, 14, 19, 24, 28, 29, 30,
dAR_filter: (32-bit)  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
AR_filter: (2-bit)  7, 29,
"""
def mod(j): return (j+24)%24

fullkinout = {
    35: [], 34: [],
    36: [7, 29, ],
    37: [2, 6, 7, 8, 12, 24, 28, 29, 30, ],
    38: [1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 17, 19, 23, 24, 25, 27, 28, 29, 30, 31, ],
    39: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, ],
    40: [7, 29, ],
    41: [2, 3, 6, 7, 8, 12, 13, 14, 15, 19, 24, 28, 29, 30, ],
    42: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 22, 23, 24, 25, 27, 28, 29, 30, 31,],
}
BL = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 22, 23, 24, 25, 27, 28, 29, 30, 31, }  # sin41
BR = {1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13, 14, 15, 19, 23, 24, 28, 29, 30, }  # sin40

"""1. Compute BR[j]=x41[j]x41[j-5]+x41[j-1]+x42[j] to obtain BR[0, 5, 11, 18, 27, 31]."""
BR = set([j for j in range(32) if {j, mod(j - 5), mod(j - 1)} <= set(BL)] + list(BR))
print('1. new BR=',len(BR), BR, ',   new get',[j for j in BR if j not in {1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13, 14, 15, 19, 23, 24, 28, 29, 30, } ]) # 1. new BR= 25 {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 23, 24, 27, 28, 29, 30, 31} ,   new get [0, 5, 11, 18, 27, 31]

"""2. Compute k39[15] and k41[0, 1, 4, 5, 9, 10, 11, 18, 23, 27, 31] based on AL+BR=k39+k41."""
k39 = set([j for j in range(32) if j in BR and j in fullkinout[41]] + fullkinout[39])
print('2. new k39=', len(k39), k39, ',   new get',[j for j in k39 if j not in fullkinout[39]])  #2. new k39= 31 {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31} ,   new get [15]
k41 = set([j for j in range(32) if j in BR and j in k39] + fullkinout[41])
print('2. new k41=', len(k41), k41, ',   new get',[j for j in k41 if j not in fullkinout[41]]) # 2. new k41= 25 {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 23, 24, 27, 28, 29, 30, 31} ,   new get [0, 1, 4, 5, 9, 10, 11, 18, 23, 27, 31]


"""3. Compute k40 based on AR+k40+BL=F(AL+k39)."""
k40 = set([j for j in range(32) if j in BL and {j, mod(j - 5), mod(j - 1)} <= k39] + fullkinout[40])
print('3. new k40=', len(k40), k40, ',   new get',[j for j in k40 if j not in fullkinout[40]]) # new k40= 26 {0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 23, 24, 25, 27, 28, 29, 30, 31} ,   new get [0, 1, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 23, 24, 25, 27, 28, 30, 31]


"""4. Compute k38[0, 4, 10, 14, 15, 18] and k37[13, 14, 15, 19] based on the key schedule."""
k38 = set([j for j in range(32) if {j, mod(j - 5), mod(j - 1)} <= set(k39) and j in fullkinout[42]] + fullkinout[38])
print('4. new k38=', len(k38), k38, ',   new get',[j for j in k38 if j not in fullkinout[38]]) # 4. new k38= 27 {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 23, 24, 25, 27, 28, 29, 30, 31} ,   new get [0, 4, 10, 14, 15, 18]
k37 = set([j for j in range(32) if {j, mod(j - 5), mod(j - 1)} <= set(k38) and j in fullkinout[41]] + fullkinout[37])
print('4. new k37=', len(k37), k37, ',   new get',[j for j in k37 if j not in fullkinout[37]])  # 4. new k37= 13 {2, 6, 7, 8, 12, 13, 14, 15, 19, 24, 28, 29, 30} ,   new get [13, 14, 15, 19]


"""5. Compute k38[0, 4, 10, 14, 15, 18] and k37[13, 14, 15, 19] based on the key schedule."""



"""Summary first:"""
print('\n==============================\n')
print(f"BL:{len(BL)}-bit, {BL},", )
print(f"BR:{len(BR)}-bit, {BR},", )
print(f"k38:{len(k38)}-bit, {k38},", )
print(f"k39:{len(k39)}-bit, {k39},", )
print(f"k40:{len(k40)}-bit, {k40},", )
print(f"k41:{len(k41)}-bit, {k41},", )
print(f"k42:{len(k42)}-bit, {k42},", )

"""5. Analyze x35[5].
This involves
  KOUT[36](  1-bit)=   [5, ]    obtainable from k37 and k40
  KOUT[37](  3-bit)=   [0, 4, 5, ]   obtainable from k38[0,31,27,4,3,31,5,4,0] and k41
  KOUT[38](  6-bit)=   [0, 3, 4, 5, 27, 31, ]
  All of the above are known, so 1 bit can be filtered.
Analyze x34[6].
This involves
  KOUT[35](  1-bit)=   [6, ]   obtainable from k36[1 5 6] and k39[6]
  KOUT[36](  3-bit)=   [1, 5, 6, ]   obtainable from k37[1 0 28,  5 4 0,  6 5 1] and k40[1 5 6]
  KOUT[37](  6-bit)=   [0, 1, 4, 5, 6, 28, ]  obtainable from k41[0, 1, 4, 5, 6, 28, ] and k38[0 31 27, 1 0 28, 4 3 31, 5 4 0, 6 5 1, 28 27 23]
  KOUT[38]( 10-bit)=   [0, 1, 3, 4, 5, 6, 23, 27, 28, 31, ]
All of the above are known, so 1 bit can be filtered.

KOUT: (20-bit)]
  KOUT[35](  1-bit)=   [6, ]
  KOUT[36](  3-bit)=   [1, 5, 6, ]
  KOUT[37](  6-bit)=   [0, 1, 4, 5, 6, 28, ]
  KOUT[38]( 10-bit)=   [0, 1, 3, 4, 5, 6, 23, 27, 28, 31, ]
"""

"""6.
Analyze x35[27], which involves
  KOUT[36](  1-bit)=   [27, ]
  KOUT[37](  3-bit)=   [22, 26, 27, ]         k41[22 26]<==>k37[22,26] unknown; k37[27] comes from k41[7] and k38[27 26 22]
  KOUT[38](  6-bit)=   [17, 21, 22, 25, 26, 27, ]           k38[21, 22, 26] unknown


Analyze x34[28], which involves
  KOUT[35](  1-bit)=   [28, ]
  KOUT[36](  3-bit)=   [23, 27, 28, ]
  KOUT[37](  6-bit)=   [18, 22, 23, 26, 27, 28, ]   k41[22 26]<==>k37[22,26] unknown
  KOUT[38]( 10-bit)=   [13, 17, 18, 21, 22, 23, 25, 26, 27, 28, ]   k38[21, 22, 26] unknown

Analyze x33[5], which involves
  KOUT[34](  1-bit)=   [5, ]
  KOUT[35](  3-bit)=   [0, 4, 5, ]
  KOUT[36](  6-bit)=   [0, 3, 4, 5, 27, 31, ]
  KOUT[37]( 10-bit)=   [0, 2, 3, 4, 5, 22, 26, 27, 30, 31, ]       k41[22 26]<==>k37[22,26] unknown
  KOUT[38]( 15-bit)=   [0, 1, 2, 3, 4, 5, 17, 21, 22, 25, 26, 27, 29, 30, 31, ]     k38[21, 22, 26] unknown

The above 3 bits involve
KOUT: (45-bit)]
  KOUT[34](  1-bit)=   [5, ]
  KOUT[35](  4-bit)=   [0, 4, 5, 28, ]
  KOUT[36](  8-bit)=   [0, 3, 4, 5, 23, 27, 28, 31, ]
  KOUT[37]( 13-bit)=   [0, 2, 3, 4, 5, 18, 22, 23, 26, 27, 28, 30, 31, ]
  KOUT[38]( 19-bit)=   [0, 1, 2, 3, 4, 5, 13, 17, 18, 21, 22, 23, 25, 26, 27, 28, 29, 30, 31, ]
Here k37[22,26] and k38[21, 22, 26] are unknown. Therefore, by exhaustively enumerating these bits, 3 bits can be filtered after about 5 rounds:
125+5-3=127 terms remain, and then by


-----


Analyze x33[27], which involves
  KOUT[34](  1-bit)=   [27, ]
  KOUT[35](  3-bit)=   [22, 26, 27, ]
  KOUT[36](  6-bit)=   [17, 21, 22, 25, 26, 27, ]    k40[21 22 26] unknown
  KOUT[37]( 10-bit)=   [12, 16, 17, 20, 21, 22, 24, 25, 26, 27, ]   k41[16 17 20 25  21 22 26] unknown
  KOUT[38]( 15-bit)=   [7, 11, 12, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27, ]

"""