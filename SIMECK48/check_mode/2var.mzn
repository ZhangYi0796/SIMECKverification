% # 2026.4.20
% # 2026.7.24  # 改动：差分涉及情况中，DT情况不再影响din/dout的涉及情况，只在key_involve中单独考虑DT对涉及情况的影响
include "1data.mzn";



% 4.diff_trails
array[0..N-1] of var 0..2: DINL  = array1d(0..N-1, [if j in DINL1bit  then 1 elseif j in DINL2bit  then 2 else 0 endif| j in 0..N-1]);   % inputL  of distinguisher
array[0..N-1] of var 0..2: DINR  = array1d(0..N-1, [if j in DINR1bit  then 1 elseif j in DINR2bit  then 2 else 0 endif| j in 0..N-1]);   % inputR  of distinguisher
array[0..N-1] of var 0..2: DOUTL = array1d(0..N-1, [if j in DOUTL1bit then 1 elseif j in DOUTL2bit then 2 else 0 endif| j in 0..N-1]);   % outputR of distinguisher
array[0..N-1] of var 0..2: DOUTR = array1d(0..N-1, [if j in DOUTR1bit then 1 elseif j in DOUTR2bit then 2 else 0 endif| j in 0..N-1]);   % outputR of distinguisher
array[0..RR, 0..N-1] of var 0..2: DT;   % (DT[i,N-1~0] || DT[i-1,N-1~0]) is the i-th round difference produced by the distinguisher
constraint forall(j in 0..N-1)(         % initialization
   DT[rin, j]==DINL[j]  /\ DT[rin-1, j]==DINR[j]         % assign value of (DINL,  DINR ) to (DT[rin],  DT[rin-1] )
/\ DT[rout,j]==DOUTL[j] /\ DT[rout-1,j]==DOUTR[j]        % assign value of (DOUTL, DOUTR) to (DT[rout], DT[rout-1])
)/\forall(r in rin+1..rout-2, j in 0..N-1)(DT[r,j]==2);  % fix dummy bits
 

% 5 probabilistic extensional diff-bit position
array[0..RR, 0..N-1] of var bool: PD;  % PD[r,j]=true means that DT[r,j] is imposed to be 0 with probability less than 1
constraint forall(j in 0..N-1, r in 0..RR where not((r>=rstart-1 /\ r<=rin-2) \/ (r>=rout+1 /\ r<=rend)))(PD[r,j]==false); % initialization,  fix dummy bits
constraint if ACTIVE_PE then true else forall(j in 0..N-1, r in 0..RR)(PD[r,j]==false) endif; % active PE or not
var int: pin  = sum(j in 0..N-1,r in 0..RR where r>=rstart-1 /\ r<=rin-2)(bool2int(PD[r,j])); 
var int: pout = sum(j in 0..N-1,r in 0..RR where r>=rout+1 /\ r<=rend)(bool2int(PD[r,j]));


% 6.diff/state/key involvement 
array[0..RR,0..N-1] of var bool:  din_wanted; % target diff_in
array[0..RR,0..N-1] of var bool: dout_wanted; % target diff_out
array[0..RR,0..N-1] of var bool:  sin_wanted; % target state_in
array[0..RR,0..N-1] of var bool: sout_wanted; % target state_out
constraint forall(r in 0..RR, j in 0..N-1 )(  % initialization,
if rin<rA then ( % TYPE1
    if     r==rstart-1 then  din_wanted[r,j]==true  /\ sin_wanted[r,j]==true  /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false
    elseif r==rstart   then  din_wanted[r,j]==true  /\ sin_wanted[r,j]==true  /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false
    elseif r==rend-1   then  din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false
    elseif r==rend     then (if ACTIVE_GDMA then       din_wanted[r,j]==false /\  sin_wanted[r,j]==false /\ sout_wanted[r,j]==true  else   % GDMA WITHOUT dout[r,j]==true
                             din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==true  /\ sout_wanted[r,j]==true  endif)                                                                 
    elseif r==rend+1   then (if ACTIVE_GDMA then      sout_wanted[r,j]==true  else  % GDMA WITHOUT din[r,j]==true /\ sin[r,j]==true /\ dout[r,j]==true
                             din_wanted[r,j]==true  /\ sin_wanted[r,j]==true  /\ dout_wanted[r,j]==true  /\ sout_wanted[r,j]==true  endif)
    elseif r==rend+2   then (if ACTIVE_GDMA then      dout_wanted[r,j]==false /\ sout_wanted[r,j]==false  else   % GDMA WITHOUT din[r,j]==true /\ sin[r,j]==true
                             din_wanted[r,j]==true  /\ sin_wanted[r,j]==true  /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false endif) 
    else                     din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false
    endif
)else ( % TYPE2
    if     r==rend     then  din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==true /\ sout_wanted[r,j]==true
    elseif r==rend-1   then  din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==true /\ sout_wanted[r,j]==true
    elseif r==rA-1     then (if ACTIVE_GDMA then       din_wanted[r,j]==false /\  sin_wanted[r,j]==false  else   % GDMA WITHOUT dout[r,j]==true /\ sout[r,j]==true
                             din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==true  /\ sout_wanted[r,j]==true  endif) 
    elseif r==rA       then (if ACTIVE_GDMA then       sin_wanted[r,j]==true  else % GDMA WITHOUT dout[r,j]==true /\ sout[r,j]==true /\ din[r,j]==true
                             din_wanted[r,j]==true  /\ sin_wanted[r,j]==true  /\ dout_wanted[r,j]==true  /\ sout_wanted[r,j]==true  endif)
    elseif r==rA+1     then (if ACTIVE_GDMA then       sin_wanted[r,j]==true  /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false else   % GDMA WITHOUT din[r,j]==true
                             din_wanted[r,j]==true  /\ sin_wanted[r,j]==true  /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false endif)  
    else                     din_wanted[r,j]==false /\ sin_wanted[r,j]==false /\ dout_wanted[r,j]==false /\ sout_wanted[r,j]==false
    endif 
)endif);

array[0..RR,0..N-1] of var bool: dummy_k;%  all bit are set to false
array[0..RR,0..N-1] of var bool: din;   %  diff_involved to compute  din_wanted
array[0..RR,0..N-1] of var bool: sin;   % state_involved to compute  sin_wanted
array[0..RR,0..N-1] of var bool: kin;   %   key_involved to compute  kin_wanted
array[0..RR,0..N-1] of var bool: dout;  %  diff_involved to compute dout_wanted
array[0..RR,0..N-1] of var bool: sout;  % state_involved to compute sout_wanted
array[0..RR,0..N-1] of var bool: kout;  %   key_involved to compute kout_wanted
constraint solveORcheck ->  % if true then search attack schemes; otherwise check involved key for diff/state bits you want
  forall(r in 0..RR, j in 0..N-1)(  % initialization -- loading target bits: set target diff_bit, state_bit 
%     (if  din_wanted[r,j]/\DT[r,j]==2 then  din[r,j]==true endif)  % # 2026.4.20
%   /\(if dout_wanted[r,j]/\DT[r,j]==2 then dout[r,j]==true endif)   
%   /\(if  sin_wanted[r,j]             then  sin[r,j]==true endif)   
%   /\(if sout_wanted[r,j]             then sout[r,j]==true endif)
      (din_wanted[r,j]->din[r,j]) /\ (dout_wanted[r,j]->dout[r,j]) /\ (sin_wanted[r,j]->sin[r,j]) /\ (sout_wanted[r,j]->sout[r,j]) % # 2026.7.24
  ); 
constraint forall(j in 0..N-1)(kin[0,j]==false /\ kin[RR,j]==false /\ kout[0,j]==false /\ kout[RR,j]==false);  % initialization --  fix dummy bits
constraint forall(r in 0..RR, j in 0..N-1)(dummy_k[r,j]==false);  % initialization --  fix dummy bits
var int: din_num  = sum(j in 0..N-1,r in 0..RR)(bool2int( din[r,j]));
var int: sin_num  = sum(j in 0..N-1,r in 0..RR)(bool2int( sin[r,j]));
var int: kin_num  = sum(j in 0..N-1,r in 0..RR)(bool2int( kin[r,j]));
var int: dout_num = sum(j in 0..N-1,r in 0..RR)(bool2int(dout[r,j]));
var int: sout_num = sum(j in 0..N-1,r in 0..RR)(bool2int(sout[r,j]));
var int: kout_num = sum(j in 0..N-1,r in 0..RR)(bool2int(kout[r,j]));

% 7 guessing diff/state technique
% 7.1 guessing diff instead of key
array[0..RR, 0..N-1] of var bool: GDin;  % GD[r,j]=true means directly guess diff[r,j].  if rin<rA then EIN:  rstart-1~rin-2,rB-1~RR-2; //else EIN: rB-1~rin-2;
array[0..RR, 0..N-1] of var bool: GDout; % GD[r,j]=true means directly guess diff[r,j].  if rin<rA then EOUT: rout+1~rA                 //else EOUT:rout+1~rend,R0+1~rA
constraint if rin<rA then   % initialization,  fix dummy bits
       forall(j in 0..N-1, r in 0..RR where (r>=rin-1 /\ r<=rB-2) \/ r>RR-2)(GDin[r, j]==false)  % TYPE1
     /\forall(j in 0..N-1, r in 0..RR where not(r>=rout+1  /\ r<=rA ))(GDout[r,j]==false)
  else forall(j in 0..N-1, r in 0..RR where not(r>=rB-1 /\ r<=rin-2))(GDin[r, j]==false)  % TYPE2
     /\forall(j in 0..N-1, r in 0..RR where (r>=rA+1 /\ r<=rout) \/ r<R0+1  )(GDout[r,j]==false)
endif;
constraint if ACTIVE_GD then true else forall(j in 0..N-1, r in 0..RR )(GDin[r,j]==false/\GDout[r,j]==false) endif; % active GD or not
var int: GDin_num  = sum(j in 0..N-1,r in 0..RR)(bool2int(GDin[r,j])) ; 
var int: GDout_num = sum(j in 0..N-1,r in 0..RR)(bool2int(GDout[r,j])) ; 

% 7.2 guessing state instead of key
array[0..RR, 0..N-1] of var bool: GSin;   % GSin[r, j]=true means directly guess state[r,j].  if rin<rA then EIN:rstart+1~rin,rB-1~RR-2 //else  EIN:rB+1~rin 
array[0..RR, 0..N-1] of var bool: GSout;  % GSout[r,j]=true means directly guess state[r,j].  if rin<rA then EOUT:rout-1~rA-2  //else  EOUT:rout-1~rend-2,R0+1~rA
constraint if rin<rA then   % initialization,  fix dummy bits
       forall(j in 0..N-1, r in 0..RR where (r>=rin+1  /\ r<=rB-2)\/ r>RR-2)(GSin[r, j]==false)  % TYPE1
     /\forall(j in 0..N-1, r in 0..RR where not(r>=rout-1 /\ r<=rA-2))(GSout[r,j]==false)
  else forall(j in 0..N-1, r in 0..RR where not(r>=rB+1 /\ r<=rin ))(GSin[r, j]==false)  % TYPE2
     /\forall(j in 0..N-1, r in 0..RR where (r>=rB+1 /\ r<rout-2)\/ r<R0+1 )(GSout[r,j]==false)
endif;
constraint if ACTIVE_GS then true else forall(j in 0..N-1, r in 0..RR )(GSin[r,j]==false/\GSout[r,j]==false) endif; % active GS or not
var int: GSin_num  = sum(j in 0..N-1,r in 0..RR)(bool2int(GSin[r,j])) ; 
var int: GSout_num = sum(j in 0..N-1,r in 0..RR)(bool2int(GSout[r,j])) ; 

% 8 dependency + matching
% ------- parallel matching round -------  
% BL = F( AL + k(rA-1) ) + AR + k(rA) 
% BR + k(rA+1) = AL + k(rA-1)
% AR = F( BR+k(rA+1) ) + BL + k(rA) 
% ------- parallel matching round -------  

  
% rend-1并行分割前最后一个密钥； rA-1,rA,rA+1是并行分割的密钥，RR-1是最后一个密钥,这个密钥可能在rA+offset

% 8.1 key dependency

array[0..RR, 0..N-1] of var bool: min_kin;      % Minimum generator for fk 
array[0..RR, 0..N-1] of var bool: min_kout;     % Minimum generator for fk 
array[0..RR, 0..N-1] of var bool: full_kin;     % kin   + derivation from them
array[0..RR, 0..N-1] of var bool: full_kout;    % kout  + derivation from them 
array[0..RR, 0..N-1] of var bool: fin_fout;     % union of fullkin and fullkout
array[0..RR, 0..N-1] of var bool: full_kinout;  % spaning union of fullkin and fullkout
array[0..RR, 0..N-1] of var bool: min_kinout;   % Minimum generator for fin_fout

array[0..RR, 0..N-1] of var bool: common_k;     % common bits of kin and kout
array[0..RR, 0..N-1] of var bool: cross_k;      % linear redundancy formalized as G( full_kin) + H( full_kout) = 0 that deduced from  k[r0,j]+k[r1,ja]k[r1,jb]+k[r1,jc]+k[r4,j] = 0

constraint forall(j in 0..N-1)(   % initialization   fix dummy bits
  not(min_kin[0, j]) /\ not(min_kin[RR, j])
/\not(min_kout[0,j]) /\ not(min_kout[RR,j])
/\not(full_kin[0,j]) /\ not(full_kin[RR,j])
/\not(full_kout[0,j])/\ not(full_kout[RR,j])
/\not(cross_k[0,j])  /\ not(cross_k[RR,j])
/\not(full_kinout[0,j])  /\ not(full_kinout[RR,j])
);

constraint forall(r in 0..RR, j in 0..N-1)( common_k[r,j] == ( full_kin[r,j] /\ full_kout[r,j] ));

var int: min_kin_num    = sum(r in 0..RR, j in 0..N-1)(bool2int(min_kin[r,j]));
var int: min_kout_num   = sum(r in 0..RR, j in 0..N-1)(bool2int(min_kout[r,j]));
var int: min_kinout_num = sum(r in 0..RR, j in 0..N-1)(bool2int(min_kinout[r,j]));
var int: fin_fout_num   = sum(r in 0..RR, j in 0..N-1)(bool2int(fin_fout[r,j]));
var int: common_k_num   = sum(r in 0..RR, j in 0..N-1)(bool2int(common_k[r,j]));
var int: cross_k_num    = sum(r in 0..RR, j in 0..N-1)(bool2int(cross_k[r,j]));
var int: remain_k_num   = M*N-max(array1d(0..RR-4, [sum(j in 0..N-1)(full_kinout[r,j]+full_kinout[r+1,j]+full_kinout[r+2,j]+full_kinout[r+3,j])| r in 0..RR-4]));

% 8.2 known diff
var int: dB_known_num =  if rin<rA % Filter that can be used in advance for T1 or T2
then sum(j in 0..N-1)(bool2int(DT[rB,j]!=2) + bool2int(DT[rB-1,j]!=2))
else sum(j in 0..N-1)(bool2int(DT[rA, j]!=2) + bool2int(DT[rA-1, j]!=2)) endif;  
  
% 8.3 matching
array[0..N-1] of var bool: dAL_filter;   %  dAL = dBR
array[0..N-1] of var bool:  AL_filter;   %  AL  = BR + k(r0-1) + k(r0+1)
array[0..N-1] of var bool: dAR_filter;  %
array[0..N-1] of var bool:  AR_filter;  %
var int: dAL_filter_num = sum(j in 0..N-1)(bool2int(dAL_filter[j]));
var int:  AL_filter_num = sum(j in 0..N-1)(bool2int( AL_filter[j]));
var int: dAR_filter_num = sum(j in 0..N-1)(bool2int(dAR_filter[j]));
var int:  AR_filter_num = sum(j in 0..N-1)(bool2int( AR_filter[j]));


% 9 complexity
var int: T1 = 
if rA>rout then pd + 100*( pin + pout - pin + min_kin_num - dB_known_num + GSin_num + GDin_num)+pin*100*bool2int(not(PEfilter))
else 100*(multiple + 2*N + min_kin_num -pin + GSin_num + GDin_num)+pin*100*bool2int(not(PEfilter)) 
endif;
var int: T2 = 
if rA>rout then 100*(multiple + 2*N + min_kout_num -pout + GSout_num + GDout_num)+pout*100*bool2int(not(PEfilter))
else pd + 100*( pin + pout - pout + min_kout_num - dB_known_num + GSout_num + GDout_num)+pout*100*bool2int(not(PEfilter))
endif;
var int: T3 = pd + 100*(2*N + fin_fout_num - cross_k_num - dAL_filter_num - AL_filter_num - dAR_filter_num - AR_filter_num  + GSin_num + GDin_num + GSout_num + GDout_num) +pout*100*bool2int(not(PEfilter))+pin*100*bool2int(not(PEfilter));
var int: T5 = T3 + 100*(remain_k_num + dAL_filter_num + AL_filter_num + dAR_filter_num + AR_filter_num -N-N-N-N - GSin_num - GDin_num - GSout_num - GDout_num)-pout*100*bool2int(not(PEfilter))-pin*100*bool2int(not(PEfilter));


%circular left shift by j bits
array[0..N-1, 0..N-1] of int: SJ = array2d(0..N-1, 0..N-1, [ ((j - i) mod N + N) mod N | i in 0..N-1, j in 0..N-1 ]);  % SJ[a,j] means (j-a)mod N

%assign values for the r-th vars in a 2d-array  with given set 
predicate set_row_bits(set of int: range, array[int,int] of var bool: bitmap, int: row, set of int: true_cols) =
   forall(j in range) ( bitmap[row, j] == (j in true_cols)   );

%---------------------------formalize print---------------------------
function string: format_int(int: a, int: b) =
  let { string: s = show(a);  int: len = if a<10 then 1 elseif a<100 then 2 elseif a<1000 then 3 elseif a<10000 then 4 else 5 endif } in
    if len >= b then s  else   (concat([ " " | i in 1..(b - len) ])) ++ s    endif;
    
function string: print_trails(int: R0_local, int: rin_local, int: rout_local, int: RR_local, array[0..RR, 0..N-1] of var 0..2: trails, string: name) = 
  "\n"++name++" :\n"++
  join("\n", [if r==rout_local-1 then "\t======================================================================" else 
        "  "++format_int(r,2)++":\t" ++
        join("", [if fix(trails[r,j])  == 2 then "*" else show(trails[r, j])  endif | j in reverse(0..N-1)]) ++ ",  "++
        join("", [if fix(trails[r-1,j])== 2 then "*" else show(trails[r-1, j])endif | j in reverse(0..N-1)]) 
    endif | r in R0_local..RR_local where r<=rin_local \/ r>=rout_local-1] ) ++ "\n";

function string: print_2darray_const(int: row, int: column, array[int,int] of int: matrix, bool: reverse_or_not, string: name) = 
  "\n"++name++":\n"++
  join("\n", [  "  "++format_int(i,3)++"\t" ++ join(" ", [if reverse_or_not then show(matrix[i,column-1-j]) else show(matrix[i,j]) endif | j in 0..column-1])
  | i in 0..row-1]) ++"\n";

function string: print_2darray_var(int: row, int: column, array[int,int] of var int: matrix, bool: reverse_or_not, string: name) = 
  let {array[0..row-1] of var int: row_num = array1d(0..row-1,[ sum(j in 0..column-1)(matrix[r,j]) | r in 0..row-1]);} in
  "\n"++name++": ("++show(sum(r in 0..row-1)(row_num[r]))++"-bit)\n"++
  join("\n", [  "  "++name++"["++format_int(r,3)++"]\t("++format_int(fix(row_num[r]),2)++"-bit)= \t[" ++ 
       join(", ", [if reverse_or_not then show(matrix[r,column-1-j]) else show(matrix[r,j]) endif | j in 0..column-1])
  | r in 0..row-1]) ++"]\n";
  
function string: print_set(int: row, int: column, array[int,int] of var bool: matrix, string:name) = 
  let {array[0..row-1] of var int: row_num = array1d(0..row-1,[ sum(j in 0..column-1)(matrix[r,j]) | r in 0..row-1]);} in
  "\n"++name++": ("++show(sum(r in 0..row-1)(row_num[r]))++"-bit)"++
  join("", [ 
    if fix(row_num[r])>0 then "]\n  "++name++"["++format_int(fix(r),2) ++"]("++ format_int(fix(row_num[r]),3) ++"-bit)=   [" ++ 
       join("", [if fix(matrix[r,j]) then show(j)++", " else "" endif| j in 0..column-1])
    else ""  endif
  | r in 0..row-1 ]) ++"]\n";
  
function string: print_1darray(int: len, array[int] of var bool: L, string:name) = 
   "\n"++name++": ("++show(sum(j in 0..len-1)(L[j]))++"-bit)  "++
       join("", [if fix(L[j]) then show(j)++", " else "" endif| j in 0..len-1])
   ++"\n";
  
  
  
% % ================example for debug==================== 
% constraint ACTIVE_PE ->  (PD[34,0]=true /\ PD[34,5]=true /\ PD[35,1]=true/\ PD[35,6]=true);

% solve satisfy;
% output ["\n---------------------------debug the var above---------------------------\n"];
% output print_trails(R0,rin,rout,RR,DT,"DT"); % debug DT
% output print_2darray_const(N,N,SJ,true,"lookup table of circular shift 0~N bit, i.e, store the value of ((j-i)mod N +N) mod N"); % debug SJ
% output print_2darray_var(RR,N,DT,false,"DT"); % debug PD
% output print_set(RR,N, PD, "PD"); % debug PD
% output print_set(RR,N, dout, "DOUT"); 
% output print_trails(R0,rin,rout,RR,DT," DT"); 
