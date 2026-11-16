% # 2026.1.26
% # 2026.3.13
% # 2026.4.22  修改 diff_involved_GD和state_involved_GS的involve_range：
%    从involve_range = if tar_r<known_r then tar_r..known_r-2 else known_r+1..tar_r endif; 
%改为  involve_range = if tar_r<known_r then tar_r-1..known_r-2 else known_r+1..tar_r endif; 

% # 2026.7.24  # 改动：差分涉及情况中，DT情况不再影响din/dout的涉及情况，只在key_involve中单独考虑DT对涉及情况的影响
include "3diff_propagation.mzn";  


% part I
predicate diff_involved_GD(  % all involvements for  diffin_bit    
  array[0..RR,0..N-1] of var bool: dx, % diff_involved
  array[0..RR,0..N-1] of var bool:  x, % state_invovled
  array[0..RR,0..N-1] of var 0..2:  t, % truncated diff trails
  int: tar_r, int: known_r,            % the round numbers of target/known diff
  array[0..RR,0..N-1] of var bool: gd, % guessing diff directly
  ) = (               
  %case 1:  tar_r < ... < known_r:     traverse r in tar_r..known_r-2           
  %         dx0[j] = dx1[j-RA]x1[j-RB] ^ x1[j-RA]dx1[j-RB] ^ dx1[j-RA]dx1[j-RB] ^ dx1[j-RC] ^ dx2[j]
  %case 2:  known_r < ... < tar_r:     traverse r in known_r+1..tar_r   
  %         dx2[j] = dx1[j-RA]x1[j-RB] ^ x1[j-RA]dx1[j-RB] ^ dx1[j-RA]dx1[j-RB] ^ dx1[j-RC] ^ dx0[j]
let {        int: offset = if tar_r < known_r then 1 else  -1 endif;
      set of int: involve_range = if tar_r<known_r then tar_r-1..known_r-2 else known_r+1..tar_r endif; }    in
forall(r in involve_range, j in 0..N-1)(    
  let{ int: ja=SJ[RA,j]; int: jb=SJ[RB,j]; int: jc=SJ[RC,j];  int: r1=r+offset; int: r2=r+offset+offset; } in
  % # 2026.7.24  
  if dx[r,j]==false \/ gd[r,j]==true \/ t[r,j]!=2 then true    
  else ( % dx[r,j] is a target diff_bit
     dx[r1,ja]==true /\ (t[r1,ja]!=0->x[r1, jb]==true) % dx1[j-RA]x1[j-RB]
   /\dx[r1,jb]==true /\ (t[r1,jb]!=0->x[r1, ja]==true) % x1[j-RA]dx1[j-RB]
   /\dx[r1,jc]==true  % dx1[j-RC] 
   /\dx[r2, j]==true  % dx2[j]
  )  endif ));  

% part II
predicate state_involved_GS(  % all involvements for the target state_bit    
  array[0..RR,0..N-1] of var bool: k,  % key_invovled
  array[0..RR,0..N-1] of var bool: x,  % state_invovled
  int:  tar_r, int: known_r,           % the round numbers of target/known state
  bool: active_equivalent_key_mode,    % whether active equivalent key mode                           
  array[0..RR,0..N-1] of var bool: gs, % guessing state directly 
  set of int: no_key_round) = (        % no key bits located at no_key_round        !!! note: no_key_round=99 is a dummy statu  and it makes no sense when equivalent key mode is actived !!!
  %case 1:  tar_r < ... < known_r:     traverse r in tar_r..known_r-2           
  %  x0[j] = x1[j-RA]x1[j-RB] ^ x1[j-RC] ^ x2[j] ^ k1[j]                       % regular key mode 
  %  x0[j] = xk1[j-RA]xk1[j-RB] ^ x1[j-RC] ^ x2[j], where xk1 means x1^k1      % equivalent-key mode 
  %case 2:  known_r < ... < tar_r:     traverse r in known_r+1..tar_r   
  %  x2[j] = x1[j-RA]x1[j-RB] ^ x1[j-RC] ^ x0[j] ^ k1[j]                       % regular key mode    
  %  x2[j] = xk1[j-RA]xk1[j-RB] ^ x1[j-RC] ^ x0[j], where xk1 means x1^k1      % equivalent-key mode  
let {    int: offset = if tar_r < known_r then 1 else -1 endif;
  set of int: involve_range = if tar_r<known_r then tar_r-1..known_r-2 else known_r+1..tar_r endif; } in
forall(r in involve_range, j in 0..N-1)(  
  let{ int: ja=SJ[RA,j]; int: jb=SJ[RB,j]; int: jc=SJ[RC,j]; int: r1=r+offset; int: r2=r+offset+offset; } in
  if x[r, j] /\ gs[r,j]==false then (% x[r,j] is a target stae_bit
     x[r1,ja]==true /\ x[r1,jb]==true /\ x[r1,jc]==true /\ x[r2,j]==true  
   /\(if  active_equivalent_key_mode then(k[r1,ja]==true /\ k[r1,jb]==true)  % equivalent-key mode 
      elseif not(r1 in no_key_round) then k[r1, j]==true else true endif)    % regular key mode
  )else true endif ));
  

predicate diff_attack_involvement_GDS( % all involvements for  Ein/Eout in diff attack  
  array[0..RR,0..N-1] of var bool: dx, % diff_involved
  array[0..RR,0..N-1] of var bool: x,  % state_invovled
  array[0..RR,0..N-1] of var bool: k,  % key_invovled
  array[0..RR,0..N-1] of var 0..2: t,  % truncated diff trails
  int: outter_r, int: inner_r, % round number at outter/inner part
  bool: active_equivalent_key_mode,    % whether active equivalent key mode
  bool: dma_setting,      % (1)true: under diff-MITM attack,  get outter diff from outter state and inner diff;  (2)false: conventional diff attack, get inner dif from outter state and diff
  array[0..RR,0..N-1] of var bool: gd, % guessing diff  directly
  array[0..RR,0..N-1] of var bool: gs, % guessing state directly
  set of int : no_key_round ) = (      % no key bits located at no_key_round        !!! note: no_key_round={} is a dummy statu  and it makes no sense when equivalent key mode is actived !!!
  if dma_setting then % diff-MITM attack
     diff_involved_GD(dx,x,t,outter_r,inner_r,gd) /\ state_involved_GS(k,x,inner_r, outter_r, active_equivalent_key_mode,gs,no_key_round)
  else % conventional diff attack
     diff_involved_GD(dx,x,t,inner_r,outter_r,gd) /\ state_involved_GS(k,x,inner_r, outter_r, active_equivalent_key_mode,gs,no_key_round)
  endif);


predicate splice_cut_involvement_GDS(bool: active_equivalent_key_mode) = (% get the state[rB] from R0/RR
%   array[0..RR,0..N-1] of var 0..2: DT, din, dout, sin, sout, kin, kout, int: rA, rB, R0, RR, GDin, GDout, GSin, GSout  ---- global var
  if rin<rA then  % Ein1,  tar_r=rB,  known_r=RR,  no keys located at $rB$
     diff_attack_involvement_GDS(din, sin, kin, DT, RR, rB, active_equivalent_key_mode, false, GDin, GSin, {rB})  % get din/sin[rB], din/sin[rB-1],
  else                % Eout1, tar_r=rA,  known_r=R0,  no keys located at $rB-1$
     diff_attack_involvement_GDS(dout,sout,kout,DT, R0, rA, active_equivalent_key_mode, false, GDout, GSout,{rA-1})  % get din/sin[rA], din/sin[rA-1],
  endif);


% % ================example for debug====================
% constraint pin<=PIN_BOUND/\pout<=POUT_BOUND;
% constraint get_diff_trail(DT); 

% % TYPE1
% constraint let{bool:dma_setting = true, set of int:no_key_roound = {rin,}} in % regular key + dma mode + all RF have keys
%   diff_attack_involvement_GDS(din, sin, kin, DT, rstart, rin, ACTIVE_EK, dma_setting, GDin, GSin, no_key_roound);   % Ein0: rstart~rin 
% constraint splice_cut_involvement_GDS(false); % involvement in Ein1
% constraint let{bool:dma_setting = true, set of int:no_key_roound = {rout, rend}} in % regular key + dma mode +  no keys located at $rend$
%   diff_attack_involvement_GDS(dout,sout,kout,DT, rend+1, rout,ACTIVE_EK, dma_setting, GDout, GSout, no_key_roound);          % Eout0: rout~rend+1 

% % % TYPE2
% % constraint let{bool:dma_setting = true, set of  int:no_key_roound = {rstart-1}} in % regular key + dma mode + no keys located at $rstart-1$
% %   diff_attack_involvement(din, sin, kin, DT, rA, rin, ACTIVE_EK, dma_setting, GDin, GSin, no_key_roound);   % Ein0: rA~rin  
% % constraint splice_cut_involvement(false); % involvement in Eout1 
% % constraint let{bool:dma_setting = true, set of int:no_key_roound = {}} in % regular key + dma mode + all RF have keys
% %   diff_attack_involvement(dout, sout, kout, DT, rend, rout, ACTIVE_EK, dma_setting, GDout, GSout, no_key_roound); % Eout0: rout~rend
  


% %0, 1, 2, 5, 6, 7, 11, 12, 14,
% constraint ACTIVE_PE ->  (PD[17,0]==true /\ PD[17,5]==true);
% constraint din[21,14] ;

% % solve minimize(pin+pout);
% solve minimize(kin_num+kout_num);

% output ["\n---------------------------debug---------------------------\n"];
% output ["rstart=" ++show(rstart)++ ", rin="++show(rin)++ ", rout="++show(rout)++ ", rend="++show(rend)++ 
%         ", rB="++show(rA)++   ", R0=" ++show(R0)++  ", RR="  ++show(RR) ];
% output print_trails(R0,rin,rout,RR,DT," DT"); 
% output print_set(RR,N, PD, "  PD"); 
% output ["\n-----------------"]; 
% output print_set(RR,N, din, " DIN"); 
% output print_set(RR,N, sin, " SIN"); 
% output print_set(RR,N, kin, " KIN"); 
% output ["\n-----------------"]; 
% output print_set(RR,N, dout, "DOUT");
% output print_set(RR,N, sout, "SOUT"); 
% output print_set(RR,N, kout, "KOUT"); 


    
      
        

  


