% 统计验证PE所涉及到的密钥，记得设置solveORcheck= false;

include "4key_involve.mzn"; 


% ================example for debug====================
constraint pin<=PIN_BOUND/\pout<=POUT_BOUND;
constraint get_diff_trail(DT); 

% TYPE1
constraint let{bool:dma_setting = true, set of int:no_key_roound = {rin,}} in % regular key + dma mode + all RF have keys
  diff_attack_involvement_GDS(din, sin, kin, DT, rstart, rin, ACTIVE_EK, dma_setting, GDin, GSin, no_key_roound);   % Ein0: rstart~rin 
constraint splice_cut_involvement_GDS(false); % involvement in Ein1
constraint let{bool:dma_setting = true, set of int:no_key_roound = {rout, rend}} in % regular key + dma mode +  no keys located at $rend$
  diff_attack_involvement_GDS(dout,sout,kout,DT, rend+1, rout,ACTIVE_EK, dma_setting, GDout, GSout, no_key_roound);          % Eout0: rout~rend+1 

% % TYPE2
% constraint let{bool:dma_setting = true, set of  int:no_key_roound = {rstart-1}} in % regular key + dma mode + no keys located at $rstart-1$
%   diff_attack_involvement(din, sin, kin, DT, rA, rin, ACTIVE_EK, dma_setting, GDin, GSin, no_key_roound);   % Ein0: rA~rin  
% constraint splice_cut_involvement(false); % involvement in Eout1 
% constraint let{bool:dma_setting = true, set of int:no_key_roound = {}} in % regular key + dma mode + all RF have keys
%   diff_attack_involvement(dout, sout, kout, DT, rend, rout, ACTIVE_EK, dma_setting, GDout, GSout, no_key_roound); % Eout0: rout~rend
  


%0, 1, 2, 5, 6, 7, 11, 12, 14,
constraint ACTIVE_PE ->  (PD[18,0]==true /\ PD[18,5]==true /\ PD[20,2]==true);
constraint sout[19,13]/\dout[19,1];%sout[17,11]/\ sout[17,5]/\ sout[19,13]/\dout[19,1];  %验证的等价条件
constraint ACTIVE_GDMA/\ACTIVE_GD -> GSin_num+GDin_num==0;
constraint ACTIVE_GDMA/\ACTIVE_GD -> GSout_num+GDout_num<1;
% constraint ACTIVE_GDMA/\ACTIVE_GD -> GSout[19,0]/\GDout[19,1];  % 如果使用了状态猜测或差分猜测

% solve minimize(pin+pout);
solve minimize(kin_num+kout_num);

output ["\n---------------------------debug---------------------------\n"];
output ["rstart=" ++show(rstart)++ ", rin="++show(rin)++ ", rout="++show(rout)++ ", rend="++show(rend)++ 
        ", rB="++show(rA)++   ", R0=" ++show(R0)++  ", RR="  ++show(RR) ];
output print_trails(R0,rin,rout,RR,DT," DT"); 
output print_set(RR,N, PD, "  PD"); 
output ["\n-----------------"]; 
output print_set(RR,N, din, " DIN"); 
output print_set(RR,N, sin, " SIN"); 
output print_set(RR,N, kin, " KIN"); 
output ["\n-----------------"]; 
output print_set(RR,N, dout, "DOUT");
output print_set(RR,N, sout, "SOUT"); 
output print_set(RR,N, kout, "KOUT"); 
