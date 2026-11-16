% 1.cipher        PL_{N-1} || ··· || PL_{0} || PR_{N-1} || ··· || PR_{0}  -->Ek-->  CL_{N-1} || ··· || CL_{0} || CR_{N-1} || ··· || CR_{0}
int: N  = 16; % block size is (2*N)-bit  % 32 24 16
int: M  =  4; % key size is (M*N)-bit
int: RA =  0; % SIMECK%  int: RA = 8; % SIMON% 
int: RB =  5; % SIMECK%  int: RB = 1; % SIMON% 
int: RC =  1; % SIMECK%  int: RC = 2; % SIMON%


% 2.distinguisher
int: pd = 3006; % 6041 4542 2802
int: rd = 14;   % 30 22 13
int: PIN_BOUND = 0;
int: POUT_BOUND = 3;
int: multiple = 3; % 0.632 requirement:  pd+pin+pout+1 < 2*N + multiple    30.06+4+1<32+m --> m=4    m<log(N)=4    pout=4-->4   pout=3-->3   pout=2-->2
set of int: DINL1bit  = {};   % position of "1" in DINL
set of int: DINL2bit  = {};   % position of "2" in DINL

set of int: DINR1bit  = {0};  % position of "1" in DINR
set of int: DINR2bit  = {};   % position of "2" in DINR

set of int: DOUTL1bit = {0};  % position of "1" in DOUTL
set of int: DOUTL2bit = {};   % position of "2" in DOUTL

set of int: DOUTR1bit = {};   % position of "1" in DOUTR
set of int: DOUTR2bit = {};   % position of "2" in DOUTR


% 3.assign round number     
  % TYPE1 decomposed Ek as:                                           Ein0 -> distinguisher -> Eout0' -> RFwithoutRK -> Ec --> RFwithoutRK -> Ein1'  
  % Eout0' + RFwithoutRK=Eout0; RFwithoutRK + Ein1'=Ein1             ↗···↘ ↗·············↘  ↗···↘   ↗··········↘ ↗··↘  ↗··········↘  ↗···↘
  % i.e., assign parallel-matching after  Eout0:           1=R0 = rstart < rin      <       rout <   rend      <      rA  <  rB      <       rB  +1 <= RR
  
  int: R0     = 1;          %round number of plaintext
  int: rstart = 1;          %round number of the input of Ein0
  int: rin    = rstart+2;   %round number of the input of the distinguiher   
  int: rout   = rin+rd;     %round number of the output of the distinguisher
  int: rend   = rout+5;     %round number of the output of Eout0
  int:  rA    = rend+1;     %round number of the input of Ec   
  int:  rB    =  rA +1;     %round number of the output of Ec  
  int:  RR    =  rB +1;     %round number of ciphertext                          

    
%   % TYPE2 decomposed Ek as:                                      Eout1' -> RFwithoutRK -> Ec -> RFwithoutRK -> Ein0' -> distinguisher -> Eout0  
%   % Eout1' + RFwithoutRK=Eout1; RFwithoutRK + Ein0'=Ein0        ↗···↘    ↗·········↘  ↗··↘ ↗·········↘  ↗····↘ ↗·············↘  ↗····↘    
%   % i.e., assign parallel-matching before Ein0:              1=R0 <=  rA -1    <     rA  <  rA +1   <    rstart  <  rin      <       rout  <  rend = RR
%   int: R0     = 1;         %round number of plaintext
%   int:  rA    = R0+2;      %round number of the input of Ec    
%   int:  rB    =  rA +1;    %round number of the output of Ec   
%   int: rstart =  rB  +1;   %round number of the input of Ein0
%   int: rin    = rstart+3;  %round number of the input of the distinguiher
%   int: rout   = rin+rd;    %round number of the output of the distinguisher
%   int: rend   = rout+6;    %round number of the output of Eout
%   int: RR     = rend;      %round number of ciphertext 

% 4. active techniques
   bool: solveORcheck= false;  % true: set target state/diff to find attack schemes;  false: just check the involved key for state/diff you want
   bool: PEfilter    = false;  % false: filter of PE can only be used after matching;  true: get involved key/state for PE filter
   
   bool: ACTIVE_EK   = false;  % equivalent key mode (waiting to do)
   bool: ACTIVE_PE   = true;   % probabilistic extension 
   bool: ACTIVE_GS   = true;  % whether guess state
   bool: ACTIVE_GD   = true;  % whether guess diff 
   bool: ACTIVE_GDMA = true;  % partial guessing in GDMA
% ---------------------------------↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ configuration ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑---------------------------------