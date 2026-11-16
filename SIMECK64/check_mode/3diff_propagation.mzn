% truncated propagation 

include "2var.mzn";

%  Integrate with #Probabilistic Technique#
predicate one_round_diff_propagation( 
  % Target: dx1,dx2-->dx3 OR  dx3,dx2-->dx1  
  % Given that x3 = RF(x1,x2,k):= (x1<<<RA) & (x1<<<RB) ^ (x1<<<RC) ^ x2 ^ k
  % So dx3[j] = dx1[j-RA]&x1[j-RB] ^ x1[j-RA]&dx1[j-RB] ^ dx1[j-RA]&dx1[j-RB] ^ dx1[j-RC] ^ dx2[j] 
  array[0..N-1] of var 0..2: dx1,
  array[0..N-1] of var 0..2: dx2,
  array[0..N-1] of var 0..2: dx3,
  array[0..N-1] of var bool: pd,
  ) = forall(j in 0..N-1)(  let{ int: ja=SJ[RA,j]; int: jb=SJ[RB,j]; int: jc=SJ[RC,j];  } in
  if (dx2[ja]==2 \/ dx2[jb]==2 \/ dx2[jc] == 2 \/  dx1[j] == 2)  then (dx3[j]==0/\pd[j]==true)\/(dx3[j]==2/\pd[j]==false) 
  elseif (dx2[ja]!=0 \/ dx2[jb]!=0) then (dx3[j]==0/\pd[j]==true)\/(dx3[j]==2/\pd[j]==false)   
  elseif  dx2[jc] == dx1[j] then  dx3[j]==0/\pd[j]==false  else dx3[j] == 1/\pd[j]==false  endif    %      dx3[j] =  (dx1<<<RC) ^ dx2:  0<-00 0<-11 1<-10
);


predicate get_diff_trail(  array[0..RR, 0..N-1] of var 0..2: dtrail,  ) = forall(r in rout+1..RR)
( one_round_diff_propagation(array1d(0..N-1, [DT[r-2,j]|j in 0..N-1]), 
                             array1d(0..N-1, [DT[r-1,j]|j in 0..N-1]), 
                             array1d(0..N-1, [DT[r,j]  |j in 0..N-1]), 
                             array1d(0..N-1, [PD[r,j]  |j in 0..N-1])))
/\forall(r in R0-1..rin-2  )
( one_round_diff_propagation(array1d(0..N-1, [DT[r+2,j]|j in 0..N-1]), 
                             array1d(0..N-1, [DT[r+1,j]|j in 0..N-1]), 
                             array1d(0..N-1, [DT[r,j]  |j in 0..N-1]), 
                             array1d(0..N-1, [PD[r,j]  |j in 0..N-1])));



% % ================example for debug====================
% constraint ACTIVE_PE -> (PD[34,0]==true /\ PD[34,5]==true);
% constraint get_diff_trail(DT); 

% solve minimize(pin+pout);

% output ["\n---------------------------debug the var above---------------------------\n"];
% output print_trails(R0,rin,rout,RR,DT,"DT"); % debug DT
% output print_2darray_var(RR,N,DT,false,"DT"); % debug PD
% output print_set(RR,N, PD, "PD"); % debug PD
