"""Install the SEPARATE live battery-policy functional check, without running it.

Save as ~/green-fanet-multihop/sim/enable_battery_enforcement.py and run normally.
It creates only four new files; existing policy/controller/topology/trial files
and runtime state remain unchanged. Checks dependency hashes before writing.
The installer makes no Docker, tc, OpenFlow, link or controller changes.
Revision 2 bundles its own helpers; it does not depend on run_live_trial.py.

NEXT, with the topology running and no other traffic/controller active:
    sudo -v
    python3 ~/green-fanet-multihop/sim/check_battery_enforcement.py --scenario A --mode adaptive

That separate check temporarily installs queues, video meters and an owned
flow overlay, probes connectivity, physically downs both UAV1 interfaces,
then restores links/accepted baseline queues and removes its own rules/meters.
It uses a private state file. It is NOT a UDP performance/energy experiment.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import zlib

EXPECTED_SOURCES = {'core/model.py': '5a6f7815aa76e5562429317ae57490bc0e6949618942cdfb27839226f217c03a', 'core/lab_scenario.py': '2243a642809a7f1672ad5999246c5339501c28f248cffcc760374b092af6f458', 'core/state_store.py': '6adc5ab5e24f9767c1500ea4e35121cd9f3fab4715b2b91c2bbaaa0f9b2c1383', 'core/battery_policy.py': '299b9d00e107f4c035c9dd456337e0b85d5553d853765aaeaf8b0197cd757d10'}
PAYLOAD_SHA256 = 'e80194278ddfd0dffb74dcae6f219d5a0a71ff31a58f75d3698c9d1bd7522aa7'
PAYLOAD_B85 = (
    'c-p;v3wzr(mgryMxL@v4jZDi)+HIB5be&jkee2iQPP$!7!;cmzn-huDkd$pT$^Gs3JOB^?K}kt>xARRbQ6L@%2M6bUKJHBNtSa)^'
    'EGhPGqpC`ZRk(<%`!ZOpcKY7Vi2iq#ETST+5>GVQT@-nhOsX``yt)H#nipPmpLqFWmc-t4nNf>q=9TmOL*h;DlgWo*l#Q~><X_9Q'
    'NJ?s5EVC>rcGIk^BIqXe{<Tb&Nf~$tFkDfj&@qfLO^bQyoiCE?XqG>EFo8)@mT7j^9c5Wwd5dWBA*sALnWYafLl34x{djQ^rCH#e'
    '<=)@(tF9MS`8=I?^X05ccPF!`gh>=pR;IL=yclH(%;s*jTSgDiy9Z6uIjn33qr#ldXR!zUm(aNMq5@{0RM0;z7e-98-RUg7yO+}`'
    'VYNrc|2aJLrbUwcAr?Hz=W`e<&0tIbj({a}v6w}f7iBR%nx?ZP@ZO%EU0<G`c*_#rjYb&&0-%&t-hC3ys{57q?%@54-Cg+im51Br'
    'mAO|XWhHmTE0@Is0E7pIX8YbWN@vR=!F}M}h5bn9i@d;>7Ay7TpJfieOpAO@J<rlxPyBKLUsbcbR3FP#{kcl#3HE$(dH#QgZ?D74'
    '^Yd$O0IdV;EQr%0i{^>n_C2~S@vk3-2!}B2bULF9`sZH(Rg$9edtFcOzB7{ZEmq6mHYyW2;b^f4=TR2jC56^PLtMF*=^{)XlB{yJ'
    '3hrTRwATJ8^WZ<&qNC%V!^7jNi-YU8zYH(C-s!>dnepIocyMSuD3c0C3MaD?(6^%vr-Au?d8_>Za|1ldwW;FQ@L@lEsn$)$<W4rh'
    'BMV0+D!mK!JM6nU<@qd~tW;w_y-;Cdm%o?kT^3b<EHL3ol0`+DhqE;MP`dg{GB^Q~WDel7AoS+oY8bvhIXJsQ(EMjOyf}aROBVol'
    '{_F7&_we}q^7#7quJ`l1gUiFP{{DcINMSbf1cty*HLz%GI15!0mKA)KW6ts@4(U09g~xy{hj0u5|M)wg<@w1;cr}E*JG_F&z2L<t'
    'dvkDkc|5!fua8fM=kE|(_j^GPdl_YMGWD=~pp9u!`b9E}R%NHp>%$*PXnqk;lX<l8JNyek<S{B@_-&S!mH$V&5Fo+-Zs@(6(av&z'
    'v@;%i&*c*zRy^8)DU5bHW1=fD5DSk79d{c&aQovkXY;z-(av3o1BnhgVve^!sq{$}3DUPDmWve4#N!Q1;Subm*i(~3wyveIcJ+q7'
    '9EO{<9H7U`B9oBs%6Zq@_z=y~7}18;Cze@bxZKrr>fyb@KjU>WOEL))?=J)T3ddN1sb8-JZXAHr`)IaIhDDJV{%GeCTQP~AFM&Sa'
    'CeVA9%oo+ldrYhQe2GIXlBfa*cGL`_Y~{xVG^DuzATEN#%k#706@!L;QG2~%3h%NH8Qjd=7~jI#sKFlZ^BL~0gew4ApaZY?xhJ=m'
    '+edgICWtj3;XMA4WC#l+4jq~re!?+Ky5V1FaK7n{KN}0J`|+c$ciZX6MT@cO)$!5tuoeD}$Vl_=@-lAr`{PX;f|r=MR<W<!G>(%D'
    'sK;G8fjb#zOQ6C3F_-X$=^VaS`r3^WT&|V}i-jES{OBTlKfJs;K0iasa-$RKK>KlwJ>v_AlVOO=Ko|l-&8A)N+o-q$jQsXn#Q8g8'
    'U(4kpDSUk{c$v(moj~<rzpcFt4TE_eCwvnp*+U8#6x;#CM>|IcXT$68x8d>6zg&l>=ZC}54j#p6`UH^Q=>V-Q0L+~Lx1#X1USap@'
    'j>V4o>P74$ilapZTnKd2H#X6=F^zes14BLHN!0qY7RMI?@(hk88Y9bruC5QRhvCuj39VQ1AOFnL%-5L<Tn1mSyd+>+k;UPgCLmsE'
    'r=yWGZDQYeN5FCcBbh|SYy}Lc2QL-Xa)FS;J@fA2jz+*u3ON6;#E6NMN1c1b3D(`!7o2Y`xvQvyxjWc(%XVL#p8q-wui>Awtv2Th'
    'XAZn%TIzg%p3RtwF^eBMSOO3y9J?h*fw5ONYHn|bX9vIwD3W9B^0JiMjHkeNynk?UadJF76ni_i2N&}vX@}_^^3uG!$WI%?+LuP7'
    'hpxFIdoaQ4hs5CzKp4rA=5#XRy}~@3;IfXQS!p+l7w(s<r<PuUPR&y2GtMVV;>^~zYM)&+!Sfa-i+pnLZjmKVmHNGB{RjlK3K1#b'
    'zJqb#PEJvRf|k4cR?~ZsYv@{Wt)KdVLlTDxBBXmJk9qMS!QX&^4nT}}%y_$y<DGR3vI|ETWIRE2iSzGz)zbhwMFKialUZz%-zu8p'
    '9^lyrf(Iun&(cYll{!HzKt6?QakRs-1c=e1>(P$>3jRR-eKt;O_2i{Y4saUwk<1^1<pMF$mp~j;Pk_5}g8^&doBR#F!Mbo$xD|ag'
    '&w|#YSgsB8{0?uq6wWdb0AP-f&wlovm3UB)>;>_1z5p&Ne}p4|?C*zURSvF;WzsQWjmRY+Ehno(R^B4UNdZ7OfB;Qp53nYpe<iOQ'
    '1zi5bLVP$aBGN%1Ljycp@MF*FtA);8JH&LHP$3l;BuWD*|FQSXplfX>-juJ94{|M`or;KVd=$}xI7t@x!EcPzF>m9+puWMq#5hlS'
    '$6r1%ZDz=bA;u#^34Os^#4pin&5eVWH^>moQ=kTMvx$q?@;l6}j)Aw^-CqMJ!T;k_O!Qmc0zZ3iVIT{-;*99%xQJGG(egR2k5gZV'
    'j&aJ=;p%f|-R8Q8>%e`XlP@<3UzO`nKgb98BP|7fpqaMx`jEy+9!fD8Tg%TrFRksx{I*Pr2cXF|WpYrswmwS0MOxEn=M5|Dc7?(Y'
    '2stxN%Ob*K_*$yz0O4*ER-lzaw>a9-=pfz{c@Y&W*Z}*=50KLc%jFah8;)vF%@@WIRPP3lMG9C{!Oi4rq)KdU7cdrB{%Y_7g`3gN'
    '2o++03E3o%;ZhiY98^tre=xcRE(3(LSu{y}HA=TJL6h#4NfryNtDaDmQI;S!xJVz~;)3+UB>=}t-udbw68c5+&@chJWR_Htu*0Z|'
    '@XYLydNUHr+WRQGgI$T21u8e0@SD(6g9NCgdIAiRQ??qxPk6?IC{|4Zc-Gce1~^vUX`N{>nu1WF!zilY0C_xT5M?HL{vm~fqG37R'
    '(K--`HL3^Hpqqi@vgEFi&l?+n7h~9j%6cbWNc|fydj*^rl;n=<MhD!~Zyu2PO?rj7(%-{_x7R2j)@wB1?3k0(*1d)|&?l{_NH@*>'
    '6ub4cAv!h(z$lCx<LnFd@uzugEj||LH;5NNWPy~ySzHZj-5%}nfOoom9RvM~M1+CB2Tj^C(MgyM6h;}U0Jy<XL9Qc<V^M;TU2<!`'
    'Zfgj3m&sjP;;x`}J$YKN8Xpb;h^y0_h+Brl1ZmA=w#1JhEO}F4V^P}!Om`WqJ$hoc>yDmi;yQW)4%ibiKm$)}YYz)d^(+Nmn%bGf'
    '-$w#zX-C%|@_O3Zt_Ze3><V!!{l>k01J^BD0{A)+<_{Li;&QUU$30dlNDiX!A+zban<UTB*OgjL*{{}YeZ~e2CdOnV3cRioCu$+4'
    'O9`lkO4l=3Z=J<JWb2|TA6{r2E&a4v0s?Mro>y=(BFAm;jd%W#6sY4PTih)6(ijBgsz5HbSk992HE=ORMdD-zCm!3)1Mgbd;_Uv4'
    '<ez}qC15yUJK`|X>k`>tRL0!q57b48#xUk4<bgNw+d)t^QIU2^V%rLsp49!F;&&&{V$heHv7#!5t-vP8+R-9X2|I=oFY=~32TXgz'
    '4BOa1qMG+*>>e|3{{HxIcy8RklH9N5lF1f3fB|s=OMs<(g}J^-v<T<73mW%ZZ@<^;bvj#a1KkE&>;no%Q5FvXLFu)(;lbgd1K879'
    'bXTfYN8zt;F0Q;!Ui|>|Z&!{NCI33u%*futL|`YaMZAHhhef{d5m*EKr|aD=i?RyK^p9lF>x|dzF&lH^<OvN3le{1!M3MpLUns?!'
    'B53-icREd(hs_As%SO=$2~(OaEjg`<?(Rq@BESY%gJ^m+Ji7*13M-kfhG0S|C4Xz@8QGO7Oq#|%c?@6guYdJ^=)hN6z4<Bvh3sD>'
    '>*>}oF|Z+`bsWnB(uAr)z}uwABsB`WVHPiPc<2#C(<$6pC8|bN-ZB#$Yv4dFn9h9;xag-K!NPQalrAg!)G@b<rin&@E~{P#`>x56'
    'Rl~_ATKfru;^{>L5cS;gcD?<U4z*5E&4vfA##3e+FY?8E)Q#9@bj#Pzm(^lf`D*Dcy)eoWqivmdB9sDz0|iRLDj+KZM!pu|&oNI)'
    'Pa9mM<jUaEw3z>Np)vnRAItykYqi~ki~lW4q(BS${g?Br>nq7m-1LCy0X7a5>U%)O;d}koU1`5VOvc)G{#)seI+yaw5ylyU@YckK'
    'P&~X{g>hO4m!E;>Z$ADT@x_{?Mi@y|<@v0JB|)##LWz*E76@DB%VGlU;{<sWQa7+Asxc40xg^+xu4mYlyK>jNypgU0;Ob~!>*$VE'
    'XY{`6&+f=Yiq?~%7N~6|X${J=Eboc*B*4BE)oKCP;?obnFKltz?Y^#(>In76{x<twQ<ty0(Y|7Of=cpD&;uMDcgC*!=|C{MXob7G'
    'E0R0pwC)lh4pD{@-YlJ@6&l_b+GXXqoQNGoy{|=QTP_uw`oe~UVn2F6^g!ZC7Z0z(vX~46nz!_Wt>Us8Xompb4H1BY1~}cFxc27k'
    '{A}oG?l|Nm1JW%U64I@;lo%|vP;dZou~<GQEz{ZO%~w+vy9o{cz!1d_C7mboLv+WrKI0y>RaM(?RqL@=S90lEnYO728y0%m{0t}P'
    'Dm*$l|1G?F_vZBY`g(YXvUByc>A-*_Ii14x5Ka$lU~hU`QNO`xM>yV$c1W%11}&-1$t!1PQ`Z_g=}0s%&}?f~<2JcVvlbJ8lBfq{'
    'c{Hqk>us2BlR(1+uLfWjPs72^XXDLaU_WozXYK34LIQSYcz5>pmxHsPdH0o}u*Gz-W(U}G*suV*gh|`d+;y6kO`tovF|CcXntB1x'
    '%04+Qm9<>(8bC{8gwkbiL{=vhoboYDhRv2Xu51MnWpet`w^<d|v=3+|_P^DRlrDTwMs!q-wL>`(rULZM^k&g598S37?xST1ZwKC0'
    '1-G1_41$ExiSss7+|dr|p3oIr_Y=8Is>dXudo(Fh1W6e*tf%(sCF^g2pxyo8`M}%9tNaXU40H#i2QP1QBAbwVjqu-Qi$CgP2@ZxL'
    'mhFD=LK);x2x*x3Jl*cz*N}UI(auoc^=raFFWyI`(0&SCBWpid<%_ea99k_)*W34)cLs7Cr8Cx&5><1&SZjX!Tj+g1J3UXTCz}E*'
    'f&@3=#lht;d^7wR-9Slay4J%$yr7?YL5JAspv?elpQNf-IZ36|;2QHto+inn@`m&Wsd`j0RyeyrpwjIRyXI3f%K$+QYLT``qB74m'
    'n*93f55js+pOz!<I_|@>qw~wR!&79oj}DGchKC+u9RT>X7cHwCm>M|oOi)XYdw#v))C02sgc!~_y6Tegayh{W4Gy44;=b@1VWE|g'
    'e5^oYKu?j~Ep7GNTpZ-EF?bg2PoF*W(CluZ)taS!`LziWl=tn|_^7PwR5=U;%LV#?cA6+pifE-a*uop*3pA5Dkb%L=_;dphFNf$P'
    'IXsjb++ZH-C%oCs+qPZ#;MiIi^6={I1@0f-Tlja9gUItNcsV8RVB?1J;cA`bdg;g%lhz2ST8}utEqVl=dG~MdFMFTbY89sn-vo{D'
    'c!Z6BgEUd757##F;rRJ>8G|$nz<M!d75krtmKez1X&#b<*e#Z>UMwf~Net{<5%Nr>9YgE8VdJp;%zy@w4<(Tg7tv*p3Z$XR$%1KI'
    'e>*-*Bie57w8l01H}#@vYVEhmm+}I^ce=G>4RxI_tBqV!^Y+tRK)=w1SX_?&`4#z=bTwDGPTNJvM;+NVbwxV#lho!f1E+K6)->o!'
    'c}XkX&1;X@Yc?>b7`>WAiA%>lK*PyY(5=n4^CtgP({oX~O}xJj)=HWEFWqe+ZwZ!1mtmS4TW{xDw&&{w;5J6&0_K&GJ(;-F4ZG&T'
    'BIhm$F~42FZ%U?u9yBRQgNQudBcdUbWx<HNjb}-+@b%y_Yrf5m(il@kxU83K=5)i!NMt*J@CkwwJ60ej4}B4assuB5Q$)L9Xa7-0'
    'C;BQRG8p2&=SLS;k7+fzKT1eHK^iYB{;^You%x!(R5aEdtsA~uJj%Sh3#6ghJU5FVjgeMd1XsTu!$9HT#qnW(Gm^c_lw%IPA+U-1'
    '+fwj0ee?et1nwpW-lzMGhCyTm5?`iq!jTpnJxvy?Nj}?1`rY9K4zVC+1KC<e`pv=h_3-j{9a$vzEPYf-Y~YaZTsWR!K*)No!okh1'
    '4WKY*rQ*k7Jk-F)-Y?g0yoWrUBzx?h!7=3MqH=I@g3P~{+`$VaI=`$HWR%m93^&TO80*(Eu5gz^UXWuhnc6i}kj81==3FU{v&C%X'
    'fZWaIIODN)@}xQdz06i^=Z^FolFKmA-sdO;$s;w-X45CNIc4L;CqBInzqHO~wu|19s*Le^nS8XPk_7N2EPP#oyMAs;pI^*E$(hIw'
    '*a)H2H2p19^l+HY4o*U;Rk<8qoc!L<iWshS^<dJ^+l9Z@Kx7yR-(4J{HrTCtu?-sOg24AtSyevU*U-$pele&1mXrGGrQ_)i1s&Q3'
    '1n0+ZhhGf>e3=z*$_KFtk22|RZI#(>*<YYax5IwAhVxll*P7P3YijT`XNs=Hwzg=+x1H=}jdxRL{y)&S`(nEs9vuGOrfl58mhGIV'
    't(#mo$8A-Q-*~?QbLr{c{CMdW<$b#F(Di@jaSVb-Fr2Ul1Zm-t*y)DZ)ZK2U;#_}^ksxte-u?MIEC)J{hE^7)+AcA;Ty*Yno7>F{'
    'u_M!leYe&3n)(@UFzMnc9I&k|GOwwvbg|}L)h8Aekq`#JKjZ^I8ZP3wHlU=wh=B5D@U-~@_QjvDw{5w76t3Trt*w#9MBA!3EfvSv'
    'wow3h?puemU_`%$r$&>Er4x4%u5I~mmQ{?E5L*YNdIyt@?75?w>m*5UMQ)ywFs7QAp--H!Kt(&DIJ(SYGfh&RAnC1mRdBZGRSmZv'
    'b*z|9q08eaDn#aa5|#AI-}5W)ZVBULRYD%v=-SPEu?iwVp*JIz*rQA^N%7i4&z3yllR+`|Bqz?3IE{oU-^d!oz781f`}FT`dd7b$'
    '^UCSL)vwgz=*Vs%eYfG~7x>-u=*ILbKf=?~A&}`1Q^??xANW;e{DfyOdziXKW|%?4U9S%h(P`$@_w;GM>%DwMpI&?(Wf;vL{&H}3'
    'crqlu;@^{Aua66QdvXBx^y%^0`6ZkG1QUR!xcwe81A;ZeM=yF7e}E5RG8o3Da*YTbF{*|w!v&HdIFQQ4r4-(I<Wr9yd#Do<-XjC2'
    'x!0A|LgkVon=ZYs*>shhBBCv7xZU6sG5q1>3-4P`SXkvUEPos^1-ZDFuS`pX=v&*k=XQrAorS`Oy!6Q*cp9<y9>|a3TseR;wq0`2'
    'op*kA^1Be^ydux5*WN6N(8fH&D{)UEG@JqQNHN@pMYg8<bQY8UJkXxy+^cf$JMZ*%Q3l?7Iv^7`7`J(W{`|{qS)#cZ8BcWtmv99O'
    '$I(~8EAi@qI+L7Aq=ZvFn~5WbhgS4)ACV{$sl-4O;VSOt<BX0QHcC_qFnYxO$kp)?o<xfh4=hNyFN5!S9^B8R$kZb(_i0(Xs>MJw'
    'DsjHq+Owx(Hf}j!1i7kA`LxN?&V>Gf6D3p=#bL@lq$oM~oq}opg+x^3$>5z65j@EQe$ciX8o)O4ubf^BKWj&{{l0@2s$1FbG+NF?'
    'H!sDxEMEMJKkNg=a9SYLd<i@<RY}}FR}}NI>I-Jba2Guiq1hK}l~d=)SN!zd{5BO!m?Y`Ue7I%|ifIrl{r-dKz<xL$tAtb@2qvh+'
    '=UWJe;;5Rg#~a{qn)Pb}xF5W%=V^TD$yM$nIkjCB{F-0_y4G*O8PfWbUA$=NLhfxZ*w+Tuzr2uLyreF4{zIawbfo_i+plfrMiIe<'
    '1*D4*``|zZ+L~=T7I?y&h?)otA(z_;=Wq!ez;Z5t``!Ml?dH23Ms>D;tVRgF46+)4wwQ2DIrtNHlL3{S%MpRd;zyKa)CEI9-}7=i'
    'kjy}wuXJ)ER{xE6&9ONm-y`v2O5dDjLWxVM7rjSRS#q4+@rCyQcL8Q{jAmsnJLBoIVcUy9a+@WBdxSo7%yvngrAVNaLKyEb(&yX$'
    '$mAt28o?F)1Q!B^MNEO=r$Y`0>WAKoVE^y9FxV}+(39$(ZML{p^d}|(w%6(6`AZkn6ds_HxPG{JtOOli^0LcYCkK(VqxW?C!(Q)c'
    'I+1|HGp<vH-qR0y1AN?wYiPwaxGe#r{`;x86;Z0R@LdhIqy(Hw6vMDQ{EjHb;O>ws7G=)jd6gg1MR@<{RMhDIJ?CxX6~Ze3T+$sO'
    'jMo#EvB`}|u+=;mI`e^8vlSQijTRhAc)0*nCuR&0Z<)>Wn7NB82Vo+=TY2z4rnD1b(98t@`pWLoip~Ltj8gi>>OQJWiK$C`%6*Ez'
    'Q&P4GNKDB3JRrv_xg8ldtYs2p289UVpJYS;N&6;&XyZEeH*y`?w7%xTp^4agzTc;D-SgX$wb+{AcQ=9f3)UjRWq`WZfb|y;aTk#m'
    'osDaxC+LNOSo@e6M9?ZFmT?x*LMRbr7zgGWO`>9Q@52H92PXssKzsF}gBD2%OnKsSe{JU)T4Jt|+naxkM%nmV%sMhEzr8}ojL|55'
    '4qP~jCO&@dc#97eG^G<yQ-wiJ>*SC;xn_<ehg^7?mVA3m7z8p8i#Sq!&!QeC@j!w`gWXVES3@I$e!gM3Tp;KSmB>YrKA>}k_)R5<'
    'F715Mdh%F3O>`8e8B26gER!cI&B!deRRpK2vS{)SQl^E1NES(4*=m%{lDlZK5`pmLq(~P`g*bnm$S5sBIY>7JoiF5_d%0T5CZkLS'
    '0>Nu+_!P2JmOKh72{PeqR!c|sD5Xk`kMQ9sHD!vCb6I?u>uHt|A!V9n3=WvpUzfLPUYqj(i(|m^@}uI8^wn^ih)E6hd-5m%Wd`zw'
    'I#e}60E^RK0(?iqewb5q6=nTmRFxk^r{Zsoy4-ib_=W1o2KrjrY~J#Wg&PAI@kbddM7?KgZ%}wudDN+ilW!hPpseDgC}eI+D~D{|'
    '20gA64MDUBYkRmaV52E^Br0hZR0%-xDe1JhkLeaj`2q*J(3boBC%8KP`S|Qw%+<6~%C{b)wDKkNzY|S`r9s=yYi==oS^#SrJNo&M'
    ';&iv@zt-#kPn%XNzsf%(aD{(Jv)I(-945HmUJ6|;tK`MMm8f!syLlx}#vTi%NpKfX>Vn>qvhRL(3fEPjt0Mr=*gG2`#r2@u1!~fb'
    '${6~J)Z4%5?fw{ypLhJM{Io1T&C5?^hnXsvvF=R^lprrk)&+7>to>y7d%Rwj^4rU<xPRaq@pbeGCN2ErEgRwHIl&@7{fhtKazFhH'
    '|7@Nc-Q)G-eyzXL^iJh>{PMH>QqS?rZjyHyI;z}d=^qIxxu2EHkHL{F@HBcpZi<|-m6UmwN7_x|eJj^-!_Quf$BsPB)x=~?wa7+d'
    'K9CNvk8{^!A)ui>BySNfUl!`V__xxt3l0di{Vs}W;uauRL3Z}AQIB1xb*_LWLtMdrpR|+uEq^PxMbH1K-+Su(1Pl;g>~aZowXX*~'
    'hCiV-0Q=sP{qc1!=n2ktMZ2INCU$^0sRkp%Q|8}*{qmSe^N2qi-TGqooyI(CDA220Ar8)7HD5njI?VQD35NI_c%!T5G$-orX1^B3'
    '0UvYV0hv?a)|Avz7+*Br;g6)qxrLA;l<{Ox(=hs-BDxiUp<q<*nL-&UL%fC(b27b^lUZH@Cn);t3e3L<-W|LT4~HiQzlWz+bPLTu'
    'q?--ksD9V=qT5n^>ud{5o{KWu@JW`LiXE^eCfNa7e$ITSKurt0utIL6U2Di0(nC7Wf5DXbz0EUM3KCud_ew0gW5Q)J<Hqe=xC>tu'
    'NiY#s^|m$6;)&bxkRg_#hrGyuT?=3=b?JLbG}EyS&q{^gFaUPeRdc>EvMQug(TTPl4GdJMOicwU^SnCSsXVkyJ~axz`7Jzsb75of'
    '7WtzkKruq06=ijDj}Yk8+Xr1xbD-PMROGV|MBf}-K*NCVJT35qk4FBGO(~bsP*fo?Ao~t7mYt1krKibz+KtqyZ=fv>ur%lZ)uKBG'
    'Ch@F^WozcqaxZo?eoWqXVVOmX@;<M8`)-V4yzG{wU&+Yh8e<|Vl%Pt^k%@XXxE4^@nW7v7cc<{+GcLsh%~b4c3QWl|dLU-#<7Wz-'
    '6d8WRqtEquQ8f%?;DMpBmlHx3Z=MAtpwb)7H1w!(OP|<4RW9S4Pu^}O)CW1pyF&SvJSC*DP~B@vxG0X<O%yt!oS_&iQTkF~5`zeJ'
    'oEYMtO8tSa3I*SN{>V;Qib>Yydb<jVP5`6;u*C{{n~K;PAdmQnfWx1#0)m{Do-0~zKCywH9Z6(}4)wZTBi)gD6&-+eaFRY{H^G1-'
    '%#}yVOz6ncX5^SIWb>>0-md3*ooYi2BoHVcy@tpiKQ|*qfbG1f&pW;^ve;94G1f_Uw#)2XpRnb^NyPQ!pxMet$jiZ^c{(E=fJ6?!'
    '9AKrHwSY#}%<xf&zGh-}+fNV9@oYvl0iw)1zIb@$Da=|kUFOdKtS(fQ%DUaMp|oQ}b!qJk<h7LWe7SBpnx^jjs?h{V-EuVD4$wXv'
    'SvQ#eTF2BJyG0726R<}9XgO}>O}$<wlWJ@Gggk0<=!xil%X?Z2_3YO(Qp*hGH3`3pj~dO8#QR24?(q$s?lGqs6w|NC_I+MrU`>)J'
    'E6-9`Z}B{`S?5md2>xQ=|Cf{Mn)>6w|LgP`(>KkdiI&XEng*s8m{FD|9x<FH*&WrDNEb%7FYOhkf|NzlUq|vKB{I=qBVA%&G1Z7>'
    'DB8%`T0NRC@Iqi6;w5R-Qj2rs<dSrd7STosJ6$`s4l;IJFsNo_w<7t@m;;Llt1ZSNHuA0lNd@*(e%+FBl}wD>nmsvZQz}5z&}Nn;'
    '>D~QpzAU~1Md{sb5EKt0qaS`SQ57FGv(X?%>Dv^ev4=Cza9{07>MWemdzsA;HcfcTZZ)89)gO^<##w;1&L*|KKH9k$UY;JD4bQGI'
    '36Y76To{g#$2@NJHf@Owi==@4Lv@LIm3nlr@Sb0jOMTZgqN_2;V<s-G_d`8Xd|H3|Z0Oo#-)yca)A`=I+B~(%=8Z5?oE*O&*5y9A'
    'R-o;w`WlTLuv7rV48x(OXq`oZ?(II10q6V?t7K}~{Luz3qr|$pODYNKq*Y;=NK?rnK>(>^lu6~Y_m0bUU0fc&$21S+Due47Q&!Xk'
    'lh}C7LgikwSQGlhg205abue{GD6l(^iVv{x<F}_5qCP<v^+=hwxL=iMfS#eA1y^(n*FRSPp{iy9TB^v3&59>Bkn7fPu0(431LM-@'
    'bqq0M7_t-i2wf+VCp3}&UA#v|x^j<g;Vbk}q=Zt+dLC1K(|3m#6xxm3M&TXgvOCIP>glbtsk@zoyX0X$VXxmvltM)WhB;A|3TX@('
    'Wrv(P8h0LOh>!(pb4XYD9p2%a5lj!eQlJ2d8+~4KkS<~OT~$b<;*PTBxyzCwGlrXq_N=&4kEat5P}MhJp0Qx5+pd<ETa-0jV{b$D'
    'q;i_yTI-;SFUuw7U2hacy)Y`B2ADfx_K^6UfYq_$kF)+MidjYt)XrATygj^8(mC>FUs5}C7Tt!bXqRY8saCEwROKwAheTH8{Bxy9'
    'zpV7AtTC#2qc_Wp)}G2{ebU+=T(ID}zmVm_+->;NbWLXit%#|rYid<9b(zyWbq1){Zd0MtRr>0#ZJN}beaHj?Oh*={k`Ne$NCaD;'
    '8mu?S>Qy{=1g^D$2hHbtXryseB~lR|-Q`%QU0sZ&%hevkEXqV8zKzvc<P=zN@G~l^QyY8xE=MT;D?|_MSaL7uDqjy#&mo^qs+pfJ'
    '5=n2r{i=!N59Ka(B_5yiUl}d5|B{Los!`k$qKcG1J2)Mxf}Zt!v}xBOo^MU_hU<@Zx6>0jWP*l*&!wNz?0yvSWn7iyr=zBYl?Up)'
    'xT4l54S>y<YsDw^N|X{wWa%6jaz)Z`Ftig9QU9!}U)~Bmz5i1`7SsEb$ukb0$bIJ%7F-D7e0;i(iWon11~>ocdgJHapU~S!^2c53'
    '+APMV92+&q1#BhQaoa}$ORiz9UU;$74A>}5(1}+Pw81V=ok7--DeMKDIk7N$6;=mtcWAOV{lOUj3e%AAMe1}K!?o|(H{SXCEAK_H'
    '|L^FUj1f|lvfmTc;{n>ta?rK~-tk?=9)avQxWZsKVWqnT(e*<qEa>&T|A7;1ojFb%Ru+8wlmFA8z3HdX=)XFqua)-+|6G|M|41Tx'
    'iapeDrilSiFbGKP8$DDTN4QFlsG>2g<a1-sGE7sf1JCJ#2FqcbgBL>L57%s!oIPIw%GNI(P{>C>_=j<9iPbeumw&(;97}*qN;{Is'
    'auHLGMkI64aiE$Z#>)OT&aSK%;sT&7B~pXSK8^xpsuMeElyxHfBUwQIYBLv2$~@W`>Sa`94Pv`=%F6rOVE@M+<u}ce3X58b>Ro^l'
    'v01ZA&a+|gVnRjW7it5hNYWo`pccJ;q6s<()rDVb`C}TT)jhhhtW>%lvzl0R=d$C^LS%t910G+u%$pe5hXHX2dia^4KJZ@t`2CA*'
    'fz5<Pf!m0fD-gm4SAo7^lM3YKGQnB;lJC;7SX_~)Oh^+dk0D#t`qTg@#@s|~z6h04S=5jby*S$Af9PG~Ab{-2!KP!)LxM}rNR9H?'
    'u!h^f7FP)kKq?pU;KtXSiue0cyQ}%;iijV4%8__N6A%C4592mdb8Ut~cB1bs>r_27Wf|U=VkBRcFEKZqBmE6epUblwKw-0e4Tm}v'
    'q5uRfbAQX(u_wMXeLUvNS?pP2cw=&cb)XxAKI=5k+8l%YvA0D=!c<XVZ1TM?+6u1;mfc*Cu)WLHc=^=67eFV3FUbv@%3%B)9%v47'
    '9mTk`k&6u*%ERXiE=I5&^w7~MtgSzSzZZv1GyQCD^07VY$1NZvN~(=6Jw&@LSb=SoovM9t%C`;E7Og_^9S&L5<u}}JKYnfyn0oLu'
    'bMfqkA+Qx(UuFf=<GhsFZ)4xv+5B{m#{ZdZ)<pKP<AQ1P;3Ic<>BQG?e`{g^dw~-c%$b!kka<nmCG!<}pwxcwQvB1?!=qjX-*++O'
    '7{#S-9Sj-l^Z#EotQgzJE^xG#j7-?*Mr8xh!BN`q5kT=IMYiG$bU1xTR$V=Wjv%8)Mv99@i+yw&*V{a-XmA*W*Q?!?8vELG_TiN('
    'hbw~%jBd-dj#l2TS`TuF<m}gO)3rhO2<Jd#ui{z5N060TVdz9{!R~rWT$iZVQQK~SpxZJH`C5Zin}Ib7YwQWi$w{(G@`Yc=#&v+}'
    '^<D`(4#(K`*oq_RgZ9%4^CxGiKXVZ>L{cQjk$t+3ER*4ey}n_bZ#BEOn%j-&0!@JitaK<63CWm(t|+aMW0~PP3zEd9uEzzW>uS-`'
    'IQUXUamZ}5?y8<LoorU8wrsTetLmfg5{>M*1}RcvzzkY3FzIBPl{jO~Oc2PFleGmMB?VutmsHe^_5meVB^4ssN>CnDk$o)^5n4JQ'
    'MNVuS1&NIO?#u;a>e_@+hMrv)Fc2m<N9M~ZZoIAYB*MIifu_nq*vD3Ipu{)>&xC_O3o>2lsn1f*cpXq-&Zew@0)=67rp7f0JDryL'
    '?0RO}L0f*;emkAyUbxgb^+46=se}amQrA1DUlsngQ$+)^*xR16L%?=q`Qt2!@7MwWr<v$jgGL#6YnE9NCFVsfHAfv5MZnk2@qqV<'
    'Ufz=#JmPdZMJhvzexpz@kLR2vlL+8(YEc@`B`25-_NDU06)JU>dv*EsTD+ySaVSRs+CK|=)3O~My=Pt>v1ReBq@EQ^^95cSWQyvD'
    'NKBN)J4C}q!9La}420Son7QSAu}cpXT-ZEpx8bL%kwG_nngXk+sjr}VLg$8#Zh@d5HoeWGxL)U9#QW<i!qzMQ>awu&6rJC#Bs`iv'
    'RQ+gbV8s;4^I?u=CvwR!m4Tz350pb)X(Yw{ii*C*V^(L%E1Oc23FnOcrYDhTfR)nher(Q!3bZQDWZQza2IIo&SL<w|@<*IB-XUD;'
    '9@TCWIdlwzyv+r)*M!`9d(9#hGK}G-p$T9t)#d-z;-jrvOw6Ihz_65Q%|d8q53=}N%^T`<5Cxq5pZeWTUgs;i&mJ*rfxf?wb+H84'
    '%~vfWjGMPPs(2(Eh3ZDrT`#i~L}`^;NqX1UX)y@o9IUM$xlY5<qXI5;uP5x~E|YO6nwkmo=TVeV-|szPAYZgQJ=i@OKmSDP&E3Dr'
    'f_k6e-U{UxcjGm>P-J6J=?R3rthjIi8f#HX^!|_6dzwzC2ohD6LI<<E6tFIJQLkOmCn2_2uA9v{ZUR@ub1?MGn~rp=qVAGi?z)}+'
    '_1%(<pbCA3Qb650(juU;v?&Bo6Dtz9hbck<L&R8Qr=E-%Inug12G(p4G$N*o)6`wF6+3WyHMOxVCLdkpq_l#6As2EIl$(F3>0sY$'
    'rI4CUNf>e(u^;U^rj|&I%>e`ZI$w%c<o}44NJwSMHTff=O@B>V2Njd0<)qOZJEW3*y=X?>VC~FKSMv}HIY8a4At<t-44V6)U-0!+'
    'Vq?Kr<Ag%hndFD)@vgYB$zOr$x)`TJ43yuZ)g!Wt%YMy$CNVvX6ZBUp(87j?!f(JrumfE8sMdSSvNjrpE$+%Mb_$nn=L@>J^;dR9'
    'qnFMUPw;yx^M{F~VY|N>X~=f}F4K)PuPjH0o69_pjf`1~S;Fi<GrhtWWLEg0(>QgiZ;`nG(7<>EvS|HIE9=|5C(R>|@OClAn#GwH'
    'y3DH5R>R5kCL(DT<uvAWgk72X1lR%jbLS_RVgg7OTPAItHj9B=7Fzy^EQN5pP)z*0Y*|LPvxJYfq=y^%133>4ijW<@aA}r()%I_A'
    'L&Lz06XQUldIJpOiO5KsKA^JLJxhA27U_6hwsJu~|I*LoqwJz@c8FloHU@ux$%&NYUi1|_HdnT4ES_yAHbkg@nG=K*Y6^4f=Q2P{'
    'mxy18XY7OAN@-!BDx!Efx<dN$0-@K$wQ_@x#@?<V+vZa}#8<mVKHC6rUZ|f9a@*Cn1DpMkF8uZM*LbD0d?XO>wV!XCKp$`PnApS$'
    '$a*ZYi9yZR=!6*b5}F38jq!}E!6E%rNTLv@Y+_3&B^YPLs}gcuZ#f*o3p=X3I*fF?l>S>S0Z#bVYfwrVRb3U%BBgyL$8Z#7<YLGx'
    'zTccOGXoOczk(M~)*H?5Nb3}fmNkFkBSGoxI9)C~%B$VDPb=X9PlcRp##eHklt=HDRpvTIlir-=w@~NlLWVpQS*1^oI;Q#riE-Ax'
    'D@gF#>YwSWqqB07FGLmAD~b@Hr~sV|?^(74UeIfT0y^R^fO$oyeiS#*1s-D_&^KS~J;_0W9%!z!ZMQM^F7&@DeNj^#p##$hxJyZA'
    '<9Qgl@+{taNuG5nPFP(s?rciFbty;%vAhK6p3pL;*AktJ`pEj<z?MYhXM?FRmgPNhHJ!CgxX?e+l|&xOKHP3rQf<mF-{u|)&DVOE'
    'T^|D}|Jh?6)!|&$(57o{ncCZEpKV$Z87d+QNyvT772szF&EciUOB&u)=`etdag@EFK-3aptKk8^tpR}^2#ZI16`Ix>Ep6pgTI-v1'
    '9JV4kb)iD!0s(DmoO+)<49sBy$gi06OZ7@F#cP&_maIl&=X$NZbG_z(hO_@R@HAAF?{m&Bj`1xRL^?@gX8eRApEa1W$a%+#^}^lO'
    'TuGxe^J~}pqNF=Q#?=G|!UOz*e!=_|lnW2bpM+S#Bn&(Ht3edUq4XMuCGGCAVF!eidz^GRKm#ro%aU=mAiKbUr_(Lc6b+2W>wB+_'
    'L&gXP-1{4=+XK~~5FbUi^andu%2YUld5I@5S*9_^B<i_p#Cx(t#O0DIv8*txPef-e5spTXn;KgykEYjr6dASkM?zs=KVT;yBbkGw'
    'UKnlW{zZh)h2$MZ@(3v$#B1sj(Z^wPB;USRWpy6aS<9$y3}1KDqmrfPf(=JF25fBBt#{&wR{NcCksj62gCg}7-BWvpaKq&ZG2s?@'
    'zFN1a5sT&!>ycMZqHMX~k}<TTo3TiZ{lHO4bbk6&ROGWOh2GWyA~L2Kah4`2{K`Il46e|(w0O_@&d;AMB{O3{Ga$<utw`A_1AGU~'
    '-&hg{<C;zHB8+_trr5^Ef4bty$@$w~!{L8=pY-o%Z?rej94G?X0{-JuMOXZ6mt;ZP&n=KO-@gb%&5IKtXvY^=Ggf<WaejHN8<vaJ'
    'QpC6g_xU`50dTGGG|3+Jpu;`*xC;;mexT5Gh{~3{S_Ua)FG&23eo_3ty|zvq;<%Bw2#@}EWY5R)iYyjLYc1ye1il3sySg|8278tb'
    'kFJdJ7}Aw$BtNiAv9fZ<NSCn@xvG583_ha9NiG#$aTibD1}8>`J2)Pym!GQ10xhYZP>~}ueyORpnYlH8Y9YGp2~8CR321W_`Us3j'
    'lj?SU3zM&swZVX=bgxD?m1fE!&5UMwW6KZv)}S%1sU~%pmg%_L5eoY2T06F;wsdP*qwP)5;zW#Y&~Ss%IOKHh8)1lg@szsS&2!)_'
    'TO3d7$}eo&q&}(8&y3>GaetPj=_MoUvNi-r`Ga#sux4e{RXwndw>BnQKWO%3`HOQETwE4}WsLG+KYbcBCPT^|8E~nux(Z5ko6c;H'
    'G$NgR-WIDMPLc(F@Hteq(e6enr^ghCk5^1MEg~VLp_w80v8UTYfGq_i9$1m8{zX@G*fp<3moX1bhs3?hIxH3gF9tERKSceG#pu!('
    'R~CPwnDn}{76W3d8h-QGuI;*}gv|4Ku3lm{6J>G(jH5vL*IdaK4FX6j_?BlsX-bU@S3OV@#$P;u&IM@m63OC7>+;cNr5}^1&T~-R'
    '1FqfYGtyTEFM6zEMBeEhjzy8@b7fHr_InMsoU2YQq7~Ilmo4{$7hUyZOUe2^`S3RSBh!xE-z(7{{fNH%?VX|ru)EVZxho<N8VoBT'
    'c@4{%a@us+q0Chq^jbS?HvbNqQ%1K7E)%3u#R)g3+RKT{=Ngx*<?#0ywwzOb>}<QmS>5j$FFMa@-JyL}Dcg?ZcG((TOD?Rw5P0|%'
    'r+Q|Eq0ouGqVmpsBnnyBn2vL;Cse21b->rnxZlniY)ucGv;GYZ8Rx)wjQFf4Pm|d)UKgQb^>ee2n-~MLrTH2vnf&nlH;|nV4$&V|'
    'Em1lB(J~L@j>vZo4o{D-uZM@>(YuqA_7s<+owv(^VqjE%ieeEtGJF>vq@uHd!hk_@s-aCa4Jj=}kmZj)e8<m!pq+eKO*$AoGQ}sD'
    'I_CFh^Jnq(vtOQ_KD+uaqdQ%0YX}D{^OSpzjQP8SJ9xeBc|OmnHsP6Iv!2f-qsGrLKShB5yz)E2ee!hE-#2VqYJ$Q11AO*5%%aql'
    'ce=LmlBZ0CD>R#VL*chZ2TF`Eaf7?eG6@xE*K;v`sO)2dJefj8>;N%z@^!LUb`2hp;|Z8CvznRQTHQ`DNUA^ay%C9EtcG19*H}wg'
    'Mn~a*Qn!TVee~kH@0qR%OO;4%67WyHEk#nkRCe*DP;|dTI~k{UNm==ha0@M8tx?l~b8-ZWmGIPPuYf5VNDWBc1(1@G8>}t3z9~78'
    '8UUqZ&P+m2JD**UV~t3-q#||O9L}`NS$y}m!AB6^(kZ}FAtI05aTw6Hi`R1LfTY^jxBGD=SWpQaaFF)OidOPzhsxP>*U__EY=jEO'
    'u<fdp>Iyo}NH+(qAob@SlUkAcsm{-iMzPt<!%SBdRnihkqBMZ<p>_}!PDVqbz3o*mbV9pzS}0xrAf4XPLqlb+@$2ro4n<n+9pCqQ'
    'QnSWpF8=hnt4yle9F>}IWB7y6|Cs!7l0DGcCY7I;0enjf%sg^*a5lUSe;XeE{L6KCdVV+@Xj(k}@#^jH?BMeFe6U`PNB@a8P=pGP'
    'j!%XIv?tc!=*T_~E-p@v@d}o0)`c>3){b?0{_8NjhJVfm_SFP%{Qdfu^RstnZ{8gp4KIg>1L3%H@-{p;Ie~9)P1lEp#?&k;Y-n&b'
    'mz)a%`3<=Nt(F~D_vO>YE+$h+vR%y8hQr!QF`K34m#T?+5vhiBFls8$T5>k6rLrBn$mQfQ9_U?Qg!;n({*S$*YtTT}%VW2ofwu0e'
    '>%;SR*Bv*7y<_L~X4+wK{W4?T4C9lWGsZ3c*y~D8nr~JV+c=`JM+`bYmF2YIxp>@ZIwP>9^e>$KQViiHaPml-0*Cye)BcVX74y8|'
    '^lmklCx5(IV&R95s`YNNQ^$chNC_E2L=?)vj49J|v~370(+EYICc}U{apQ8QoDLKMcQD~yD6{~;R^6pps6x%cOdypRfd-FV?(jzL'
    '1gV9M9`?}}RTLMKU-z3j*?Pka3yZvW+mb9>H>KR!uAaLSmnd9Xld3&L8AooaZe?OvD_7{c@no)0ZCp+j+F29+gp#V6VbvA8!ZT3@'
    'eU*C?_nR2a8<mcALmfk%)3jhtBvmC-R4O7VRSN8F36pZ6m9m+B4Qfe#1Sd3j7C(FTnl1G3`L#zv=AgamlrQX46r$2~1U=PfY`q}d'
    'X<=rBIYDqUUlx(o=;f9)FJIx?>^ly9GZ%$@TinoFGOelH)xM{OCZ`}uf=I%EaFk-2r#lSsC(GmRPw?ws9C@m<UR+=u)+F>ka$RF>'
    '*YzXSgiFBXEPbamQ+q*#!pP6pE;0wg^JTqb3_E{N6dt;T&~#hGCNcq!sno&(F*8<$9k_0oKcv5u)$Z41b(=>;e2mAqSS~6u8<Nqr'
    'zp;0TGmeHL)|QUyYLRe|Zzl+;Qa~6A|2gH(#y>Zui6bjfEtm4c3TFxdw80#QZJK6?@!DFrdSnu1zBm_rgWDI2X-if&GPSj7jex5H'
    's|$n;2-ybivAnZ%2SW=$MhXvH0`5q@5Fs#_TNlHQqWNtc^&92w>W>{$=g7RHHCKKZaP=9j{WsoaG6x=<ig01t*?6yx9V+WOu~h68'
    'Yd6kfmG(-im;+;Yi=nsuTE#l!1igpFN`>{WUaK<VC9_@iBOd<zLz)bFPtTtA@E^|M?8qhBvB@6i+Qfx&_(oII7y0i?W<zVkpxd6<'
    '!uVjoNUD<m$?m?&nApM?>5!4LS?^D}7V>o$26Q?txv-d0V!RkE&*m3ec3Kt^rnzaX7VkB29|QHc|CKBpM-l;Rxv&_lHl>eRg{|VT'
    'm!XwpW(~~1?yjD_YtuG`Tzzq}pSGA&XPrB%L~RRF33oLh21gXcC^9#QqMnin%%cxfvQ?zJ3)Z9=*fx8QHnp|!`{#8UA09l${7y+h'
    'm%(ccAY5`8-JHk|F&$o7IhoUjYHnS@?aj)$?G$vb1HmRZ`&fuyO_E;oK<)yi5>W-qA@S8U-^~hrmAhPWW)8;>2V8BJ_ZGhnrvhFY'
    '1JuwQz@%&B+4;R4=N##2g}*%T!;T*<O9MJ;BoAr6EIA>e8G<fTMerKMRlhcmg)8vC<tm{(9Ibf*)D+j94>fmJ{QP#4m)OZDB+xKo'
    'Wk}aTEQb$uD;u<qXR7NKgv^PG#fEB<V~S9-xz#mYnjEd1O_Q@V=aFV<dH?5)6Ms_RF*xOSXK$~M&(97{JS`E9$tSC|21{Ty3xB<I'
    '%KfU!-&B!7<_0AWR}`jr-CmucHYvxLKd4=~Z`5M_0?d%JJeLgc9v#y?k!yr`6cG4TC5QC|927ZOJJFWlA~~10Jnz~C0QI{Wr()N4'
    'qp`j%c7yyJ1xb(W@Dy1nVpppZQ9Il2meB)Vd9waP+X_(^*z_9Zj3K%(Ab5bDahkQ$q>G<y+}~%%c4)7}Kx!3+=;t1WO5=!y4>04D'
    '&;IXNss8i-2exvgr~'
)


def payload_files():
    raw = zlib.decompress(base64.b85decode(PAYLOAD_B85.encode("ascii")))
    if hashlib.sha256(raw).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("Installer payload checksum differs; no files changed")
    files = json.loads(raw)
    if set(files) != {'core/battery_enforcement.py', 'core/battery_live_support.py', 'controller/battery_paths.py', 'sim/check_battery_enforcement.py'}:
        raise ValueError("Unexpected installer destinations")
    for relative, source in files.items():
        ast.parse(source, filename=relative, feature_version=(3, 10))
        compile(source, relative, "exec")
    return files


def install(project):
    files = payload_files()
    # Read and verify every dependency and destination before writing any file.
    for relative, expected in EXPECTED_SOURCES.items():
        path = project / relative
        actual = hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        if actual != expected:
            raise ValueError("Existing source differs from the validated version: " + relative
                             + ". No files changed; retain the file and report this message.")
    pending = []
    for relative, source in files.items():
        path = project / relative
        if path.exists():
            if path.read_text(encoding="utf-8") != source:
                raise ValueError("Destination has different content; left untouched: " + str(path))
        else:
            if not path.parent.is_dir():
                raise ValueError("Expected project directory is missing: " + str(path.parent))
            pending.append((path, source))
    created = []
    try:
        for path, source in pending:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                        dir=path.parent, prefix=".battery-enforcement-", delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(source)
                # Exclusive, atomic creation; never replace a concurrent edit.
                os.link(temporary, path)
                created.append((path, source))
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    except BaseException:
        for path, source in reversed(created):
            if path.read_text(encoding="utf-8") == source:
                path.unlink()
        raise
    for relative in files:
        print(("Created: " if any(path == project/relative for path, _ in created)
               else "Matching file already installed: ") + str(project/relative))
    print("Existing model, scenario, controller, topology and runtime state unchanged.")
    print("Next: sudo -v, then python3 " + str(project / "sim/check_battery_enforcement.py") + " --scenario A --mode adaptive")
    print("Installer only: no network changes yet. The separate check activates and restores owned settings.")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path,
                        default=Path.home() / "green-fanet-multihop")
    args = parser.parse_args()
    try:
        install(args.project_root.expanduser().resolve())
    except (OSError, ValueError, SyntaxError, zlib.error) as error:
        print("Installation stopped: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
