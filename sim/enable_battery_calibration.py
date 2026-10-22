"""Install a separate source calibration on the verified battery-policy queues.

Run this installer as your normal user. It creates two NEW sim files only;
it does not start traffic or modify running controller/queues/state/links.
Existing scripts and calibration results remain unchanged. Validates the
installed protected-policy dependencies before creating either new file.
No dependence on run_live_trial.py or previous calibration runner scripts.

NEXT, keep the topology running and stop other traffic/controllers:
    sudo -v
    python3 ~/green-fanet-multihop/sim/run_battery_source_calibration.py

One 40s concurrent UDP run: private UAV1=90%, fixed scenario A, no battery
events and no failed links. Protected UAV queues/video 4.4 Mbps ingress meter;
source fq with application targets 1.2/4.2 Mbps, --fq-rate 0, payload 1200B.
Captures both endpoints plus an 8s tail. Removes owned resources/restores
accepted relay queues and source noqueue before evaluating acceptance.
Same source criteria: mean +/-5%, all interior 1s bins +/-10%, gap <=100ms;
first and last 5s excluded from the interior. Path cleanliness is separate.
Completion alone is not source acceptance, measured QoS or an energy result.
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

EXPECTED_SOURCES = {'core/model.py': '5a6f7815aa76e5562429317ae57490bc0e6949618942cdfb27839226f217c03a', 'core/lab_scenario.py': '2243a642809a7f1672ad5999246c5339501c28f248cffcc760374b092af6f458', 'core/state_store.py': '6adc5ab5e24f9767c1500ea4e35121cd9f3fab4715b2b91c2bbaaa0f9b2c1383', 'core/battery_policy.py': '299b9d00e107f4c035c9dd456337e0b85d5553d853765aaeaf8b0197cd757d10', 'core/battery_enforcement.py': '521758411144a09f7336f15a7849c3e08cbf6589161328670d8a1e396dd6354f', 'core/battery_live_support.py': '603dece9c7006440a386edbe431b12b1cfc880c2a2d8872e23e4359b0c2666dc', 'controller/battery_paths.py': '5b961e969de4b1147f8f4bf6a52b3905c6b2b8aaf715531a49a4e4757d830677'}
PAYLOAD_SHA256 = '9cd015abbf93fefe016d34306a5568a3c7574a52f0c53645e54886dcb4ec463b'
PAYLOAD_B85 = (
    'c-p;vi+|ciw(!5A^{($i0~nm7o08IA*Ku3lCbrjha_?SX^^-x^+JHonh~sVi{q5g*&1hyc0@BCLZVgEDJagvEne+T*FHaT+H&Ic<'
    'tA}tB&6Ar|R3up%=IiA$TNRz<!(Knw8`1xcqh+yP#X*!#gJKoUX2~Rwa=|QH1;t$)r15>QTxCT(DdK7S=XJb}gFIWWCUIai-x;N&'
    '^gNwE1lfHWPlKCmolfENU)fC_M9@WEWXokd?F1Lm<b7N~UFw=&CMgVe7D1CxJYIdECiB)PO|v41mdklEp+^DKO|$!XJiUz<aa!a7'
    '3^IR6CwHqXP5ur2Wog{Lj~?37cpg0ji#W=m6DkTLyuM5FV3AGNbDY+PcoifIoGT0>n8&x#<N=_NMDrk@tdeCxV7ZI(AkBhkU1SRw'
    '!z5Tl3C)&4m~snP><)mTfB!4bQvCxe-svA%K1ye+Y!NKsDO8a$09=eh%loPRzKZqN{BB(&^YUkMn?}aZ3?W<oELQ7@@pF9x%Q%Vi'
    'Tt6!AR&g{<(%bS$vM767uahY*D~)!NrL*K#4R#r=q6L604=(ikRoqc{H%~sq3gJ|hNw!!3K(WCQpvEk?UnNBxBA^-widOI;ny=$#'
    'f0PFB4<B{7ND+T58d$C~T`!h-gUYo4X{NBQgTq!3&F9&Dm`3T~`)HoW&EQD@OM`3F3gUE<;S>j>y>&5bzZmT`%OMC7Hm1o6&^uc_'
    'w1PBRK-<ykc1>8LhC_V@12v0AS%BY{O#}zjM$;U;jMzICti6h17%6vBjt&<moM*QL9yJgtO5mXa)Iqgn=xw#iRyjOb#mhPDE$A&s'
    'W?VD=nB+y?Xa+IBD_~3(kjw##!bP-t-%wrtIrwhHn-=N8JwUrnrGh+KEa&k{*ix`hVFOOWG!I~l<#({Dfd)JTcUfKpf_5=(L2U0P'
    '2HJwaL~QGrl^X&N>_ffBKgO$Q1{k)ft^nwl(VqEs1VoSfZNYT0eR+sqTU=B9llMHk@P_9e#_3e5&=4MZohI`r&x7-Iv0N7yfSm#|'
    'rVbZC-+-FM!793k?KsWWOjGh0_fHW6wZv)U1@sie(d16ZAHWXq3_363V4kEg5m#*Xh<*avrZAa+XdJ^iSpxlR1yiH|t5&dt-+7Da'
    '7p_1)xr>470fKabGbDTpR77}}05aWkXe}mea9ndh?KmNNiRA%J|C$H!$7oUjN>4lHl=(X%QWz#_QiNe6kLNHnL4p>-BD{l<&0!^A'
    '_AsW<#BcnEH9ArOmRgf7>wVb{6e)i=rHmdJY1A*L9BmdTaRvv7+XPWbtgXmp=bFAX3ZMdUF`!Z*K7kd8VgTUadIgls+fD~odsQ@='
    'YDo!H)EX8tp-`+I`Zi+TCol_lTAgeer;X9x#~Nx!Ye>bN*6<%5^67eUgGfWDm88%HP&P!*hPe(M#@|-ZYkJzje;Ri;Y)<!|vyx0R'
    '8#t03E6nEW{I0Hbp0+e<93Vg&u#1pqj$2w_;BSVp+q*%qu6nVtHd1LUOxt+{M{}}l;2E`|W2*UxONXpV80C{BVf-nNvCZ?Vz##rO'
    'iGh7Np$}r4ay|{5m9sFPKFjyB1XzptgRh2-5gj-S^4Lb`=?a*n3PPK^;9nUOKs13C2G5PL!wF@UOY$&6Zld909rOSv*X26JMow_-'
    '0MFOity+#%FioZb@{cf+B){ti`><NUer5l7`eu+MIaNoB@Y#LOq6C;!yH9G>WInRA05HX?aG6XS#4|`gvm~BRbA#I$j`s5PG{YS}'
    '+H0r$$;6(&CuzO}_CpG^VOs;w3BT%4a<uo$FP*CbHhBl8kpe6p9|Qg9BAGruVp}+<akG;H170Wu10c<T;P4om!Jh`fA#&mTd)OW0'
    '6To*sV3<0R7g_>(*&D-pPLo?~3}3-%($KG(!PkSJXF!^v{0?~{1>@^%nE^xeP{K~F(u!x%hpu7U5HKxv!0yUCyX6kluRXac%pojS'
    'tGu$nZ)Ol?$s8V45FYEmQsReu!U6jUZ%odS(17+my|s2e)q&a9R%sWLB@#F+RILf4h7rc~wS^hRg4Npkq*bF($IgAVES!oTprjXR'
    '<Mac6d3_uny?#A7#$SA`>D=EXlRIcK&0_>EG+bfK+HF2_saCOSz*w7%@@XvCe{hqe2l<_JJE?4fzs8fhEcnY`f^XpcUwWgxm(YJQ'
    'D_#QGj3@Z)KSz6i#mch?8dYFXJ({qrj!!6>+J}5W8=Rh9t0(Uh;GT(r96aS`&knnlF**Q|bwz*}plm1jY2YC|%K26A@I|Ffc>A67'
    '*!}8DY2vMX{x5#QrLzODUEagJuaV{W9ltf3oh9C`0QD;^-rHaSST&vfFs^0m$_r`df{;lgPfM8Pfq{DT3`pp}sCISz>iq4sb@Je$'
    '@lZK=rtp;58<#a{;34~>EC>(>EU%RLTDRbw1nR_4BLea?hw}ADNA2;UL@{tPD}aZZu2(?Lpz&h86r!egUU}_nHY>xi5VXAK@wG$N'
    'NI&);4_FpCq`ZicrUt-3zyN?V^p3zcL87_#bAo9;kK<*d(=`wLjnH6*8}S9<NivAlBA&hs<iHciC<KJDH7#^NsnZUOb^S8dETIwy'
    'Sim-*(qRtI17PS1r$P->PeT@gxF_LO<T*{DBCtCwdlQNkT%5l0vW`NZ8z^yt$_F@WyeJ&Vv<?8OlLetWJmzWLJQQ(WGaq~ZcjyiR'
    '3>(c8u!g#W`P~@g(R}wg6Fn}c79=SCNeW;FfI{3NQedM@a)J5sPJJUog|u0o2*oCNj6LmG*m57i5-MKyMRO+}TCOh!@61dgf)K8Q'
    'lWaB3Ex8Y~bVxUUxxrh($LTZpGkFSsZVus3)Whoqfaq%+c(2>-0wv~>@Jb3%aj3{8zbQ*rX2><4P2tbeNlhP~4yY{DGCOEKickk{'
    'ujY+)btBhP28IEqJ3u*-@(7sdeth`MX4R1k<$}zGK0_qq2gCleu|hEcoR@{Sn9DPiH7oHqZX;w5lL;+Jza%uYDCT7=ohDJ*3TCTl'
    '!h-fmM4XazJS>M~oP~?%Um4uF;TD1)A^ks3qa{oV*vz=N&sOh|zK{&Jvrh3$ZE#n_t^N4pDf~nDO7qY9V;ejTvkQVy<FFMxBT}O}'
    '_*0e6cmQ+qaY@4e;H0>VS5TKg62Ltt$IInm=b5$F_zcAxtlM;U?<{HW%jy9}+<bPw<FO)m02OG8y)SFeTl*pb_k~G>bE2v6h7(X$'
    '2uB`I%H?e-@(Oo=Yz5RCw)m!nQp<!RtPEW>1-$42FU$%7dSUn3i}3m1zNFPMN~s=qo25DyXpZVsfDUepyUHY)X>-;`_1yFVovRSs'
    'Rl#2ceQu{Rq6fULA@GAQ5Fp*I`VZi$Rs&wy`%ZD6B}JXacpQcNSdF=F-DTB8z7BfNHeW!m?ogGX_kn{j*=z<3TPuk1eetkFD$sk@'
    'vXLW1bqO@}ryq&urmkVd51Vjz7D7oIsB8p?Sfl&#1yJf%0G}_S7bZ7TnFEgkfb?wp*5>)Vdwq1~Lw<7}JIq0MY|NzuOYme6Jkww='
    'n+ELZe(b*Jc1_6hrM(o!)=%=VyUU85UVM1w&M>*djVo;qxxsPpA3^VV6VOVA%Dd&)&mXY!7WG7**}|7)3#78KhWO1l!7~IK9e6m4'
    'uK^19T?YF#KHLlyMH#$snU$md4_KS0v)OEOYu`)pSQ-Sr8Canl7_^{3l`9a#+ce8jd&;}9>`XMt15sXffafg2w8$cRU7qv~`|8`5'
    '>Y$s(&}7Pr;q484sTw%!ss>Q4olP=C1H1570(+9x!&|*B0N5IY<f3qy+yxzrRRs4J(i_{br-!XzO7Ch>#=;ruSPQ%I^&Bhy0{ksO'
    '7CABgMk2!!V)(-NiEpWMs=%Xw^6CkFc`Ol90}cq>-;5crr_1njwhRsa$upZ?KnF%UUk5J`w~Z&?C`4~Nh`t5c-@dx=oqi0o&U!gT'
    'orjv*V6+G2d8`lf3^lP-bx;nZ{i0bnXoSmQ_eFo>xhY8V#3ErE=7Hl!79qa_7OBXxAiq<F8l?Y&v-0OP+`i(<QTk^t@HBYZ`3mpF'
    '5lpxrJUwjRB!#Xes#Q2}57v0<HeLjD>uYu#2ot>U2Bo_j*RJ+yb+vm2af{~;HhsD2WK(;r0<hYRc71%|JJ<?~^vkdgnX($hUj|Xs'
    'kXRT=@j3Wc4#tOuHk!fkOeBZDg(5v0aTfaU;H>?#Rx40UmZ4hI!OrVRyVu?c?p&(Z40mk@(pVLsTh}*7oduz41@B8##WEq68JFZ<'
    '_o>k_k2kR)@_?Il3^kN33EQ$T%?*=f%cQdKTd{5c-WW}2fL1?0?DqOdvXdz(6n}Xn+8Y(oEn3;&qb|{BZj&sQh)e@N+hn2olq@#j'
    'LWa+W<Hza}Lnnv7b0=~h6j?!6psp5F1Z2@bs(xf%Yh@Z`ZQu=i=2noqh|Rl0b2ggcRZ+@9r?RHy$w#Uvy%1Ir>ma0Z_9{6zi0Y;!'
    'T^kA<IiSl1`J}W@F)Act2wCr~4RblBr&wW#jX2G!PSw6AoJOr1omeEl<uWM3hrMENM-;m7`P8jQrsO0rCT0+MkIYn+ht=Ql3`=7r'
    'P55`b%H-feG^{_p7!pGZTgMK{SmkUS9(SVYv{6n-R;sQO+8^T%;JqA_4K=V9<F$D~nr~bVBF5F_Fo_W@g?mx^b3m4qQ5vk%XmOL='
    'uCsL><VkuvkK0%;xIVeM4o}Wr1&cV(quUr|pGXYdc3@6<9xra@51rsml4BDGlML?3`Gky&(qaYYu54?Z-UD=rCYEWZ20RuS0MIU%'
    '@T6e^h6w;+af$aG5~b!1&&{=N*_y!U?I4|c151=F;lhmU(QKaG=K-)UWC<Do_fpU<d>KURDeyXQ8PNcBt?!5uwbX!1>Mq*15SJ})'
    'pnP9VLJMXF&_-vLq|<0VZvd;&_;%6!XJa&)K55F*=ilnmqf!3FU+@^ErsOKKBJ0@Q8d8OC9)kBMhnV|X6!NHtD4KYwyZMrGmX-Er'
    'GJDm~0X9HKZi4r@3J~Fd(es2;0(Bbd_psd?(@DaE4rM5+nEa$tVqAA|dH((B>ys<w)wmaEo)qbOD3E=3etLYu0(*5&!J`y^qxn*}'
    'xLMLs)$1JMvm)bPFP^F6(QfVZ)ya9KwZlql&+OKoeu=G#1po5n`26w}uOdP)na474Sj&HoMnhbw#<zW3&`(!y-!w;~F+6(G7<SuV'
    'b;eJcZ7QIC;Va<8@k3eGK|Au6o{p}bSoQhGPj7x0e+#UAegL(bPIap+;5pVH1jDWmsDJg-tTq}otg-EnMpOf+BkYpZCuJho{8nQl'
    '0O8Hs*Vm`7PtQ(D7~z(}o04J(%nc>a(0D*jn{}G7(qpuzCPZMzCHTpD5<kUfZ|rAZ;<F#@XJ0**bZQY5lRG3+ymGYl61W9fqtcQ9'
    'G}4+PTT{SUfFo-K|4Pu}xfRT_9DWH2firCqrv(aqNfSW5bZ%GKdTHs<m?p|~9XkjKr+|n>MT774it{pFz|W?ag(nbMxXKmq5#DMD'
    'mP7nI4h{%7{#JNS;lgNwAJJ%VroxfsYVYE+x-k(<+zRxNnwuv1lFV2`Xe18>bY;)-pssa<Fcv0A!-AqI6q~4y_8x702>B8KSw(C7'
    'PLiWp7~GwB4TkT>tRvSygKvPRAsl%RBlh2z8pg623)QNuM9YTirg=9#+C~_Jj7#@1hAXIkrUx<h*2Rf;@rtD@*lRep-Z|?vZti};'
    'Wo8b~Vcy7&n1%MX;uyHUrgN{NBId=4iAtES7r=BpSlg1HCA5Kts9VCt!cW-F6#|180PlthV}wIf9ca+Wv8mhM{h*X-vz@ezx3p6b'
    'yFk-2OUjTz)&%yu>XJ@CJsK(HSr}ZkEyC|hXFSTAMK@v(g)zfGM!YKby4_9}sE1X?!k&W-gH-DaD?tifI1}<XT21bVyJ5ygv-Jvo'
    'QxqS!vss&JIgCx&7ZeJ!SxALowOMV;gGL%7oswxGuD*<cJRT}ndTG@_y(}w;MX^t)8*+Sb=JC&;VK+~LyW%Do!YQAQzZi{fumSkc'
    '57I{Gi*K8aZwFHP(`fX+%?&1+*sFbp2A}ZftMlul*RKT_e118@fnF7hC`UO!kOr<`!Lx860ng<)teCxcQ0q7%=PWXf$EgNCUVlg2'
    'CG3c`nD13AFsc3002AR%4rQSdYnq-oOF&j_5=$$AC#7+C!!x#6zv#TWJU=_RGDb{7QRv_!YtKAp>!r`xfLrRo-2qO1HoI=ecu^LW'
    'KQ-jgWn7+M;PW6F?a`dt`#Jo-Q=r{<upcyNI)=SobA!D&{M%~si`I(#Z2^}x9I7>o&8_3PEVY%*AYmncg_XFM4&x7&k)eBQreztH'
    'uMriUjbkAJJuerZZOmY}xOW{7r=4w|EkNALY;yT*|0tjHBCXwQA{2nZ_xGo?S|oHK{}eG$FAcize^=*kFON^c<MXrYBiNXi!GL>T'
    '_t=q2mpDDUKDqq<==g+6tb2%7U8l^CM`y2IbAi9jP$px){{HXb`Nj3=`PmiQ)XtMdA_k^tyTjk`-Wyim)ZhSOXp|P~g%p0?d#23D'
    'lOh57UGo~qIyws?RaYx0clKh^_@d%7Ckwgr0=iJGTGviU@Iz>0dEi+@n-JN)R-jN|Kt7or6olEB33Yrd1XW_LLF6_>(f7zK5UpFr'
    'mL`yzX}T6Qo2+TbfeIaFfr#-XiV3M~M29uP=1Fa037rM}Jms1VR4x&K|6jXrdKZP82B3-GL;jX54#U~cWPwv!Rg^$`55yCJMqUB4'
    'pV=p%d@W8}T)^58TlA<5Fg{AP0ic#GlG>SkdH<RRv!4UqjTmZ>TTD*WN{vLG;mm(|G(=hNW1#7}VLVM5#wHX)yN0_3Ys~8G%Y(7a'
    'aFcO6o;^q}9m$ytmj(|*B>1UO?w}oG@Bw7F9kxl0SII0vw-q{0uvNXFW_KkaXa(%3Br@(sPaf>FcF;Muqs*n_G`cYjHwF6CGGHYg'
    '9gMZG;pCbHj3)EcHgwRkq@mUpC!%e#;j9u29Kv(FM(v<XRHD-~OYy9`B{iv<gcgQX;HLNPeT86dWq3C67u-ghkiSiRQdRaFA<y#~'
    '(*Jvs0^4u7LJe#}Y|`jBhk3*{>C)5FqSf_k#bz@`Qy!AnR4&S|Vz`ANGDRsa3Q<zPYa#?6;MA3|vOg<JApeRO!2u1hct<rw9<u0N'
    'i`Tj+eSm!h{0*7%DpF%sKs!DjtwZt#n&hEm!7fwMy+J+Q+rIeh(%hcR<0xG(>(~DGUU<`%+HBis3*fi0sg1-@9ky6sfvRQ0NezW`'
    'F#ZLgGe?$qwAbI_b8uyx!D^Yym46AR{HzF|O14ICYU6+=e4g&KSykbUyY!D(uw-U$Bpycd_W+pQL)0jnW8Fu&b)@L13&%&VPrti7'
    'LVh;9IDdV5{0|a;iU+xv6tjd^JzM~8ha^lZvU$9UQh<vx`Xse=r~6zNrmIMjtwP|c!aSa2>2!15UbpNh`j{-%i%_?rG#BA*v=nhD'
    'Nkgi=0jsfK8ErX~n<!6m)-7B>Bk^QTQ4!+wHc8`{+<S}wD!~N3l!0Suu>h(7tdCYx3TpEA><Xa!^E#1GCK_>2&X|U56wE!HU=#sZ'
    'mt_WHJ78TFvOviyH<Uprt0J8%3u@SN!i=**5=H9f(Kx!OwXjtFi0ZC|-bz%jG;W9%bY0I$Cev`0t4bMYyOeS*H1s*#X1$oNF;-22'
    'Cxo60@$RtH2e)MHtRY)+eFP^`tz$=q5fYrmw1I~_hBlXM9`xd`N_z&@W@1gL2e7A$Lw6i}p+QixF6>N$4)xr=&7qV6S@bTG$_^)j'
    '9SlpiAXDd!2nT&vx6{yrl`>wE477sva>)@i;BC2dZTzWDz|(XxUr*ui0|Z&;7`$f{P0=CfHi#3n+znJ89Ox%nJ@iqVj3%EHHApoi'
    '20+=2!&^|TwwP?-GSP#aS!?nS!P8l{eGg;_csOnhiW9V9mo{(@lEwUuOsCn#$5D&t*hFmyU4c_K*Z~x|!8Q3eT;^q6T55rYz5cj4'
    'Rzp9U=NT{o821R>LRg_qQH&4_62k<C3%d;`xOwDC?5#&n!=_QI-rK#gJAQS<rHGv5A>dcTx0F%e00nohMm8-^)peQxu{O0a#>Q)z'
    'C8ukq2Ef!AA(_Y`$Y+kxu4{)V4^ZE59>FJ8VLEBf+AObZRZwvfrszU5M;eGNAPIys27c(xW>4S?v}yU`#esT#VC%Txj#nNEW<O-l'
    'l&acLiQ{4*p5PX=2dH-!l3r97PGWAr++KE-T@Dt+1Vogk0}WcJ@Fsr1K{GJLzjira=N2UL^`cRr-by{>7+wYmvKwcE5;8;y(Ncm!'
    '+^A?4v_^n;hAXRgWO^!OJ*wL=#zW2MktiaMJ^*&}r99f|sKguC05D@cQihwXJ>pRtHKVkAJ2Y;^@A<Fn#tPhXq~e#c%RhxNLsbr1'
    'v}0pB{6LGT7SPF6@&U~d(J_&nLAQj%F<8VRdyhUpMw?Cysuqu?5?P=Of-op+?;d?X#{(Gc9Tbb@0lT}i)S6-dpwwChX9QFz8{n8a'
    'HQ@`qF$nA^0;VtEeQm6+okI)wWy0;a8gHNkb*+HZ3Lvm+%z)a~7_@*y<SuVOzg3ADAUu8<GT=RbKCQnkpo)Sq1cjp-ZQRHa(K?;n'
    '(V>C(Vubnf79@VitvGapYOx`~SDSpRe}&h-QRMW(cTubh1;C0zik{=cCSOc6*j(#b4oA$O*Yph>ZJ!24fG;a3Qp-f^EgBc4G4XE~'
    '3FU*=!nth(Ai;dTi}F|p^l?C31-c$TIlwy;bHfAG)pdQ8D?+lZp7ub8;er_z;vh~s1PSH^fG1wXBGP4)f?XW({nLh>^*NDq6s52!'
    '>h`rnJGa8!&W6h9>E;*!P{Hv2$9W^4kKs%_R*yS*umAQ*Rj3|1#0TgLFI3Nrioy~n@&-tz*1R_a?(%xfKlP($<NS*5do4@s&@u_g'
    'HMel`ahaen!-oubx&t$R885OTR)Yj&#hDS!#Mqy7x-$n~s0c$JB8(apPdmRcQiN3+IHUy{na4h?@T2qR!OnnREu41g1XsTCn^w{r'
    'WTQe1D5{Nz64U|`!y9pQv0oQwp?-LO(B^`pM)audnF<25k!(~b|8L$1xCu%r4jP2#xrouV1c%ibr8odaM1htJi4JK=caQ<eomFYf'
    '2INArLU}6chqxo3In$G%rv*ZJzQzES97c`IL0j4+l(t~u%9QF9VBD0tevkI9ROn*%hCh9k2h)u3j*VZC2xyxwQSxX%2bx7GPbvc*'
    'l16&Flq*Uf8aKh$K~#}N=pcf+Rgy+Dcb|!lB+4O`(=64jn(5k03puR6-;X!+_)67LZo6hxC80E+6@N(Ld$aTCCU0m2(3Xtt5-Cbc'
    'MtG_*3Xa51ZxbYBnZ(FVUw@~`Y=(XfHxEIEDxGepSK7RxSecNs4j;cD7a90?0j!#ClMH7C#U*kgwR9jG2FBg9=F4IKU<zJY-Dcr7'
    'ZHl<vGv%SYC(6nHfCe-aOo7H>`d;&Zo*cBF@9SwhLO_KMeyN5MbW-@!VZv5bWE?@;*=(z+*H>Dsm9>nA$=Cvyea?KdMX0%pU|++n'
    'BpEP=4M03qg1cVMV%;hXd)<8_3Jf&YtZu69f}U|LB5bd^Vf;c1wER&^`ccS==SU2UPOsZt_#8HPj#?7NKk=lxRj5^wmLaOOlx~JF'
    '+_c>0jX@&JiVcs_e;XboeTE-1mpHFb=|ad1oF37^`vF5fp)()tf3hX#gTn0uHaptXvP$Ii?D+ib`1RYX(|0Er$809GRP5{Tk4|6n'
    'b2)D0`Nh%I6&aDMlXDTHgp14@ZKKd6h09@Hao!n?ZbVcEdy1-|Ys9cW7#m&|wsGrClukD_v|B5pPvK#)O_KO7H>iWpGE>5P83I1z'
    '`O{qmpOLNS4c}ZgI|R`<Tn_*q9C{8De+7-XC1|Kv;L(hkI-kR^lo0^pWP|iph#`hdtz=`w$8BCl=9JV2+!9R%<r}Q;72}&=Igio~'
    'aH8T|yj<UC)ffUYN#6%dYb-e*3Cm#hFmQec|2%6nJ9qKNVP8`s%!i=Q_!WGe%oCRJ$rH`&w8%wQ*}KA7o)mQ2h(tmjlp(N7L*CiX'
    'A;#ffESdeHnD}y0M?D$4n@sNFMWkJ6O4r3cX)Y;@e_K@7hAyrBp(l!GfXiC6n{;TiJy2!014)R0B5}bZG1JVZ;&U}iKBA<VFkr3n'
    'R8YJLy?&)efPxXwhz~t<1!jP(G!;;OW9-WXEBAm;t7NxT&NYlbz%qo|1gXzpt8{})A0nN=Sk0BvMBi9APnJzc#J9I8$PCM-ZP5Bb'
    '#rl&d;4+)sQ3!g*`JsL^uCyvQbf(VYvMu6992tu9*by9H5R3lUlnOq27BgGQ!kv@hHHHX~xG&X=AZUG~^M<gQcg~7tRA&P!<KY4q'
    'Z77q?gwB>xJc*U`gnmwD#*W?|ZqsYGaG^(4Hs!?Kbk)b@(6ZU2m^T0r3PI8CHE&j<25h`fW*_o4wIq+l@$eju^Y4MH>QQW1qmzry'
    ')qkH}AO9Gh9lbd*O<?mf-eom}y?x0=<_+(z>jLpntm<@VS?pd1-mQqGKP+&=+h%sAyNnsHw(O(1Yw*)cUhk<nz6IOd3D0FTYR@PI'
    'Vj^={3vEIh@X8%{6$7#PJk^1+tH&<LI+|jrRJ^QI9K2HKD4jjQ&f0Bl)Z!Y?-^KG~sO<c_Rk1|1o(dt#?Q%ka9Q9BQ86$>yL31AR'
    'hoflVlbC|Umw`9SzEz>0+sNv9O6<CblwHRp0J4j7Gx!Xt%giAi7+t&01#nsoX?;;d9#Sh|2~B{S`e9*&oCM?;A_svd_=xsA;L=0o'
    '^*i1fX-_bSE)omX7E-()t~lyL87{KYKFy}qoUAldp`aSuP0Cc^ttMrElpUaLTBe4xvuRnqc^MxmWRJI4=LM!bQMP7ceqmtSMu0jT'
    '5$cC_wquN@)6I5_yBI5OF?K{FQ8-B|XTAw$8J<p_v%!!UPjoD0!9Z86_qg)bTaZ4bWH{(95b|9JwZvvnQ+lX7;-eBTiD>mhcRV4i'
    '_+X&72=ri1)Jml!{k6FbZkm0ntOQGD&sCTu$S_}YemuXrz8dm5F@}qU<TV)W9YAYV1Ts6aTv_ur-&zxBmI}+Hdmq$B0~#1Vn{EIc'
    'iJ(r=4}h?j>3sI{%J;^4N)c}0JZE(hxl~a+1PXj3KMtGfuHyZ-A2j?!HP?s8vJUeQ=5c{kFlUPV3o`Zdg0rev(;&LS0Zy5Te^KS('
    '(XkY7NTy7ZF9a`I#L~h!%?v074y80v^zfyM53blbE&DX&qLxQE@eZhd-OfActR4fEETWn)%ueQE@D6A=!G*M6VYiH-rIJSYJJcdh'
    '^`NF)hojz`2(-c*^l0z9431l!YLAM&)V3;bkKXkLUv>9i250Ai+=BwT2kA?$+;loPVmhwf%toX`3k;K^C&BaX=bp!?e;c3?PNQlT'
    'V|ewIM=3|`7~3A342umX;IL%j%yX|TOW$7VtP+(oyUe#R+UprvRy1EVRz^CNndwD@?-dIJTIFG7Vz`sgT4cur2EDEueObji*udu0'
    'txd(>-@c1gI4RU=z*sk=K%k!3f=W%f)Qu3)a;Nl7UA~1{W`Pi$0wjtUMP>iFiQ#<bL;?>L4%19ZV2YtD!WH*SqU(^@IPGr2R0?q_'
    'Rxrczjz!2-Xj~ibXczOx*u*%U#Oa3tMJvei4t!5mcsUi*s?pxDZMjmloe==E900chFL)iBn92!cOESiICXp~L6pJNg7eB7GcT!~X'
    'I7^ko5#UfipvXcPHz;^>v&>ro#RkI2Kk^$TP#lO$gi|jAeT@ma_0;lrB8PlfZ6SvYi_aj3#P2#GVYkx6^`;vKyuabb_ix{@U$t(<'
    'h>kLD**8%9*;Q`aDxu9Lf962%7#yiq8~TX$RdqfT$w{X3+iAMUb9bQW8!&nE(uNkAGkzllHVpMDdj;Nya?w$o8dkyP`&5}MD-A-8'
    'vozQxBU!7xS3NRf;(_HhO8qx?KFFT$l1AWnJ&<soJ74*abe3eSEh0m?@7!eMWJm!_baYQxw75)LQ#pTdv@kdvu_ri98Oew^dM;5>'
    'Q-32boTx0dTcsvSj!rg9prafY&5Z}Q2WB_W$ot9+f6vq13tuZW5J{L|yuIi7&c}W2d4g*iN?(R${PqK-WJhG6s`5*v!s5hAfQqOB'
    '0q#4GX<Hz~_osP>sAZ`I@t!7|_Y#pVcRSVZ4R>D%9jjgMZM#rTc;D_r(-;3Zlpi_S=?C5B=L~4Wrsb*>MvFKL&4`J@w?^py`{OZU'
    'gv>*<@)WBe*6Gq$>y&eF?~1w(C9850eoMVxx9KVAHLg={HziyJ=$Kux1_VR*Qg(-(1;_?%RS7id60J_EUAC+c=#aC1Zr-hbSX#JU'
    'jwpS3-*QfA=>sgW77R3hWm-Aqwg%8OjkmPL+w`*#&pWgl;Yr03T?9=kpZ7*_CK-5ILsQi@2{Ws;bQCG(d#I5iB{>b+9Jfl#g<A3('
    'eZW}i2mo9F-Lazz;!1MCuO(cdu11~N7hQACLmkorgHTw~UE|d*g7UwUNL<2hp_B)6RcxVYvVRzSI%HEgjps!q45Gwpa%!j`y($zC'
    '%lstXnBqUUoig`Cb;j-58CRr&w2UE*bZXj&I8Ad<kg;C)P-26Wb^}fY9Xn+F=!&ovcK!YmY#Lgv0Gs+X1qL^8RgTES&@er+gxxLQ'
    'JGUKKJ5zLTuC#22MWpw_;zqujV$wxa#eL<$+_hbvH+5LgQuvVjond<Pt56)6T$$zL=U&9cd9HFBbBVnKSsYa3RcfwUiTVht9XE#@'
    '3j@&*bz3k?-JrT>nhn+jx#X680o+M<Fa2gJrVaU0`s{Pn3&TjabX`Y7&Rq{BGi)YWTBY%{t=q|MW8N9*r|q21-W3*vC2~}T_3Z04'
    'X&I2{n=^WJEd`i`-`C+NSN&kW^K?eCpO?xm0l4&oePHKx99Ibi%taTJ_uF>|Yw+QsnjX5LV#n4y=Tc|Ab8muv>4;Imh(L?t4*#7('
    'sJxhWjmbUK;0}~=f7K@q6FE+z_3fQ$FraKw_{ElPnCCMUR8ovn(^Dx5?8L1#J0WEy4nvZP7{<BsUL{j^okPfwkgcN{^XMj?x5SvQ'
    'xs!t#m)+)6=LLtWLUT;CbU1w)Rn4q6@L($pT$IP9zNo?{s%dNW9XGF;G)7K~XY*e+bXPw4iRwl1?JeTqoyN*L;s*OI<yja?(T0!l'
    '_1-pXyod}j{AO>g%^q21Gg}?9euGn%*$?|<z1*$ea-rqQYxrH70Cn>Apv1m@H7boNL?LmszCC&uS?N+fqjh4=TwMXXa@k#&<{fSb'
    '72=XYX`8buHR`rsEeyrFk<B#b(c)$r^|u8w^PE*?QjrQLO<@Oz+D0Z+F`Ag}Z5%cp^Y%n7@YL1odr#9HX>#@EO;I1}FWbL|1R3Kx'
    '(23&5B4#%Dv`FpAm$UklbE0jFawSrU1C;<nS-J{FF@TIf-y3IBO_m|jK(uo(Osb9XZ7_~@Z%SKinYWrRyX{fb4P<@A&U@q39?cMc'
    's3TGv!zf>k^H-w6AfSBYWeIVzTk}=S2;S=8&mu~b8Eh5>Vk<knW%pj+#+Fs{G>I7nXlzDOAId3HK``X3&64gubd5SzOe=P2)+ktM'
    'wYj5zM^p-bf)X1!8G=M_GYo4Eh&VZ$z;y9z7-K5E3S{_O91EN&DbszbT(#cc1h$%;prvbs?@k^6-mt4Qw*^HntzUIkL%M2~@!z5e'
    'asueE7AVsxaa7y@MsaN*NRa8bw$^ZAW;;u;r_Z4q3CqE;dY1)z_LWA68#h`q=~N};Dt<kruxCP(&C-<3;LDA}WVaC&NtiuH+?i;1'
    '6Df9NTXT7HQM1rlfLyu`VbiRfQLQR}QoT;fu&NdOyoQx89?HCb;=rs00^)Ku5T~A&<<Y#OEgFeGbpG*NUwEzbgEjF*&|VH&YdK=P'
    'WXaLPWI-(3M4KU!8R|~$tXMVOwxyI<%J}GL>CamVf#o*}C`basvD0C-$urM^spA`h!q-0y?BNd0q*N~3V>=V;q4y<gIyI;qi7^YN'
    '&WI&R<Jl!|&*n(o?%kAEI}f7ljMH0acW)7wHY?dAjRXmsC0u+nQ;7^+8JB5aQps(If~kQMNkF5eGO(2x`W_+8(2z;BywspoV=2<K'
    '#y}RimMiJl8=}A%8e8z%L$i9e!b+?#sS`UJOB@6LEXybaEw_}>VOh$Zg~IzOhP*4ZrWtNEp)#zMNSYkTvn_-2fy38GnGv%L$;q>7'
    '^DLWg0!o9rVDxJ7b3xNDC7~P|Znk4nT<K=~8=INFL#e|?%~jW2n*xyR&n=XeBZ(`AlF7c7j=kk~r?PhQRT;s71ubbcowN?Qv4c5m'
    'Q=@og-9{&+2lv~fcj6=`ga!4|)*de}GhVU!(DkAnZ|jn++ThGzVQ4NEvFpBx`9e9TJqU@|KB!X%nK|pxc#qHJ>YY|I2abV{cc9`4'
    'vU8weYY4+y?bKLO!g3+Mn#otjQ7nyj96qHXkVR$Y0$qH{2=*3Y?MN3SlKl=Ff5QfC?l=Lw68vyg#um_lK7iyY9`+?>!h>T$Vvr#7'
    'H%$Ov*AzW{o=rHMr+>OGG2axX<Tp*I3}gcH@dhz*VwWiU9G0(OKt-5Zqe85V&ZMHj?GH4uF$kR|hsIlkv(sTERDrL$yp^&x+0?Ph'
    '*Ym>b0d6;Fs7vJud#%PRSjVuO6!{|SUsl{s8hA($QIo;a_QZDa&{mEn!c$>E#co^COnJDTAQ28vj+Z1Dl&7Gvd{)ywdfVSfjCB?$'
    '&!N!Ys(km&OHtUqP$PE2=Tx;iD6c*2P5#=J=Nu>UTE;M}n}qK%f6uO3DmyhjKx>{!5KUn*^!2FX!M#z=XWsUioz)^f#!Gd?hyre;'
    'QXrXl(I)}6gP9dgmTKY(8EF+vgrk;lIGmU0=dyYz1Ez4?7m4%ovV4y5Q@$Qh<dl~jbo)8bwt~Z112O4X*-AvWXHzAy8|hcA1o!iP'
    'pku7C;!wxM(Hh5~vHzrVINRTEzNFEJe(`0n@6|Cj^caTq0bItafED^hKlMd*@u(NAGs-30JH)e5-IZ*ltK6c!D9M<Hp6D>>3D2)8'
    'yLsIAt91j`cu_G2TbLiBo!nP~=eiB<R6QmtO%ZVwfukmDYG+`Io|%1yJTYmI2V+iTn$);&4(IPqE{|TnHn&W0bbNeraeZ`ld_vVq'
    'dR^HqA5ed?=elFmZd|ASWsELxoN|R@OQStwCwRs2)uMHgEufVNu>wqQ0uHXfDntw!trBP%ozW(Dok|WYq7tJN2Dq0eivwspRD!;$'
    'thuv%0Mf_NS&069fBHWsuWABSpbcgk-zzV;HlIntkhe++&`}3v+&{(fl0&~M7jPXm62_Dw--}v=fWwz#CU>$Y!ngxL`$H#qOAHd+'
    '$xq)MU7w6n<%q}8W?pi*nfwk4ot+2warFM+-|;GQT=bAjNI6qYcAsK<D8PjAo#QXenrujIF*y~*K$}Mo2ZYM`ftp-#pK1G3!(_RI'
    '3~PiY#OgNN3EnZ6oonrf*b}lOfB<o4hSL#X7k5zmE}NrWb9$DQn1Cxw8C=P3&RPC|z#K=bd4je-#)6SJKZ4Sjf=3158KudBgc(56'
    ';1ymB<pCUn5Bdjs=AwEB_4Ct0Kb}p}Vy=JPMfn|cr+*W=s~=fDN=XoeTNO$L@*LF{y3nfZK2L7Z4pILkX>0jYYlO>359N0<239{X'
    'q>$uA|F4td>+tgY{95TvLQ>R(A<EeDY>sB99RLF+#o>=p3hi>tZQumrRe@PC(XPO34GHiL#aL&OEZE<RfI$ZMw+a@}C5oc}#uxhi'
    'D(=jqn^5m1DSCAcd*I3}MY|xRo1!X|18JfoCN>MI%`dxE^*u+vQ^j~`@o!oL#A09lI3>3qWQ|lKlD7T${QRfWla_pjZ;q~hY6U;M'
    'J-U1q!tOo4JiP`M_07rk$z}N6(G?VYbM!yq$;J8ck5K0|u=C-Y)3bAx$q+%O0s@HTs`ANcX?1e>gksaHtEjT`OJGJHa7OTja;jIS'
    'gGR?;zFyKq^d6vATbfd7n^_WG1D{9IYqSg~$%Ztp+BLRdwfRb1u2#Jo(9{&tb*q80sDxb|7O)kf+t^4ZDE=K>V6(bbRW5rl*il64'
    '7TYMQ)(OuIGfdJDqQEt0%f=QZkxh%iVGBKVvimTN(gCZ2NJ2XrrL}IKY6u)%romxk>at}1x^$;HK8<n^vm(G7WAKJ8`uu@>X51pb'
    'Y_2w#k&MR}w$3b@yV)&=4N7<0+AVi)vziH}l0Dd$GuX(tN%<X_%89(#mt)ja>5yvyGDJ{}BSzqp+>K{7+GC3{biq{~Fdm-*xr`a|'
    'PH|m8in+d#IDw6C`%0YsDOI!szLBizQ!<4k0`|wJyJ$7VFU`U5pRHj0r1dQZ6XeAt8<!-FZQ-&ZJ)tavS&}xel!U@)Iw=7~%8V78'
    'ZUn_-YKKo$RbosKy@VCxyw`RBM5+q2gWAn+H$*^eHmd;}>(=bg!TGzZ;IPyC8}qQa#9t(b2!b~A8?<bl;Pf_CIe*Yq`XTt3sPN#F'
    'P`etq@t-)r+L7bHVP>5#zQwHIwMA8;a3do)X9B-+tVvR&V0blZlyIhj0Z_<}P^}w1)C)(r${E4Y*@0$KiF!%l8ZF?}r5^v>keBKR'
    '(7DHTx|u*H-W1`q(=^$n(~J7>lQmh#CwKAWeMs8@_qC0W{}+3AiFaZ+bA14mSA!B<?sgQA=|<cf3Y1GgUQ*8YuU)34N|}v-R&-lf'
    '^CbmM?J3B$?(CaE@2f5fjo|tLcZbz`$(9HhF|{4n)HqqbWX}??oWL&zj7*W_M{}Sjy?LN98c(VbqrGj)As^5xtGJu3`JzdIS!~ay'
    'BD(cJemW14wb~ANtgd_}#j@dPw@bDS2zq$UP#*+OzxwiUS70+?(co4=3g5jxIx`}V8`=00;JB28p`rLW6N}}Dgj1DnStxFhQmDU-'
    'K9Gv4DxczmP)=Sg&yrR=<?$cJ`SK7zPS6Yhy?WA=4-)v1(1u<ryY|kTrq_wCAx8;yK&FoJV2Ei{3kfjL>yvc@>Y9KesLbVE{d6+V'
    'qlpC7n881MF|JF{tmiID_;sqI+0&3Q))-t!;F4VvZ_FG%B?q^G!bzt}IMDCd00d35x8vx5Lam}e+6eBm^;|_h2@HLk-IlNpbYf_~'
    'V@30v#j(gA$IeS*JL({>GC@ADV}O{DKq$bLByx;!Fl)h51$<8pdi`EEphVgjKpN--rs9nrf+6h6&iDyDNb^tY{L>=;1iYeVT<XZh'
    'mIdYRRYLIHphqHmj@*POFZ{i1wjt-KXFs&L4yRcOsb_33)JUv2ScjnUxCVqoNsZoBj+s^sR#5OfHPZUY>9p=B-+7QU&MY4?_->^;'
    'daMwbvhyVM@$6(kMEJA`T)PA!)Qy`EQn<fE+f?*(+Wv!<*$@ScJqL_+G6@j{S{M8+?!rc)aDyYFd<<0~8&xczm6Q;Q%u3mD5n%}z'
    'Ns1A9P)*PZCUG)vl}Ei~yYEpnmR{$n{E>|JhxGVq=gU^`tn&=7OZ50DJ?`}Qzr%`~pO<kInyBYU_ct0Eiujph7y^%+j=!J-M3#Kx'
    '!QtU3UHB+xE=7@5r=I)b`}m<%W;GGWsDL&2DF+QekOl~!-WUb!BUxoWRPK15uW?oy>}%Dzi)Si+mkt+**%*{;hl>n*q?wdxt3g}O'
    '2RX!E+<v|xPNfUFd)NoJfiY^d#!TyB=tXT|cg=9AjCxJI>=p=GHN#NVDx}(yp*1wtxC2y!Q)HFy7qFT$k}Dvrz8M712&$t!LQvcj'
    'hy{v17_ScPS00$Ulb~@WGZkW9wdvckOooRgtzvDyI<5PfA{cB%zuYd0TG3Pa`smfNXaO3q(xHU^Z0NjqW~}{eLV}xecc9M>%DR-O'
    '*GO;F)rS8YV=t)S)9L3%Uns9ez5pjU|I3H9L_;W@HjI$sZr)1xU5)=%DQ_6IR>P^)+=$Tb<sL0a@y-anAdykOQPp?${rTnb$(xh2'
    '>i{h~PF~rvHt}<zXV)v}2rY?_`SM;jj?2)P+LRRSO0bQc;NZ#j3720+3sDE!u4E`#CH+|SuE6G_hBpQk_S**Q2*c#o9Dhi3^yh)b'
    'Jo`<*o=%E-n+(aR1^j9RS1Rqt>8-}!da7ta7F#>e`VCl)G`pY2(_7Xoz-}fwR-sWA-df5E88ALneqK%iO~5yf@rc)nDjz7TVB4sf'
    'w3%|aaev-XGKo+op>+X5>b<^Il&11}i=C;UP5YhhEU!n$U|$i2D$h#dS(%zQB?$S{DomuT307ERl}AB%+c}GKRR9Q73AE{<kv~fK'
    'LaPiv)rD-k_|mPH+mbjCRv-v^v8^`u;;YVYq&}x@k!zk4RG^%>V3&0dEw`MQgR_MhSxA%+pvcfl*4Q8jHVt{G5x2sWz{(KGG<1<n'
    'S>)^p14n!B$s|QfB;|aS5FGYn7H6s>8+}p+cw*xf+D2h+g9@O*mD`TXnIM}~#`svFio8J}9ZCQY@|6+W8I`f!W?WeOT5+t?&R4ub'
    'IM)Npr=#Lr81Sla0Z6@b3QJAuH58c}h9x^KuboL+<>?z%Bms=2=Ka6sem$#~VxsdA1H%!fxhvzgkfb3_uv`I}xH7yKI5)oSw>|~U'
    'U(tMe9~N0|t}mkdG@mSaHJ{b=Fs`2Fb53I{oHU7U4B7QMP2ehxaJ`S{bZ2{O#q+^>>lhc-mTOitJ*p2Y;yAW)o6-W>Vy2wJOULtR'
    'ztR0T?6$v(+Ownf_v0s@NW9tphSbP_fuG>q3e^vP;SI7-WMfe1$({)mMFf?#6u#|0g6_xJY=$5aowW_-R$vkhU!+3Y2LlmXrt4>O'
    'POHG3W^pcoPAK7%b<&Y+Ri~72lN!{~KYz3@6(^`~g#}U?fmYxe-0Oj@VmOD%kQ%La_{vT#StCNT-t8S5Itc2K0@;@0uK5Gnwggd7'
    'QX7v`vQ9HZUs^#m=s(_^r{#;14)%ju3Tfz+M3JMzc5Rn2nTlFd1*0!ggBnF}&*V!b*~;%PC6ZeiwP-|CvTvWPzvHW?VJ^y24w#=|'
    'FyaIotGSv9>r<?vG$-ST2CzwLPbp6414SG3Yo?+2M&;J^DU9ZafDcMvoI971H#EXVZ4?bv1sJ@=#6v_-j;JSn_i*t%6{UxUy2|-Y'
    '`5|b>Br54R32<!#2y8~jmo3WXadz}N{O;)T^7P~~yga#h{SRJu+O^&nxVgf&7q5=4Pr~m`emFhj=P>EZ6Ie;7O4D;qRYMo<g@#mn'
    'f|TnVU~mOVj6_vz?n$>w)(jh_hnMI|VefpMwewZ;K*QU99e65S(z`5yMdf4~=t4cAaGB*Df|)0N?@}>dZ9|JqQ7yIA&nl;&0?Jgd'
    'b0o$m7xbnvjq}MWA)UY=41rvPVbiSIiKf#~8LVI`9UZ=kl-tN)k`;pl`xrdyZmAxn(fr}xv966KeaeGmb&K0qYSIVR)w~#b(7?}*'
    'G*J^8qZ-PlK1hSv99-d-z&))IDu!ucMYcyk?{3IlT{>O6d8~hmALQFLO#Ot@<-#FFvWXfiZqw18Mw-L4t(c*B{&MQw7RtHe0h%>('
    'jC}v#dzQT!JE{{Tv_m*~s9UZ@v?Q?#?h034T^8yWcW`C6y@NW!zLeKOYImXR!C+iUW-zdmA|9#33r3aYNGjts@K8h{HjD&qj{$%W'
    'u(V=>j0)zJZH8QWv6li2GkKgRv7}t;$_K0{DiuD)F(bytA?XP#c_@vjA7yKdk$&$af4WH{nWO<yJME+e;0n`N@sdfiHXjUR3jG;b'
    '4Ht2glUtlOy`iV$&(68|S*a>_N>*vdm9enh(_CFfNy#T8_POvFJ#ij=DF}Bqa!k@$W~5nJsJs}z{L;Cih*R&FXMcQjE=r7{Rbyqo'
    'QlrZNQXU>^r&uM?yu(R_bQ+Jy){voHcxQ%X8u+IrPhOuN{}i75Pw>h7efFIh?+7#9v9WiDKN>{V@Vi6Rax%vP77;$PWzmpYSLd(8'
    'D`@xRx)tb0a9qB<Iyrjv>ayi#&gORD-aKtIE;`5OXV;hKuV2FndwPKxB#j3b=a<(e4PQO1#g4plmo0$46U^XgoPIcf1`ptC8&)p5'
    '#Rc-HD<9UKBqs~>M$_b6{@+1eBc7Y&Md$6&yYRdJ4&QutafKxAImx!sorE2Kbvy%rBHU+CVG<Ns@SOdmpmJW(Ztk2OlGFu6!FEQ{'
    'B3t?sMYdz9wS-F&?y4;ceUE7rCFb}f(H}l70hUdXqUfR4iF^&)qQZ_{MFw-mSS1r7T79dlC)dIh$aM3zGsvkR^@FMvdBct%U|A-q'
    'FXqyqV5yoZ&Ld_evf*0mnbn(4@ZP#+9m%Y_2!_q1)eH(T&@z=X-dm>r`a8f;+x=q}i)M`yrc695&h}(B2iP3VDL)Yfd(CZ)(JYQQ'
    'd6yfFSiSJhh<)Bg4XIjS@n<PmbzT^<RrSU@iz}dPle=IZp~WlPtV#A(?DK$xnbek&W=2bKE47A7B$)Tx@}V=0<0XD+uscYl+>jz9'
    '^i-rdJX*uqij6Nhu0`jot|=GbJl+Gx8>Dg3k_H{l%O}`EF&bSbqv--er%s(4rF3FRR*CwZO7F@pMft*0ijcCg8ey86X=#du>am^r'
    '_KU>Il;%~Pj}Gxwy13cmXYVkL-l?nz$bNBeaOk_HUG%gU7_tbR!!B7Opk-Hh2gna>(n8CSI=yOw?+<tzbo^NRn4_tsUn0{uUC%K%'
    '_Ig_Swf4zsrP3ZruH5#XNqh7Xt<~xqMVl9Yqtp0y6;0!*B^M(*88uR}Xwwby7`xq0x3<A*@#j$d5nH^V2+AurnpnBU9L35yLfxH6'
    'iMpmmM|sC}((Jx5r4(H8zfr8VE+$PhHk;uSbY1?({$hW6z5nC>oBgZ*wc~D^A^luFj73=aK|Q+*h<^|?cuXY3qvOiHCOOX+>MY}D'
    '=qA^}KhNOGdKZ5j_Irn8-vB#{_wc>JR#~|l3b}M^r6Jpnu{Gh7Yn|WKfvHlMD$jS{*@yx<4ogh(N-;H}GtbI^+Om#OHb3IC%PD3b'
    'Xk|HlhUoU>cg1kYnhk4GO|7G0&R<^S4Bzm(=<xZMR;+pPu<Y=whRd*1uy3{qAkURXlU8z?+{Ss)@K|RV;nUC;?!a~p>?|Kduxq|E'
    '-2RLL+Gkcb0n|6=0vl4Nj&^fN7NIf}-QZPcjs|Zn>`h5e&GZu`nE8$!u2GIX-eo5zdB)eOog%b45jK@)pM$fXVGHV$9VoeO!)?ds'
    'yrrGRuoK&pvSC<U@{Quv$?Kzkgm12V)_Arm!1SEk3KhQmw=t{+unO7=rscPy^$-@4ZyvA|Q$j!K#!$|H*=^(G_O8IIO%Suz$N*Sv'
    'nn8A;rK^%_u_Jf&HeY~UyB%dvgStlTaoZ@HYk5R7rR7aO=qg!_1YV(Uk1egaF~(SzTC-|eRi@W8wPEQ8nwyh~^82H+lk4!mPfmaM'
    '@j85S{_134$c6aj)$z&M(dFs+V6$L|{z(mFNka^uH$bUk367>}^XTH@_36p0vdktkspiJM-kkq*5?;ffvw?e#0UZBv{p0!B+q3W9'
    'e*gW+<;kmoBsR1%a2k2!D>67Y^SL4UtEMC+t@y)QG9zZQWt-E<wlVQEcIyfmT;_!<!6jBz<UoSrPhJs7)cBciB*{%TF3IG6Ixw4P'
    'QO;8MPp45;IY;XfrZ)W)_BPI|c|>Go;i+XNSq{0zQc@V`R;?u1LoUkOBS*3zhF)t!`Z}HSzGwgkn4SVz*uV&Ef?O+!OE|+^)&8l5'
    'q$ttLU}t+P6ynh&9Wz4G{OT)uMH6gdrw&Fu@Hv=!d$nbl28LJ1ppyJ-7y^fT!8NA?qOZ6YvjtK5>eM;b46T<NxCe`eG4#NXehs*j'
    '$!5cyu)l-jv*%c3|H^>?K+VFkh#1!!F>>v1f-c1@RNdKkS&C97-3)^6M)O4!#fuVM=XGA^?1?M+V?6dVY?99Ls>ymaD!3Gl$U-!w'
    'QT!vfu@UNkdowm2g21;GM|&q^sHozpp#4j!p{PrIw2fmSv~7!QaA&TiN(+a^78f&gnFMJQ)b7*)tV5FHQ3x{$w(K4l<(4O-b^VL%'
    '*4ch4G;J!(m}>Ox@i!Q5o7@FLo%X#5fYh|c=As!}uL>L;jL^rhmzw-g6x9qsQd+Y0#%ALVHeev!K+^^qZq3bLhde$FowbIvu{RmO'
    '`4sug)p}WYb+I)aRI^3sf^H5U*3H(Y@Zr~<Ox=bm&Nv`YguRsDRh2G1N7{y@K!0pXAfHm(g45^a1Y$5*u5dU7T$gMqrev27Ycp+$'
    '6XV4oa!uR*jrk;JtY#7xbH0BLF5?C8n*r*aZ`Xi82c->OuHr<o(;=n4olmv<xDs4-tnMA=)t4*=#oRGv5#yPP=AfLbRsh8Fwtk8G'
    'AbX$0gYL)uj|cdNSfPd|)=#sN#f4(l;6&LNF83xRTA~*>ou8#r!LN((SU$2(-jrj*k)yL}?pG-yY7z^XkWr)Ap4hM!@?{eibas#s'
    'lsT&$c|f!813fvd@^yXSHa93m2A)}Ov;F&QuhTl?XTx2yXZdQD@jL2PMNCm(H+@gmwBkaf@)XN1T14-03q`^fbT;_A?CM5p3~eJP'
    'c3%3EDxL&t#w((xFVT{9&0*j&+P}n!1WDm_CaK7A+z42oC&}4Onqy+H^e2*W4hv~SJ>a)CO)R;I%{j~D@K*Th8}D{ev2xMYESg8_'
    '>Vd19ytGECT9d4l#mu_vYNk>*w`j$MvKl9et00r>dFjZo@tzxhNV0X#kuhvv2&KQ`IlAd*yiUL#50n~OOb%hS4l8<yoA!quyU&qh'
    'x4|pyWE3)kof}+w6*)B}s^cRzG97Lfs?bR%w#Ru!T&8bBlMd%8qp328Rwb3R`?pH6f1@<pVmOUJs>dj-I@V!`t8?wFfmd5K>XK{P'
    '(i{@RvW!#*sUa3oV!XZ#yhcknY901Io}wdby(HMMX#6b9(BWhi2T2h`a|s<Phy3)V#FE7$fkJfrESacHtk<Mu;~+iW4VC!1>!sS&'
    '7=pO~%1-eB&6TLkZHJXOF0T=CLBg+SV-%y}1y+YNsbULgL_4=l{?Ld*Z2t1-1M{<WGsYk)RWmSlV>3Bxb3+>&sy>6A&&*d`Dt1ZA'
    'R<kYL*zimY$m7BDvZfIgJl@oInStc3Mtzay$G_YD{y#KM7MoU;B~a~cz2SeOwX!n2-Vsw+>egekc&MUp-&8OR(MmoHHAdke&{e*{'
    '*7Gouy~qC#iCT)B'
)


def payload_files():
    raw = zlib.decompress(base64.b85decode(PAYLOAD_B85.encode("ascii")))
    if hashlib.sha256(raw).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("Installer payload checksum differs; no files changed")
    files = json.loads(raw)
    if set(files) != {'sim/run_battery_source_calibration.py', 'sim/battery_calibration_support.py'}:
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
                        dir=path.parent, prefix=".battery-calibration-", delete=False) as handle:
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
    print("Next: sudo -v, then python3 " + str(project / "sim/run_battery_source_calibration.py"))
    print("Installer only: no network changes yet. Run ONE calibration; do not start a comparison batch.")
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
