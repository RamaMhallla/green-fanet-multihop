"""Install ONE separate A/adaptive UDP event diagnostic.
Creates only two new sim files; no network or Windows settings are changed by
this installer. Existing source calibration and thresholds remain unchanged.
The separate runner starts bounded traffic, publishes private battery events,
temporarily downs both UAV1 links, then restores its owned network settings.
This is a descriptive diagnostic, not a calibrated performance comparison.
Run normally; after installation keep topology running, then sudo -v and:
python3 ~/green-fanet-multihop/sim/run_battery_udp_diagnostic.py
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

EXPECTED_SOURCES = {'core/model.py': '5a6f7815aa76e5562429317ae57490bc0e6949618942cdfb27839226f217c03a', 'core/lab_scenario.py': '2243a642809a7f1672ad5999246c5339501c28f248cffcc760374b092af6f458', 'core/state_store.py': '6adc5ab5e24f9767c1500ea4e35121cd9f3fab4715b2b91c2bbaaa0f9b2c1383', 'core/battery_policy.py': '299b9d00e107f4c035c9dd456337e0b85d5553d853765aaeaf8b0197cd757d10', 'core/battery_enforcement.py': '521758411144a09f7336f15a7849c3e08cbf6589161328670d8a1e396dd6354f', 'core/battery_live_support.py': '603dece9c7006440a386edbe431b12b1cfc880c2a2d8872e23e4359b0c2666dc', 'controller/battery_paths.py': '5b961e969de4b1147f8f4bf6a52b3905c6b2b8aaf715531a49a4e4757d830677', 'sim/battery_calibration_support.py': '7976e6140c91ddd6aef5e4bcad4d7d8b27a211803ed6f8ca4089fdc0173db5c0'}
PAYLOAD_SHA256 = 'd6bad024902fbdf49db8d8ebf630baa4913771026f635e0690505c3454b46ca2'
PAYLOAD_B85 = (
    'c-p;v3wPVLlJH-_^&WqRY9v}t({Afj?QtBX_13X{Z71EX?d73G%4S26Dj#-y6Yp>T<^g~J3CePB?sZQii3A3~0GJnM2A?*{WU+M>'
    'R#jZw2T>AUXL(sAv!JY(%e<)k<^9Hv*tnqoj<Q(nZiP{}tdiSUynB5t;@dc@L{smj$cyAU$--33!Zf)m!Yau#k(8p&W;bDW9Y_8}'
    'b`sZRT#7QUi&;FnuEQdVBdD;f>LT9C@3J@={gGdZn>by@MJd8864g!Iz~-7_RwU5xBm|I$xd`hjUqE{^QN&e|Km&OpX8B?n7D)-6'
    'Nb`K@3n(~C!(;&f!%6|Fl0}kTV>jo?N9rPv_#&GZ`9diC7(-GB63K!-zJe-Q6wjf-G>vCfK$r>AJdC_>xlEHd8UmgQc$F9T@U><*'
    'L#U8d1y(ACjLrat@L{lXkqP)~FmEEcDJP0LD@BsQaG>`%#G%OGb%D=9==to!b&=PEz#<M|XmVf(yvjesnV5*WP9h)wdEpKGoA~4T'
    '&i3<5E&|g~4h8%Z7XTE#&R{561z+S7sD6Gqr2juX;Qw52k!J~v6y7fD#S%W`g8&vml*aJjFwbHxJO4941TU5qtb&Pn6Q-qn6NOa>'
    'Pd;62l(U<75njMz+#Ui_mPKCWfNFeju_5PYR7cAZp=Q(|YjnGPv4K^}Dy-^~E5P@nf*FT5+>rXihT;qsOwI*&x$Yv5Vt$}jKR;Kq'
    '7!cfMPN9S0J<fe_bzjBwa{Kvs+-VGkF;7x1aC~y~X8&M%O11Mencd^lz1@TTS0}q?`$vbt@zKHl-tWU^z;cm6hp*B&!s2H|9d}wu'
    'lk7t<50eyjSEn!zIiG!qt6&+<041=<mu4ZFjV_jG-vlso`4WdrBRD;Jcd|DP-uyi{I>rvuP!gE-Bus;Nna^&pl-v#H7aQ`?We55!'
    'jl-;lZWKjc5NKRp7aP1ygGE?;pr^1du414F_<febDCm_pcyP>WzLYbFd#O#f#9dO|C}NNlMSNYSun4MqBqd=2^ysC?@(MPTA_1^c'
    '|DK;3<mF=H0Z9O@S|9^O{AUfjJ%Hl3v8Q%3{v~r`%lk0XsW(8%gYa=r?AU!T!laDFNu9yq<0&G<yVy8}<qwnuiKYf6;*SYFfmMjK'
    '%%D{l8w0az`FvKT9^gZ*)~~|ix-`28gRYAV2e*LT>cLc%b(HgxA7%WR-<BhSBp)B~=g~6G-lX~6_Sg8^Xyn*G{cZnj@0Z|k_wDpj'
    'JQHbBRvxvidq?wak%p?cH~KZtag_0_u5fuGg#%nvvt<M%hMUhynAo`BABeHMuK3680to=1qJ>|W4#a$UQ&&mq-`ym$8?R}jUAlKh'
    'PI$f}vww@EEMY2e(ZP5Pp!SF|ATDw&wWL+oWw)ctA_nG!<kmGE5$<6*Zfr@?t<0yku?gCYFduW6nM)fq(s5+d6Fud!v1i!WXe8f5'
    'y@6d38FWy^AFJM~SfX1`B3;7ui5!=>2R+$G@wNXwpa3~ILIE_*;(1z^KrW~zpsQ(H75a088`Du@-AOz{9%{-hau)-GCB$K`m{gcu'
    '+A^AMjT8CTInD1g=wd)nf(Dy_HTA<<5t1$77!+6Nu3FqbaTXVzEPak_qo@$s>yCH&5nv#(P_P7y`R7wX5)Cb!vU0(v(YzFCJg-2m'
    'tMVF{b7T!(OKKA()_I2Tqxi?@&nPKpBURY{gXrk6+k4|ra-M1i{U7}yH$lmt1Wt1MoBU4hjQAG6NanPEcs4zGv%5DP3@nmd<arfP'
    'eNS~~;9tiTwDKXzaB$*p6C^PCpLJX#D_Mg~pE5&1*kVzamAHz91OQ)Qrekxptwd-`Mncxzyi{Ay#EpTAFp5^90$*VtxeyCzM!8>h'
    '4__ZlSI)}C#{5sL@l{6zFwrc#Cr3U}zsoFK!gN*k3gJ=~4s=Dr;QI9z38Ji#J8qLG&Vxk^j3P)PiyHDn-4L@%priPBgbYNkG<q=6'
    'TLfA#2io*VYzf)kh+!~jzxs%*$iG7chDelWw%o;8f+F;>|I5+o+37j+iOcixrC-9BaE)#OH2B@ri(=f_OvTKa$XOn#2{g;Em+%pL'
    'y7h_vHZ(!w8{?<ZZxAL?rUb$P!-5_VVJAiI1|%-AS$4jAAiX0g2Yx=_2SkRxc|P98$Lh!Pfzn=_f1AQ{ch#I9BFi9VGGz+NxI!ve'
    'GDQZVl6#HfqBRVnE3oL&IAe+ayRJYF0}4=Q3Rq<_w1e-4B-sL=W;t{T&5OG*O<8nh0n-rYKw$zMCj;RWNeZmJ#j+$J(~=#+#X7Qs'
    '(%)csdtGvjKv)k&QMU+|N#q%_1H2t@A)@=ExVjl*Qx<Lp?gmRAwp|RQNj>N(=c8_V@0kk-q*z>^uX13wa;8c_#a`k|Ky55=N5(J3'
    'T^xRpGCk<@&%WaY^=|k5wvcKMJ%2ui7js;XR|pg~ZX7O3)dy6Khk`iz1j(yOcu0YsXax`O@Xh$CEE^3P6Y*d9m5F-Nz@?;iO|+%q'
    'wuo_9l0Hb&z~!0gju>4lnB;jQ<(aH;Bv;3X1Z6i{r}qh$Q^hUO3zRTI#h^1XJ<ssH^;Rx~^UlC<vq5o_W`z;xsz`Wo$@_W-(BQWX'
    'jDwh-#;lQn`m{n4>YJPP25G5l9bqfX?r~^7fSSc+=}_CKC7feuMXmkYFs<X#8;~5^8Pbn>!0XCuv=`9qrfe?}a5n6~RSY6P%)6r_'
    'gi^z08plh|-!|D|+al9uTck0;^1DV>1*%*IT_B+<&SrT86cZR=UCl?|+1yrJe#-hv;p>>HpEqh4Ev`zhwM$%+5h!aDv(o-?TkL>B'
    'pd^}wPS0K+y*q=Q1Wa_o7L9KAhOAna@T7>BX*eVK=Bl2T$v@)BcB_#%yPZVItn%{Ghwn*&`s=}7uzPR-0QO+CCY@sQ)=^z8>*^SO'
    'coG4_7J?1)pNU?!X^`lfT6mO9%C>o2BHJPhT#$xnQVm#IW!7cdK)RH4FVALmQ6QCsHMAq%AMNi=#kT)kyuDhML-Bt9_4G)*(7(}Q'
    'HA4H9kjAW+LTfr=+)pjP5IJOi_6Rv-Ts(msl1OZb1#8j7dX-WF@2?p6=Ji|Pn43nQ5mmwB3K{q1&{k6M=U8@1+E5VTkF->&o+?)4'
    'B-*Fl@l<)Khx5<VbZG=$gQl-o$*ZR}u$DQmZ=}F-*&~$BUV-<4)P<BVhgA^#4pk0|>symh<0uV@ip6o<iY-!Tn3G97mWnF1J6M~6'
    'ebZ)OxN-iaj0nfKwl!c^R7E(SgTRTkr8QBiLL@K&Mq)hpQGydpR*YifJSi3}byf8iI)^<j@;lrOIqH=#EfcZ}S12FD(kEe!OH_Fk'
    'rU46<G=o3N7b(is&GX(Zf@6moICfAc0_bsGM5Tv}F#tx!s0*u`!C<hGVLNbk1wcM@M))PUx)Z-rD_|Ux@d^67{Y|+xoA2c#IH!SZ'
    'D^No4I*jC%OL~6UHL8<Y4>~P1G7-*Z@v;gtw6TLEUY4+c;dL1=L!^o6{h*(ztlnBg!P>j4f2*{&i6m#e)4y_4HfM1jqI$?DCf&Ut'
    'r2*HDg`V_uR$4MWEH)J5!Bcv@Vxx0aY?q}FEwrJ!)PIKX<<~wgdpQoEII}p$gJ3-Br5T0qMV(PQYcKcCbU36FgF1Gl5<LZXVN!YW'
    '3}Lc89ym&ZxaUVOu*`G3WwFnv<?Nv3W>b9NGDAc0-zH+bw!PY**F1CbtU+<Tb;y7u`k=>WNqMuH0<7MJ-?evOr_2w13uGO(r)>p~'
    '@IGzqfGO5?h_yF|w2!p-Uj^6|hDnDG{?fQ|u)V&8+1s@qTa8~<`O@o}0@;G`i1l=i25hTqs@f{sX}4BX<V!r_|HLvB0XfI-mtq7s'
    '0MuzS)KLD0p-CerAaDV6>A^Cz<4khFAH<j{>uS`Ptu&ishP6s1aDo0{8<UM!>)7T0P8N7-7q#djF5~JknkV-UqmNDtu*D#X(<+q0'
    'CU>D-Lw1x;*R_ce%P!+c$utZH4TF6n9`%m6V}zt>45+73BQ$kD|4DYtOFi)cI*Wji)c7p4D#-Ux=b>#eSF7vG8_cO|z4mfy*EBv{'
    'f!d8OBmA1CxU_BSL)W`D965K&dBHp}FlStDi$$pS#NtYRHLbIYu)7Cnnd?2kzi<z%(Qv<<;#%zQ5d@F<uPu2Hq~&NIo~q;%0w!H0'
    'zD@i|?#1<^z6NCtYFu&ONbbsvNZ6G!eB00n5(7IVp$hPrDxh>&6Cj@ic61en-08P+9gyuJx#F+qqiy7@@FP%r*Lp#MaUcnqHY$(A'
    '_PR_8o!BG;63aBq&|yx);kJatAmO1g<U2KUo?*Fgi9D%!Kq{cV4-HK0m?L^<J1Vf6uvzM=J7UxSdQNtwm&z?dY(`s~pf*HF2}8IC'
    'Ui(LaUQJwdQKBiurRRCfY!qmuOG#xLT8wus#nF1#);8Ui7o!4qFjz=aid#{UR9||VAwDlQ3~51nx_m@cNW2QmcuHS!;zD#jsIPBK'
    'e+A_d!!I6bhGjtWd`uQ2C|s(#U&bCo8~8zh$P5Cqxa>4X{_?$a&qE5FntnLs=g2-<UK(D-=@4`~vPQKQu<gF1MG-37(W4k8tI^Ru'
    '!D~5+T`H3m^{Qu7D`c_)JtsjY^?Kz-HEex)$l$fm#*5RE;oQoHZpvk&QLQLBen=913s|F5u5cg2sls}JEb6%gVW)QL0M;_``>+`n'
    'Xh-cx?5pR$4aQQmzU~1fmxp2bKjRwHk4tpCTBDs036AaMdhIq7EmdUMESpvvgxV8Arvd%5(E+L!3YogKHtC#Xbx!jH=p?MQ&mnwJ'
    '?JWBQG+}y|w1BeI6iC=WKtO8r`nF#$4y6T%y+qP*aTSHgSOAfD{?1}1d*5hDaNyuoK1eOFqQg3^ypCjz&c}mu?V=M%@KT{&*==O='
    '_CPK4^wryOa?>?wa#s_Nvz5yCKVzMSK`<wAuO1dMm`h~#pqtVBt;NYY_1)HqE#=p*oc85PV#K@zT39Y&Fv2|w*?;Mg`UyKg{`KTm'
    'VR&>K{aWFe-PV*=`%ypUI^Bkb-9~o^>1ga8(1QvTC}KQgGGZ=_rEfX^ON#^=N?~E6^)#%b1PBs{A5B<AJ0@aCwql@cA|y}cWe6nG'
    'bpCJF&_o=A^lLQF1)wg;<k)W?&;LrVweS{Umds(7sktIA4pz_9?v)<={V;l_-2n>Lq(^;{etAs{fb`9KGz_3+XeopVPOYXvXQ8)C'
    'w&}p21D8g!4p^gL2kM}+!QP|ZXIOC+td1u;aFk@8pnJI7Y)Pq1Y>mMR@oBXG1<+|g>)Bb_T8A5`RmHv6tQsp3-5<rEVHlw$ZXhb~'
    'f>6+ny=a%#;Tu$*JleH~$;xKz=n$%nr@yUYCKaPHFUG5&a+Hdky(UnljVB%8B1`T%W)k?U*V-J{aVdE$)%&E46iji^2aCTcj`#4$'
    '0)E{rT8T)Mte_oiy)pi2iUzBEK97wJr@X?3;?Fuvlj?p5^IX<387v<-9_d`_>=ZhXMaw*4TjL6cIWm$AHS}{;?UL*hFl!x;W*}sq'
    '298RHkIsDnb+s$A^Ut;#CQDLU<wM)^(w4U*3asAB&<J9bEy8Q}cO*+nXCD{!)uAhBto_@h+g{^PNm2~p+g0R4Tx4+?Nb_e`hT;iS'
    'YMj-{9W^Dg6N{u=gw^bZ!u;eLX%p2_LkW`N7YQJ1Ph{ggDo2Tc^fCll4lQ>X&L9m4-|{yOMWeG*3SoM1fL4O-BT-=J*OC_tJWvgq'
    'KqM8J*dM+ngzW=Oc90T?Q4^$P?)`32*UIiUjqf~aJ70kUDckS#S<_ur?N~3^G(bT(WVIWv+NLofETSe<m7+z%x(rj$rOHykGAWX)'
    'njMEgszP70xVXN@B?$6d41K&xa0zgXsjvNYVUBKcvQ2(cF6seO%$=tn(08c{kb5*>YmhX3=MC9LX#9@0DZ3Le9a#%5vF0eh%ld#T'
    'nvdUg;lS_>QAWaiJ_qVfMp_StiX98nG{~f(R6f&(hWvuhz40A|wK6ib8T`@&9h6HVUJGmkn)v9+CI<*T$@I?wP{Hl^TdsSTWYFUP'
    'AX2PA2h<M}@eTQ@(1AQ}X@kVzC>R2(Za{0$&088%X@JmlT?Wm#G;Bg?t37ijfKinw$6z_Ln|7I5cpIZ%C9eA4s8mU7`Pp+(<>J}5'
    'z*Av1BIN*0j`zlSCXl6?jIxbaI-O&RQ=lqk%o?enVWCwnLo~!6XK5YLrYi1bi7@)3E~^FXGTb{@CIr=vO{}97N~QwiyntwvQ#(o4'
    'Sv<N6?_r;&;eE4X9zS4U!x+T{IF1-h*FovbXB?##GhnJ^)r2RNI;sK-Uk=UZ95X@B4S^=V!=Ms!Vv!aMkHL0r>gUE0!VrYGVULTT'
    'X(>#KvKq=+!_!_M#Q+|Uh9YTx#z!!Q=8+lkLMC<~Pamryq{Cul2p&NlF;IlSPx<$VUYaMyi>u_i&THC8Qn2DPm2(GwBaTna^~gLZ'
    'g;H-3LDvQGKQbzyWkz;sMO8QXKkqy3y!`8+TF0O!UU~mvK>Pxa0-``Z&;q9=E1A2sCFbDjmX`B2Rg<UY4tplKN5V!0*$DOWF8O>W'
    'o(JRcSp7eA7WvjJ(rp9}tx{k`xHr7jd}LW)fy#p{Dy02ow}c^zWQC_AG>hknxTA)3Cu(gjBSXMfHgB@Wby|Olw~W>9z-e9QDf_WO'
    'ZjZIPwXDu*1Z+oSqAqeEwrRL5$w?~1=vS6$c=N?b;g=y0Hs#7GZ3J|*>uwX{et<VQFfz+;n7Do_<3DN1!YAoyXynd>NsrXBCA{N0'
    'MV84Wf8gOibQ@5z2gM33Ja;{AShZ;qyyhId3%Y~BPnt#R$=VU;=9an~T5_lInn3cznCMgIkV6DvfiX$?I59{vIg7;K<v@D@$Y!~n'
    '0EQQYR~X73gjH}&qPbEx$Vj}SNVlA#kx(@Kkp`6Eff<f9IPn#mAifgcfn@X|{&v05+VJ#@wt+oZoU;{QSZ4{)Z-u%Ec8ZzNP(WLb'
    'w<|}hRA)dUh$&jYWmHZyYXr!yB3yeyoXibhLTGBqKsZ=JGnlf;HjNv*DNCZH*^G(KTkspvA+p4~+mT>VFeHQT<YHt0aPR1F@8I3('
    '{`)BqGIS-;Oq!rwZ0sGqJwBM8O@qDN<Fj`s(_r`A>;1F7umbIG!Pe-BTX<=_0ea5J0hefFz-aPWIboH>c!FXI$~{aSn)wqyPQ>%a'
    '&|v6qiY`w2`0%9ldtm0Ykb=5az8i-JSdm;1#)yGG%7+BwmG}vA6vLs!0j#Z!s8y&8Qt0zTKkRG=_4W=L;^uTTQ?d^b*BP`F3<=Qa'
    '5JlB?mxSFid4IGEWqPD*7^vjJdb7KKzzsCt8#t=e@$TuVw!f@%V#NzjpIPy6WqsvIa&eJyV7b^k**}|}?C%OsE9oF9>3S|S4H|ty'
    'dXDtZVOREQoLQ7RoIt0QpHJySKG}Z_dKJ-Yj5D?0QJg~pjbDReC0$!yicP0`i>Eu-48*2>?7~9tJCxD6J8`#J@Z4mPG>T4Tt75aA'
    'S>^%NI$6|<Kn+lFs3?GuvX6}FsxcWYX9y_+^LC|Kp$d*Y@17oWii9vHsqr_0`H<|YG#|?p6q18Frm)um$?EiZ4{yCR3iL9}9&(D4'
    ')`q^WXaFc~?H-QnV+TOC--)YxL8d-?>#Vd1UbdjV+kMZ8Ezp!F*pz33>oxbaAQ|TXd6wS$LZ;1-M?rXUwFqHpsNXM9_61@?M~hKT'
    'CK-&6CuL++iY8wZCe`$5c#94X8|~Q4KKf*zM)OE7GN?{z^okmk5qa)~E{6@2r>4;xcC$?x#$Ibk*{^ZDByFI|mpSOI_ZTygVN59='
    '$O9m#l&1I6@PnCy#ORhRo61hagtP=$$1<*7jzWAt-V~!B#WsJ8H(zof7)92j0>(C`<;{JW%&3tlAzM|1wz7*%d0_ZLXPU9I>mdGA'
    'dO!Gelcy1bRB5-Yw1MjM`XZA__rl_u%v1WoEMMO1A1Gm>l?ffmqDnuW&$24jziz_v2707_(>$vmc_|YBqIW2iQpx`CxLg-1n&!*o'
    '8Xf5MPdbroerngH=FxrgouXXS4@|~~13f-D`mgEUS#WZ6bf(Vf1M)El0z9QD^AzJHd_V)*-1y@n1GwbT>L(dc`N|t}IH(B?sl*z^'
    'Xgk2-=AdUn23d8l6)rG#Yk|>R;#j{gVjpN^piUZ9(bKctv+1c>it;xEv`AE;61F7qn%FF;wiO?V=(f`^3zjMu+K_+KBp^L>)sHiZ'
    'eMJMM0^;$W-a9(_b$>dPpTXPR(_e?;=Xbj&uY=>0{UeY&ejkdrAXuLSuXazN;M?8*4yMOPd%r-P1CV-xxBG`jCz7Be>Qv$!8FHZl'
    'Q-|8`sd+L>!?IL-Tsf#GFrr%=5!reNuHj&`Ogj^$ggVspKnHu!IVmXnctS-kY)!V2R-(&pBG3kUJH6$w>&Y@SJeY75D~A_yK=4rX'
    'PxuIB0h=Mb)>+o1L$xlj+QUdyZdx$pO<dMPcB@y=X{8$x1mu%~r=BG{;}1dph){uhKE%M){4U7CY{JoebO3pAk@aRjP+j0WY#t|E'
    '1Nv0sQq%sO>m=5DJd>M>lSXS^(?rt;XM(?{cjSo~{@j{GZ`wcEAEVnONY2Aq+=zIxo97+~5EuYSA9e<SxVq5}zBqp$+twfyGpQaO'
    'BlxdRjt-}%tZ-p*as~jxw~dOM>dG8vpXr=*!SHa&=x(ve*Yqu*s5nf+3dK0L5<V&0nIA7U*!dYVQK;ZfM>t&9CMTorkY?6bUV)48'
    '%KK?Yd5C<@6!m~_WVrsEM8G6qe|)|PiwM6ACg=Y<6qnD2KV4juU-4v;J0^f0Smqgh{tlhI*zo_zlgz_XGHH~SFy-_}TU5acx5A+!'
    'Vx^5bStYK#MYx0+tB`*9bC?SZ7UzLcRTv%A9#Ch`cP5wk>0Mkz&j#3Of;s3k*FR_fA&%akis%0Jf3oxkLNL-^L9u*<Z5B#s+I+DO'
    'qzvQ!Zcr9kf@JeCK@o&JVv)9$JQ+s6{}(&h+jHzVjLiS)C-0|8f6>nu7yqNjN0@mlKI6w}%MlVyzaE}hdkvncV}KNLc~|pB5B0>+'
    'TBS!6r$-}s=*(HRtSbw7>}SEtFAj^@jhrZHqDnH3rdlyos`tzS7@pyaifi$$j0<5+r3IS8sOW{MhuTO%nVuk@Z(kZKgHA02+77s{'
    '?e+NY*t<(qkI^Z>fk63c(x9uo9VN;%5Hs8rC1)J9dWi!UKeWY`E@d`SKO#y5rQ;4MDvYeRy0IT8+ux5dHJQlb>Mk!nNM!+5L}bTg'
    'tA1kN+M|S3PUx4u_DqrFkHJI_dUZ!*^z&Ce)`!qnq$gH4^BUC;r8ZbStHNss=A$$~;p%b3V|A4?fU>n#;_LBvjOP@HdU(xPpNOx&'
    '|MvO1$Y#Q#(XG<?zCYMK1X%|#Y)KWs+!7GFuEH|LUV2KRGgq->k-$|c_c@-=$Wmy~4R3oaD9i{Y=henB38ly4f*CO#1dtr~L7u)i'
    'eKwFEWDp=T2E9}vSpM6AGydC?tb`gMuYCF799Yp!CG+f%$#jUuPgs=kLOvYpr?a#SXEL|c9RBddW#7?=9=r50tAVmEc`~TWn3WS$'
    '5|Q*}<}|xc);1d{B-)Dx5A-`W5JAJ-UbA<6o-bjDySz?S0x;2pJG43{MF-*-^xdR+t;w;-A7`1(S{7@bWx~9$Q(>8yKrFzPByx;+'
    'Fl)h73D#7__RjWL@Nx6@cnoxc-9W@S>`MRg89d0!&vp5EQGNzlQ4218<l>PD<>qC^@-?wX_AAbDh)Z6|_j0r0fv^<NRnACf@>yep'
    'q4RISIjiJSzU)CEQBtFIAF0678w`6^1zF=%Px}X_XbSm=-v@Nt0=rL`a<_7veCQCErtu_m$?W8eO6zGAy4FeAtAU#sQfq$=*i`f>'
    'u>VEVY#0MB9Sp|eOp=HKtrPzlk71)wV%`g)e2i5|HoB{TW>O{_W>Lz{AdDV#Nrs8((4q)BdYq)ghSj4U<RKl!rnddB<v(Mlsn6;0'
    '*Z#Ld@xp(B>JmNvnjZVx{QvV#M7mROlr&L~k@Pp}8hlEL;T&Y-?D8vOAacrAG7g7C*~X8GJ604~HR{k8Kg9RwJ0;16#Ei<@hM$tr'
    '00yap@aasy!(shh;e#57MtHmiuQbHh?olm|RHh1ONrB;2=_%_D7Xc`g*qQT^i;*4=N{HL>=$jSJ>21{A!9KVaMz1ldAnV7Wb7@O)'
    '*Gw$VOK+g3-9o{zryHtThg4fuG*7RZb_Z4G6j>$x0%mhgb_K-Mj}!5NuzImU3l#SRt^!3Lj91U?R}P%E2SNQx=E;opO$F1nW#v&y'
    'L#x=2MRDsLO%V*SVyD?IidxZA`Srnhf}ss)AW8=^QMM<I)%LYD`HT!V&F;YPQnYm`WA9Mth}yB*606e&scRatrzQ?+R3le{FC72L'
    'eJvCDG;xN;<r^IBU>I5Q>uws<PI)6ZqMKE;M<c@1e^8%@mS8JLWYlj=#DDna=wxsDc6xXw@N9kh+P1aH&`f%ERzO4Oqlm(nQ{C8W'
    'l1Q^@md;}s##(qlODQrz3lDNx$dfQT>KQGoF)BG-U4i{%jrcz*?2a$dx%epqM|_*;dlDvk<=Jm``spM?;g~3bfM1PVgH0S1z18ct'
    'pDJ3IMQB_4gaf7{%kR=Sy5_S56`RtbQP#S(jw@t`@u3PyZWYi3d}SYZd7h~9mhzyMp;Lma{HS|s=Em(gd&wk1`Ns6+w(3t%qLLOi'
    '>Mb^=au{y<<9XS?9L1(03|*O(%(HT6&fB%<gkG&gI>5Fr08mHTQnpRmoU3vd;gP_I9%{Uh<*8GKpXx$(d{vWyf?>%NMph0Zdhu9o'
    'ZpBrd-^luOc(2sFR{oo2<Z^XcdT6udr0YDp%#zzcg8_<*P_{;oFgP&mp+?Fj(*i5INRdPfJkUaubITZbvGIYNA+$wO@>iKX%6`n|'
    'OvSP>naKn>HmcC}5@r}w0KE^|aN3dyib+j+D!MVvBb1)Y+*K4&D!n$)yKy`o4{X7O&99xP@TuBqJVQ9vE%KRADVYp>b)*2K-X&e&'
    'Ku2t7GB^C0)|y^}M3!;NU73jUjwOIssj2_>=-2apD<&o|W@NOCY3-S5LrAiK{0|%15C^VeG9;e8pLT|y#o#Z1&+dXMFU|QSFQam{'
    '<k@`D)52w!o3s03DkW($-59oO_Q*oK-i5^7uR+8rwah2InW-PvmK$_VdQ=<M-5dzzI-?1+%}ga-#1N;^jyL{zJ|2A^j^?|gH<!;o'
    'lX-LWBON5e3j7RwD^Ne&g;&@@$%zqm9{aD7LpUDRQfAWsC&nM=^EskKo?6>z9tx9axDxl;F)z5V<#63%&VCoUQ685vCl_MR=5%CR'
    ')t4`|um9<zf9^z;D#hK7mC;U}2n<zqy#RE_iWvAXC2>e#W3$RmkgOh|Gv(tA8)p#IBIR>$%w6d{dbfyBG}OkCPeX@%(wCv=UXO#C'
    'bJV<O=-`g%rI5y%l5%5K87CjNF_{Oo<`Ilmq$WKF!B$QJc`ezOw-QOMj363G0B!A)&+l0EG<;9l$^qjuTt-@XGJ8}rDf(1Jn3d!l'
    ';enW>_LP!zZYhzj`(zr5uRPp3+lSu#ESOQcQna=OdE-RbsEwwft^tF$m<%YEOOB|gbVKZhA<<COIW*Lj0Cf%&?V(L2TmIQx+YJ3D'
    '2Rl}_=-#Wt-GkuO?#api^dvZ$9v}S9^G>_g`2sgr@b38a?%6bWHT`-2ke|b#Po^-FtttbDnyR`kr5EZ_F9&JnnFGZ53PGx3OHUdq'
    'c{8jS9xBnD!p`xw=FU~kfek18KJ;{?r1yCOlgeQsc-7&IGC?;w1Pf36zD>n=wvAJ4O319eeu|R9<&?9azbl<jj_Hl3eU0;M5(Gdl'
    'f?!})^}{F%l*0;MI;S%&(&07=nB>JE^HNP-j322UW?_2&k6716r#@K)ufxP(R<21OSXawp81Ml<eF>r`n^QOIS~u5_2?kX6B}h#*'
    'V#9DM?AY`O*+$5qOv&aQos!x&G}3zvEroC>evR+tw=)<reI20BAlW2({JHlGS5fL|iT5*`X|9p)5(G@f2+t?z(8yQBxI4dXqfw{K'
    'q|_>=*FR4{Y~BlL<k(@h3ad1Vf$A5WFr6XgbAY6Rt@T2s))vYq4Em_-29wT}!a5rZbTTiIV#YOyQbZ_LbP-*Bp;z~LT}YQ-JZCO!'
    'uiqwfN@K?`Z(DWT%`A1h<^i7<HRnDCx1nfE=Npb%ybsik0QM!%Mk1=F9bU4|+#NkPIUDyh8~C<wbhfbnc<zWtZ#yS<Mcdz;63tLj'
    'h-H!Ib7$_5zi@r^Q?7ho=hA08Lz=Z6T**#)Ze*4hu}Ozr3I4%#ckkLhk4ZMqjmyUt>b9s)pZrtGmH3`T_=ks<-oz`l>%GhxHhSkH'
    'LE^6ZRgr|L&$sdE%dJBDzziM5{W+HL@SmZ4a&WZwYcTz9@!9-+_{s_sr`x1a67>1QBWj1=Tg0v;?<|lQ;WJ-Wo~(6xbP${Z-09g+'
    '=tsak-<?i(U%x&<A<F>=)ac0bj{Uu(!?Tm4g9Bi=`^R|ovhm>f=;X{K?Ztg99n1Zjd;w&ia0XA~>~;$PZo$_P%v^Yl6XZC(ys!PF'
    'B$sq=U<xw-x77#4p;#XK?{?n@uYL>OzB)cdQuhs+x{>bkb*VZP1Yi-=8$3V3#1`LBFb@VKl%2!QweMA?(*vScYcJ9&U%GEt9>ucO'
    '5_BfqRgawSJ3OW6x~k7IBh%+429QdlitcKEoUe8@s_g8G<UeQhRbJtXZs1B2<yx>USP{3cUX`9lc!JY*E4S__XgMmWFXq&sovC}p'
    's>A9^WTWl8XI3Ay($M#TZ5e9YlVG?|T42zofsU%=kL6ju|N1-NQ3nFx9Z!RvGnwYbb~gJFOu7aqrCa+bO?hb_AkE{DZ@p~i)mJZ^'
    'BjSqz<f){Bz}C>l&f0omm|E2v=O|7&cS{<g11!6+$!pKC%`LKR5-erh43{z?lGRlr!Mxv=_kI+|OZ?(-d`PF<IR%?-s~oAwT7!AP'
    'zL*>a>wiBs%><N{PE1<iA>Q#&0&EFkE;|=m)kwPxBaSF;DVVYm%g{>HZ(p{q+*Cq&g%ib1HNbjoYigv8XBM88t<|>MLdKn;W0%em'
    'kWLb*rO{p68tv?+(K?lt_OefHg${FV=x8_{-Gw58|9ni23Fzn*+`!@oF=?SqO8)k^qa5C%a@ff=u<bt|>X#@YMs<qUJk${g%|@xO'
    'yYR@6)rR*%!lReyyw(pCU0~cmqxiZAL3OpvWaKuZdP)v%8X)&^Jod-E0K3J%f#MGc@tAV|Q@TdF!B|dmGspAfBRVpgEVR87>H5m3'
    '@>RH;pXGO6L>E)W|3E8SUCjpQdp5@>7z+LS=3+BC+x%to?dIwK*f&O)Ic3{&m<;#ZGR56S&_(jIB|PpB8T5!(+3Hg3`9d)=euhDF'
    'KK}Cp)YzN&<N40^^GjFn{KW_O?y-kf+0Njv^v@ISuN@xRll8wh(p_;&b@8`~b9XVuCLWq>m(uNs7@l=+_|W2^?25#Ut5wYAW=%QG'
    'Kr}r0yW_-UjfPKE%@at&wZGBXjF9o0@cB32T34mWcuSvOd2MN(?x<kz0E%Mq1~ijVavhhI=kU}rF2KgfxGg(S&|lt5Bd__+2m&+;'
    'D2=!Q0i?I&0xPm4Ts$87D~-!gtUtcaS<DEQ?Ua*R4ToRSQ}d#wW+qtU4r(-eU#_#$lQL(uYpvYltrXBI7_hahpWr&`vN0$#u-As;'
    'iuKa5W!Q)vdg&PsnyhiWo*wM}9=ttuIq%sg2WFt%qgY{g+EJ1L`e98)8aqy>TL<kSbLbWuJ-L|Bz|iv!6ZFN&^-YDUkBIq@$v{}|'
    'J&GK0OR7}c!AI)yBUX^xZa&KY29G9nh_2Uw8#)X%jib(v7%R(-yjqIBJq-0hkI~1z3#q%FSk0x>=HXd(OJi$Y;QVIyaC#Q}Hr@aE'
    'm$TsQ(d+5NuoCgh)4l28?#ceqWVM-y{$vdlSp&>Wh*@t8bPN>C-Q(kf{pstb%qp*{!OFJY9{oBE&fuTJNt@LH9)Cak<>>I;;j4FV'
    '-b_!XuP5?4VC&xM271>bXXn?pEQH;Qyy+1AzLxh1=kw)=FJT{HVo7YaZG>nGH(UvnTvd^CG|B+<j=`cQFnuM}9<;M-%<iIz31Ub$'
    'eZ&9y@^N)jci%PR12=``1a++&vgFLdQ_HKe>2i-_r4+D-y+&gPxoEV@-PgOvXZ!D`S`8xEU!SAwQ0|7w_v6h?d3HF#Ts0`|3Nud#'
    '2)JZf@yQXZ>p9g!U6hq(vbLv|kwttZa?g!|(hXLEBlD$#taGxf6s$X{PY<T0@Gj_4LHY5(Rdx+EbbD-7bgG~YKxyq?Tm58JT`Gw3'
    '?7vq@Ok2T5ZUyl-P}17&d5gNNSW{)CmEGgiWfI)H%aG#mJ8O615l=Hp{4+D1KGgx`>!aTee?HlLO@6UX!$hOPQvc(Rupnkhg(*pZ'
    '*^*8s8jm*nDyz<wu`0P^TPn!%EX_eE)4R2uH$S<CQBR(p(Yc%PxOF!crhFt?;@PgzP}oD?er}pm8h_uLYLwFq>!j6E!BCm|zXKf<'
    '*DxyzD%a*vJRj4G@u27GDE3vPj9ML%h=(Dv??1@qcb=Mt(lphnnZdoYC+`hb&(vM5C>zO3@pK{^J|cc;9^xgLx<A9|{z|9reOK`q'
    '($sa_oKc~zAmY0u1G4G`Ms{Z+PIkuB9cpE@cF|-Rlyy^}9T_DZCa)cd-H~kN!70Zo$;~Eq>cybHPRkGbS;x(?Ragmlmyc6Re(1od'
    'Te@r*q(fq~=EKNL`^b$-dhOLk!3cU9s|Nbk&!(F|i0@YPv@aL?dQ0!z;DS_z2eJY&Hg~-2;nWh2!>4)$1(=xEUG?m8)sJrW-bV-A'
    '3078TJK^m%I)9B>FIGRdyC*&NnzhcVm4?}9maD3gUZ@s0Ih7^yI0(lj_4v5zj}7Eh`j<V8aAqyb*J@Rpqdz)rlONmVpa;GwW&p(F'
    'Mx1amaq5lc+{xVF-3_`hJ98RdugJW;Y8qR!L23mh8B?jnRPs02pry(Yq^=eith?0A>j)lQZVnMt=Mttzy_Zt5IAN*<U09BU#edzx'
    '@+B^ab2;FUs<0VtZoV{B1rnkro8@Nj1+8Q^lp+Q>$`2J?vJ{B6aClBv;~D~BKVQU?%XT6<6cIT+se>A+?4*<-z^S=>2}z3*`?4&u'
    'A})ze6gvxIz=tT0-l?=Q^apQTAj=T>sW5Dj&j|ZkJesw{rj|h5+^<LSLOa`+Q;D;^M})~Y8`;`C)cyDITb*>QvjP#}PCc_paNqD&'
    'bLG19k9SRy0S-4(xAI-Z)m<EC0)dhS$1_O+s(pU@m@$#W%8@+QU)!LlN7&4(q<+osZeiDzKdu|Vd8~;}0rg30tuDOT`IFmt*XffV'
    'I(G=OANSff%iAGJZ60WcS=m?3Q;pGPWZpS1Hl>U8s&fxQhnYXmVYpWb^vuiWT~3;P*e8=4cjdBuzkRDaPYz=>ji=ZG-DmLyrqZ#p'
    '8o%a1y6y79YDTxS+ST1&cii2cgO4>X;P&)&)8wOim4`*Nk8(&+FDs{qYEJ{*YhHE1_T}5`vD$n0HoxxL_>45U28~7so~6uT+iB6k'
    '>sDOm{ja^s+vVwN6R0QM<;_^K@`B(Ha9Z-EjH@}hug&X*TPZIMcGJ4!j;+A0zM7XOo8$ctaS|``+gPCI?R5?7XR8TFDizb^3@qqj'
    'm8X%;rKOJTeXIGFY2J0oGdlUixSr)mrQcLDR_*>2rz8Cmw?Y0Pi6`Tan;*CEAEIxbBlT&AZgK)o94Hee_YE~mOld`oy>Y2>dty06'
    'FHTSr8SF%X`%7+EeOIg)m{GlPv5_Pi4A#JW1H!`2peMnWb@O{$>*<+knZ1YCzM)3)T+<2oL_c<p`mbrM9I*r%_0o~J-F2d?2i88n'
    '9qhOk6OD?GS0`<7&466<_*iJylamVd#kLyRc($!nJWYDWzI7%e4uC$qp<qdwAwtQ2k}fR54@eY3DKGjf(iyCqCCKR7N@d}wNf)Gq'
    'RlGr{ApY<Y0~Ps3xGE=#MADB)DyP2PId^ZTIDXp6`+BGEu06t@PVJo{-`Z5Z5s%zaG-{zrX+*78SAQS({?VDxmE7*|qIKYvqc<LP'
    'l64BV%5z9J%^3ttF_yruNKoNOgUeM=cXGUJxh3JbWPF?8<usJ|&<=H1{)jwA$^BR6%Wx$a=;1Du@1r*#f$rj}{h|Briql`O^J;bS'
    '5|YbMhmP3`%MmcyD;cd6qqJ-ou!JfH8|Y59EmADSuC{=gqO|NySK_rQDf7ZV>v{AAY-3u2-rxQC@aXhxe-A{RgM;ZF-luCz&U&am'
    'T?yu`G8Z+6?|f+jomMnA7of~5FG+kUoG~caX>HJqBTQ4&@3>>+M}N}7P`x}-BJmdO(k+?Ngr%0~B}noptRqLD1dL2b?M1IC$;wVT'
    'V%M#xK6xX(+|+cZE)aIg_HNEZXKZWC#9pHpHTT|8$ViNSaxgojrOPW~c*J<226{?{CEi^_5nO1dk@m|nyk!BsZ^U%nT_>uCla!dM'
    'g1MiK{nXM;9|_`=0rTBxPQ5DzJ-g9$c~t+ENj*Rwzi;}|j_msa`}f}%V=5yKnXbLmn^*7Xe=_J)#m}y}6xd|F%~8!zMVkw#U=U!C'
    'a}ekygPp)kXC4PXLr*py{y)2E#is'
)


def payload_files():
    raw = zlib.decompress(base64.b85decode(PAYLOAD_B85.encode("ascii")))
    if hashlib.sha256(raw).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("Installer payload checksum differs; no files changed")
    files = json.loads(raw)
    if set(files) != {'sim/run_battery_udp_diagnostic.py', 'sim/battery_diagnostic_support.py'}:
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
                        dir=path.parent, prefix=".battery-diagnostic-", delete=False) as handle:
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
    print("Next: sudo -v, then python3 " + str(project / "sim/run_battery_udp_diagnostic.py"))
    print("Installer only. Run ONE diagnostic; retain source failures; no comparison batch.")
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
