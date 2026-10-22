"""Install the separate OFFLINE battery-protection planner and scenario check.

Run normally, without sudo. No running network, Ryu, Docker or tc changes.
Existing project/model/controller/topology files are not replaced. The two new
files are source guarded; conflicting destinations are left untouched.

After installation:
    python3 ~/green-fanet-multihop/sim/check_battery_policy.py
This checks the model only. It does not activate meters, queues or UAV failure.
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

EXPECTED_SOURCES = {'core/model.py': '5a6f7815aa76e5562429317ae57490bc0e6949618942cdfb27839226f217c03a', 'core/lab_scenario.py': '2243a642809a7f1672ad5999246c5339501c28f248cffcc760374b092af6f458'}
PAYLOAD_SHA256 = 'f15380d5f01832018640adc5522d036afc64354623f7744f8aeb6ec449a9769f'
PAYLOAD_B85 = (
    'c-pl*i*nmWlD{&mE!BY+3X&W<RV#<7qa@1FMwS#wb~Y!nP#`cQ5rY7Ohh#eIf4_dr3<eL9^3`2Zm5{_tPj^qhyP?1Kf;5wdQ@<!='
    'w)R$O90hB4wca}sdt>_dW;TnXME1oj&7S=%JV=vxE&Om9<$07Qg16vPQ7oiTkPcQ^TF9Wl74q{+X3<h6g*#5h$#q&RqGT?j1U5vu'
    'Sf*haOZb`>ejMjw7N^g7Uo0iSf&c$m%2MV6zylhe#LSQ4GLyM0E(;Om<K)e|1K7HXG8u~4pH`UlMUoc67jNF3;cj2dOF#3ILQ0X&'
    '0KA`<xaZgO-W3mkIUHX^!8n=vxkQS^vdjxH%cT4wiM0FS`w^fS6_Fo{RqQ8kMO5%AJShO|nIe3a$V{X_ZC*}u2{a^yW{r?f@C^vK'
    'lR;Jjv}Atx?zbBtMx<qtN1;?u_%48Dd=mg{mZeJ(`h_3Fex3tYqU9>hfXF<If}&qN8Yk+>(k~WfCtkG+?3S_Kc%5DVAEIe2Z((5{'
    'nCGvG=t+9dGMX<6V1MAR{2(gU-Ykj%dl`Co4e(&5HhL@CS^7_2kmdy*HctM_VB)~ZUt}_P$V%B8C-j@RHNtV0CbMXMGEM~i^DO;O'
    'o)*Po0k^zJ<M0F}!Y{-?9J#NKcx5JIf9)-#A7*K~^p?|AZZA7l%bwCGKm^zDBy6lYHo$mQ9xNmZV&+ZDa4w71^6&L>xS@0d(AO1E'
    'S~V-<co*c??(5o~P|h<y1V#hv8%w`;f2iRc5*svB8{4BJw*hq1$~Ux<*M@Q?p8Pn1+mjAx!K|llh5-37D&jy%8$YieM>F9kYbVM{'
    'k&{3=w4pDiX&U!X15ruZkDVw1$t84p7C7~f+J<86M)?f2PwniH$)S&EN*Ftr|L62<#7SWMD3{_RJ{@IQnmOaWTQ*#|EKmh=R^+J^'
    'e27TO<rECic&|<)Vsj*Z90(-e?Uq=4e7qZhQ)LgTeHw-52u-ATJnD<%NfQG)xI+QNkK$<ep?A1Z=#A#YBn68#_fhwo=i#j~n}Mt&'
    ';(FpQ;pUpW2d*uF^{qQZuE7Sr|3m;1-E150^~HFvgEGMA1^0OeLYo7&p&(%wEbP_2uF^c}qL28w#RdRhttB<R--**l+#?KFg%cRn'
    '1epOyO(l3cFlXQ)@&de(0uQi?4T$crD+b%PmD-8z1wdtc@&ABw%dCl?1}`INH{$0Cwn83GFt^UwqWhk0rjF3Yf6qr3!w**v-r3Fd'
    '#pOG&bxlu&;(dO1b3M9;hkuRtJ`6t|v)sa`SLW0A=F{u(-dBc=#x)OQ;%8CHPSjaJK(Yj1s(;o}&L001+;IpJE#h<@L3AO?<AVbP'
    'E+ioRRt!anF#yt*X3;!KV2NG|{8%kqZP(A(iAS(HlS?0zuuOu5pUh?Gic`TKG2+O{rHe(nf?%OcFaXF?D}c)x9x*pamw>+%7nlDU'
    'ogWU*hqn)xA4l4DNk3Q^x;PYDfg=E<QA1AwkGzZ_3Sxi|f5Dw<<cT>VOgXH|BnXyRE!Mg95R4FGP2^`~l3+*)@t<pRkUvKi-z^(7'
    '<SRObySD_aL%8nsUM*5XJpI&&x{8N#DHD*1#|eHcv>Ak$FntEW90(;f|3;}PmCVd@k`7!r(*Z7E$711L-MqUz8(w)=m)F1CpR~M?'
    '<w|iQc+#R=#bB4?C<j+c5wlF_Sx@|JAYSd(qY+-3eG5$U!hez=1b$FJ<X=34KqTQRjZhqHeV;{HULf^BnjpmppoTRq&{v>218Axp'
    '?FYPJFi<OY6YwEHSq;!EB@pK_@OX9*ry$XkaLBrf)Cl+_*MK$$tayh`jiO%NwBcfah}ZrC0|hq&hk_iJNeHP5VQ4eDh6hQM>#tV8'
    '=PgL!(Jq(>2T;-C7KRZTtDGdUE&jkt68X9`Srk{Y$yN;H=*2{yl2ZWc^2$;bDQb+L7|ayCDmjZmxx=+s!5++z;HY7Z6E%9;$W59&'
    'lb;LZnc3FU=|WLviPlu}w6e=yp7<*WLW;^H7Z^@J{zGP8n+X2qni#oPu~_Q8E^9jJoKkwFitXq4tNOa#2t8C8p<oeb!ylAchMb$F'
    'WhQ_tl}0Kn(X=)kx*A-6zPW$cb@n~LhA5^yR>4&c@v={uy^fmYXD~VT$#?>D&|<^(Q&cp382H%~K=W?xX`aAU8v}&CyhX0QKy=HN'
    'Nu|KEGO2AuAULRY=v_*;0V@f4{2Y?s%%>oL8ObPmNt!L|-ovCx0Fw!LL<A;}0B}-Y22A?D&Xsm1OzIh>FD9ZtZW6HJel8P|dLUnX'
    'M-2K7KO(p27o@X+67ZG?N1KW$D>N(vrtXZH1j}HD(lb?c=&M+Mpf3>a+&lfvdw+U+-?x7|A6*T9_uk(d3ACA8LEFUNYQ+{7cd}OR'
    'B&hleWlB4=iW4!jqnV|UuJIYRV%cO7Yc|uQ9)BxAw2j~~>wnxy2}j0MOrzvYZR|)byNFV@S<6CYld+2CsWPGrTZUQtw1Eoc*fbC7'
    '5qv$M9)`=P5Fc+Y&qf?tyhURIQ2`|3lpTD$JRjZk`NuTDm<Qc9>^U8Qk4k4zEKN*3dcxe@;3oj7f@+t2Fdac$h8U2B>2qSICVc>j'
    '&%m-_4tyAb`(tou%&-m#W**oVO(mvN5ZGd6GzX%y2u{HgtDh(s2%l=P?@sTyXsTl0Q^4dv&SqHPgA4(yop=}>A*O4Q0(}4}^JlXt'
    'K<FemONbpY#0OO2u~e`wxaezTOc<U8K09T+PCQ+w+L#W65&DOqIDy0^z!(Oi{gG9QB2@9V@^UG4trW6I#L#HNv@Ad{0tqsM=+Pk<'
    'BV<o>vO?}UrJ^e!h2=)1#3VImDcr^qByAaeVPA#*6IQN3WHLO0Dv>G-VQ}*}okDn$u8L|Gc^)k6!s2M2P!80QVvtaRmD(9c)KUgJ'
    'y4jT(^2RCf{u8AWIovL21^KtCB!liOQqFT@J;pd7G|(L`Zh~Rr(S~hs)W&T;>iDR;zGD+l@thCFi_3WU2@&UKSaj0afTkElZQA&8'
    'Qgap&6(|2fMyT?p({>uY%~64h0m|IR6xcvo`k$R6_ehny4itqQRjL-FJ1S)rs`_@mR(T@k2Vr$E9J&+P`84~s4XUnRZE9BholUpf'
    '+aYFO?IJSR_|UORILeP#1!&u)_)mTmE2eK~H#kaT_;UIcyZXX9rKeHQXwadJ1ge?Gu>0u<B{+_y%oJ!<k-Ut-pjs7keG;}lwjWeM'
    'Q$pN|MH?uY3VuCSC8j?zs7WU+x)tMe5Y^wPz5NXeZv}IW$am7Z)xMT5jbH6X6neGBkz+0&18X}|=@U=Y5pDUgr7cL8;Mg5-7-<$_'
    '#VRffY5?-`KDrLdVZ36!lB%_cbx8Y;xQ%6<Nk*0-)w2T*a!A37#pChG!SSSVi$**jY3)ROH_(;FrcBgO<NO?)oi}>_;cECWI<KYb'
    '`XA8xEr6K~Zn>fi72Ba;heK+>^$F!cMe2a*4NL^58b!-|z<l2%6g9L54gPjkaR=%$HbFF(!mG{KjT?Xqwfgoz3BV)v5L9uxwg4n{'
    'yNrM9)fj8gGvY{10xk`ssf6o;T@-P$WQTdM!XID%fZt57+RJ>b0iB5BCb>w=3=APe^xm64BVGf)t}-c?D-=%esf<CJQHSv9g%3z|'
    'LFs16iK%I{+8b>k4JB;tZah~$2f}Mhh_y~(R)}7r2B1@N`dbfCZWm%=xoS4FA!-v6vlP3Hi9lM~!CV8y4<fvefx0yBZuHO58C^D7'
    '5kH4V5Q{qmRHsuY1=az|8qqnnF?tE1O$qA*L5ZC*)9y#S2}YEnH7#P^@cjMd18p?&NFjGq9x=_S%j5U2yXEoK3*_<DR(T}5^S=<s'
    'R{!do#IdXC{Y~PyqbJqhdeSbLB)Cn%tmCy4w^l#xMJR1W%Yba6W+dq)dV|7c>&+IMYiU&d>|URFq>^qglYej*j@DM}vnv`6HMCWc'
    'Q}4DaZerwk@A~H2Yp7x;9or!_Qi8wJoY9+KFVWfgI%oA&cB{0Ca(bF9Qkgk~O@4$avY$7>`IyB<ORNeMJTzn#92D=kd;sYar18-g'
    '_#MxG<#t@|V@tQuwx9vpA_=XVKfn3y`rX~|oXywEZgHE87>Yb4EpRz04lu;UqN<-AlDHq}*wSwHVzgtbO&e_WRsq>&1zHBXMac_6'
    '**0EXM$5(%f3=PGE<RjcRfb*#*MC)D#(Q|s(yu}WY9Fu*XpiX~JRKjTJnP4<L6;tIgK6a2;AH~Qa6m;P26}z-;9XwdKMb#~`1T=T'
    'AnNh4ni^7d5ITTLBLp5l)nKdM7-xUD<Pp1?s+no`N_W*w9*-uI8e~624Sg|uQ=^$6%Bt|-QS?pw)GxIosw}_qYUU@(b104VI@YNK'
    '*M_F%E-kUKN^oXll@WLC#aLMt>C6uJjc$lX35f?PW+4G=a4n#DfGDB6{HreI#+~OZ2OrLF%~Z&HI<4Q_ppfD9Rsp#P4k_}deSK3*'
    '6g0oso;le7UDst8{76@EX*@K~OO8|WzUo)f<N#KuAsb%G!-`b#B(rE1F{?X{$s{buRZw+}g+%2R54lzeh)&mRmuthbS`jUPUu)bh'
    'ApFWn>^#*{<>3pwqb3rUJU2@PGQxL_ZZ#Iuv?yXo^Mg-%gcesM5-T^rU~I%<bvb8#cX4sJTH&NG>>{PjmehJvMpZeNsRYWTSf)?J'
    'FUo$>q)5Rv<qIEgw8Eq72rxZQSUTmM00TIe*UpTJTul8ei*Q<pPs=0@ui}BKBT8N58u+^O=0Unr*L17u&D8)i``aWHH!GQ3#Od>4'
    '5eP1e&=_(U`CKLQ**E-}-Xr<xtS`8VBEk$uYN#@xCwdJsUmFb#tRnkhs-=Tp8~q8Ip*mE&Wm!>EF4RmZvS>cXdNjB<1c5v%vXm;|'
    'Br=S(YgeX~U!c(tM-}%t6PV~)kd|8di5J2H7xdEsr$OGcFPvVl+f7$XYxy#G+`jd!)92xu?I7z#fd<TG0RX2JI>61iWK9JdVELnE'
    '@~}PywC&~5@(>UVs-pGgLHKIIon;Tq1w_->aT5drq<8LP6OOc{1Uv8_If_$>lMi5ks>!UoGQp@Di)lFA1uIDm^D<2P_SGW(YQU*T'
    ';nZ}#){_>Yi}Uo#f10O#)rVqB3fun#I~vsbBSZ1e`<rW}NfaXbV6MhV36h%W;jF_tsRvBo;g4k!fk`=t!k<*fN=2%^X)0ketTwr>'
    '=FKr=ETW~PY@;wgFZ_HFM^p3tk37{g>nMNlNDr*v(mcERlCP^l_p*#aJm~iB1~U)u?&jtJ=l8J2=y?==dOa6KG=7p!&&AQTq)`7G'
    'CjiP_Q6DscdnlYE?A&CI4ULODYLFfsmd1%=4kYQ;9<+zc_RQdoS_-kz!|1**9`1%07nf(=+12p=esphdt4pBXSZ{0g8_m&v!?sj5'
    'N686>T^z@tROGoom)i8GIT5p9Td!Adt>EiP7!MJsnKY|ah2tiydCmA~Vw%8=rdn2uEGJxg>j*BjMzXjHFzCQ@8B?kx6pYY>{@d(8'
    'eIBZ17F#_7#+C+RnIe~*YR;jwGP7(tClu@6nm#eLKS56@bg<gM*q*J;KG`R!>U+CPOKrD-!njorp_tW*uDGs^`M(Tvd-k<f+U{FD'
    'UW;2Vi9;v48)Qq7qQL?R7%QNgBH@WCaEoJk@Q)5R0q(K_s7X@IJJUyow3wz-2w1O;Q-id2m~8L>lq~|bU{&?Q4OT@85t_B#j2oi{'
    ';W)10m$JuHuWMv)XyZ#2FvI6eMH%0i*EKP&#YS46_!S|t_EmJGT~H#6=QR7IhlW+I$c`UEzE^L4pbX*b*Sb{E_y^Ba(Hm!U2KZN<'
    'Cc;m)!K^=NdF9PzC9Nfgs`;hiY;p1R87|aXbR4!HIW#2LB7|4<*rJ^!2G?TNt~{H|PaSeG7_EBKbwTf`xC{9?jDV45WEd`Yxq_`>'
    ';c9p3Ch4;S-|_R8G?8vu1U(lV)C_+CmhS()zuXTW_J7`gzkmPVMx}YwG|kp+f+$==ClC5@XbX<*>gk!o2;sQb0Vxx@S{MKG+9C8G'
    'PmW(rnkTx;Pw?4c|C+1r6U_;F=_f85sx2!>zzQ0OB79Epz6_XNSIt%h$kfHIMYJbm;4MSn@Ux9EKW=8L5E2f}gO%?6p`<!i=jPab'
    ')u*P-@zD_&bjK>9zs5&cKR<qR)P7HedbS#29(3zA@s76POUQn-_0b_Zm+8${+r;<KJvv=PY$~gPOHfmzW^#{*`E*hjMza}sCr-LC'
    'iq&&an2%K6#CpY3?X3APP1vnHe}TxpL46z^o+=B|HO~5mGJAB1R^_AtU8|q67&({8nxmXm1h!@BpM(lrLEZphi|2Tp+@FoEhj*8B'
    '>y5!2yUV|2*t!Yy=HlY&@_Hn0uCIPSsm(~M*>HT*!%S1ZrAeeZQ_x(j6~Ek8{6Li~jEPLHssvlT#)_1<|4<T*p$PqOtbV|EZ6&>y'
    'MLo_AI_#-io+qIqpY?)XV*rK&;KuMv7sN;XZp~!Fh>{|xgST*zV$d8PyzLv%8!u0d?=}P4?j!O?V(dg6wfT;bjKRKpG~3^QtH=Ms'
    '!9E(-ec^yT`A?>#FE$3r9Vomon(dtU+8o(-;V;B~ej;wKhS%4lbNDR&&Hrh=BDU|onyHGM*x%J@?=D4HC2v$yaqtuT*Zm`nS~2y`'
    'PCl>SP<NPY8lUcHBE5(w&VJtG3*Ai@|HR#l4pfwC_9->!3sypbHr|#xquI)^Sqfcga;3t(4T%L96sIK=RDaW0)@nMFt}%$s?6QPZ'
    ';a9J|RGLT*=)}BTPwktkL}#ejKt!^3w7I~uYNE0miEjKGnDIL@20`;j0>V^s@dGDq5rwz-7C$7(>ixI~E?GRMWgIHEx{(UJv>IlQ'
    'N0VlCu7MO+O{-Tk^;+T23VLG#j7_c+j+&V3x1_4RlHIp!yRo63cG=j5dKpQ_lV)RUV32v)MW|95mC-8hgP{-0fZqlL@G+I1xl~=9'
    'wt?}Dx-241K~>{-7Qz>b3#Ii+bvd%&+kY#p7u2ljamqSWtrwEkFEUGa3CfG|@yd<TQ18o;Cs~HzA_7H(B*x5X)0n#|^R+PiyBO-y'
    'G`$rn{A{WIf=14L5PFG++OBC*`&$}ZNo<0n2oWSX!A=V|yL0Y#=Vh?aN{P%fZ?@_daHGQw2y2OdteNOt_5pQaqj8yZ$BIH+FlHTu'
    'Dr3N1edh8Ehb_ol_l>*L__hsqN8J0Uzf8DvKoW;HNgq1P6tn0vgc#b4asGc%{jHNO#L+9LK>w|}5x@qYz{>g`H|fmJ^`Z2xf(M2v'
    'nR~1vUg<xPZY!d{cE$Os{=vQQ6<$wh+Z`)TzrDG-Jo{a|zd0XWiL;+aXTN~2h6GSJst`g|jb1erzymSPFLF(F&c1j6Z>K(1<<DN%'
    'IN1jLw8!dLNDz2kHA?nkIxdEnS0pTw(ZkyqVD&mLLikD7^6+Kwc-@63zJ8N0kmp6fSnMn`fDfBtlcKO+CUC0a!l5ZbaoxbB`u$$d'
    'ea;}z_X_#BaPTKLESIa?VN~!nnGj@U@QUk=&tBpusxUxyXgsc)Y|WT^>{QgN1RF7E@4il7_y>l-3TEc75@E~a3M*JvWtwMqa*2he'
    'g8qEaT)NHInvQsov@IjH5VL1J=9(a^_dK*sp2w>^5AB-gnM4wATYioThf9ap!}|I^*lx~e'
)


def payload_files():
    raw = zlib.decompress(base64.b85decode(PAYLOAD_B85.encode("ascii")))
    if hashlib.sha256(raw).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("Installer payload checksum differs; no files changed")
    files = json.loads(raw)
    if set(files) != {"core/battery_policy.py", "sim/check_battery_policy.py"}:
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
                        dir=path.parent, prefix=".battery-policy-", delete=False) as handle:
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
    print("Next: python3 " + str(project / "sim/check_battery_policy.py"))
    print("Offline model check only; no meters, queues or link failure activated.")
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
