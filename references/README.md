# References

These are the sources used in the progress report *Green-Aware SDN Relay Control for a 5G-assisted FANET*
(Rama Mhalla and Aurelio Benvenuto, Smart and Programmable Networks, UNICAL).
The numbers [1]–[12] are the same as in the report.

For each source you can see what we took from it and where we use it.
We say clearly what comes from the source and what is our own choice.

## Files in this folder

| File | Source | Why it is here |
|---|---|---|
| `Ref2_Muthukumar_IASC2023_highlighted.pdf` | [2] | Open access (CC BY 4.0), highlighted by us |
| `Ref3_Hossain_Sensors2019_highlighted.pdf` | [3] | Open access (CC BY 4.0), highlighted by us |

All the other sources are **links only**. Their licences do not allow us to share copies
(DJI manual, IEEE papers [7] and [12], ETSI/3GPP specification, USENIX paper), or they are web pages that are
easy to open (RFCs, Linux documentation). Please do not add those PDFs to this repository.

For [12] we keep a highlighted study copy **outside** this repository
(`Ref12_Tropea_DRCN2025_highlighted_PRIVATE.pdf`), because the paper is under IEEE copyright.
The notes below list everything that is highlighted in it.

### How to read the highlighted PDFs

- **Page 1** is a summary that we added. It lists every highlight, its page and how it connects to our route score.
- Each highlight has a label in the left margin (A1–A8 for [2], B1–B9 for [3]). Click the highlight to read the same note.
- Colours: **yellow** = used in our route score (Eq. 1), **blue** = used somewhere else in the project,
  **orange** = a difference, or something we did *not* take.

### Licence note for the two PDFs

Both papers are published under the
[Creative Commons Attribution 4.0 licence](https://creativecommons.org/licenses/by/4.0/).
**Changes made by us:** highlights, margin labels, notes on the highlights and one summary page at the start.
The text of the papers is not changed. The authors and publishers do not endorse our project or our notes.

---

## Our route score (report, Eq. 1)

```
C_i(c) = α_i · D_i / D_max(c)  +  β_i · (1 − f_i)  +  γ_i · CEF_i        (one UAV i, service c)
C(c)(p) = sum of C_i(c) over the UAVs on route p
```

`D_i` = configured delay, `f_i` = battery fraction (0–1), `CEF_i` = carbon index (test input).
Lower is better. The score has no unit.

| Part of Eq. 1 | Comes from | Our own choice |
|---|---|---|
| Weighted sum, α + β + γ = 1 | [2] (stability metric, Eq. 1) | Our three terms: delay, battery, carbon |
| Battery as a fraction of the starting energy (`f_i`) | [2] (willingness, Sec. 4.1.1) | — |
| Do not use relays with low battery | [2] (WILL_LOW nodes are never relays, threshold 10%) | Our threshold is 20% (our choice), consistent with the 20% route-avoidance threshold in [12, Sec. IV-C and V] |
| Carbon emission factor per node (`CEF_i`) | [3] (pollution-aware routing) | We **add** CEF as a normalised term; [3] **multiplies** energy by CEF |
| Path value = sum over intermediate nodes only | [3] (Table 4) | u1 and GS are not counted |
| Normalising a term by a maximum (`D_i / D_max`) | idea also in [2] (Eq. 7) | — |
| Adaptive weights (logistic β, 20% centre, steepness 15, 70/30 split) | — | **ours**, not from a paper |
| CEF values 0.2 / 0.8 / 0.3 / 0.7 | — | **ours**, chosen test inputs, not measured |

---

## [1] 3GPP TS 23.501 — 5G System Architecture

- **Citation:** 3GPP TS 23.501, version 16.8.0, Release 16 (ETSI TS 123 501, 2021).
- **Link:** https://www.etsi.org/deliver/etsi_ts/123500_123599/123501/16.08.00_60/ts_123501v160800p.pdf
- **In this repo:** link only (ETSI does not allow us to share copies).
- **What we took:**
  - Sec. 5.7 and Table 5.7.4-1: the meaning of QFI and 5QI, and the reference values we use
    for 5QI 1 (voice), 5QI 2 (video) and 5QI 9 (control):

    | 5QI | Type | Priority | Delay budget | Packet error rate |
    |---|---|---|---|---|
    | 1 | GBR | 20 | 100 ms | 10⁻² |
    | 2 | GBR | 40 | 150 ms | 10⁻³ |
    | 9 | Non-GBR | 90 | 300 ms | 10⁻⁶ |

  - Sec. 5.7.1.7 and 5.8.2.7: the RAN and the UPF mark the outer IP header with a DSCP value
    (transport-level marking). This is why our FANET can work on DSCP and does not need to read the QFI.
  - Sec. 5.7.2.4: notification control (a report when a GFBR can no longer be guaranteed).
- **Where we use it:** delay budgets (100 / 150 ms) in the admission rules; Part 12 (5G Option 2).
- **Our own choice:** using 5QI 9 for control traffic is our lab mapping. Our rates and our missing-packet metric
  are not 3GPP values, and our measurements do not show 3GPP compliance.

## [2] Muthukumar et al., IASC 2023 — highlighted PDF in this folder

- **Citation:** M. Muthukumar, R. Rangasamy, I. Hussain, S. A. AlQahtani, "Energy Efficient Green Routing for
  UAVs Ad-Hoc Network," *Intelligent Automation & Soft Computing*, 37(1), 1111–1127, 2023.
- **Link:** https://doi.org/10.32604/iasc.2023.034369
- **In this repo:** `Ref2_Muthukumar_IASC2023_highlighted.pdf` (CC BY 4.0).
- **What we took:**
  - The **form of the score**: SM = α·LCI + β·EW + γ·DW with α + β + γ = 1 (their Eq. 1).
  - The **battery fraction**: actual energy divided by starting energy (Sec. 4.1.1) = our `f_i`.
  - **Exclusion of low-energy relays**: a node below 10% says WILL_LOW and is never a relay. We use 20%.
  - Background: a composite energy cost as a routing metric; their results show that excluding low-energy nodes helps.
- **Where we use it:** Eq. 1 (route score) and the 20% exclusion rule.
- **Difference:** their score is "higher is better"; our cost is "lower is better". Their terms are link lifetime,
  energy and node degree; ours are delay, battery and carbon. They use NS2 simulation, we use emulation.

## [3] Hossain et al., Sensors 2019 — highlighted PDF in this folder

- **Citation:** M. M. Hossain, J.-P. Georges, E. Rondeau, T. Divoux, "Energy, Carbon and Renewable Energy:
  Candidate Metrics for Green-Aware Routing?" *Sensors*, 19(13), 2901, 2019.
- **Link:** https://doi.org/10.3390/s19132901
- **In this repo:** `Ref3_Hossain_Sensors2019_highlighted.pdf` (CC BY 4.0).
- **What we took:**
  - The **carbon emission factor (CEF) per node** as a routing metric = our `γ·CEF_i` term.
  - The reason to keep carbon **separate from energy**: "energy consumption is not always proportional to carbon emissions."
  - The path value as a **sum over intermediate nodes only** (Table 4) = our `C(p)`.
  - A **central SDN controller** that receives the environmental values and installs the routes.
  - A **capacity rule**: no link gets more traffic than its capacity (their Eq. 1) = idea behind our admission check.
- **Where we use it:** Eq. 1 (carbon term and path sum), controller design, admission rule.
- **Difference:** they multiply energy by CEF (result in grams of CO₂); we add a normalised CEF term, so our score
  has no unit. Their CEF values are real country values (Table A2); ours are chosen test inputs.
  They use a genetic algorithm on a wired network; we use a simple planner on an emulated FANET.

## [4] DJI Matrice 100 specifications

- **Link:** https://www.dji.com/support/product/matrice100
- **In this repo:** link only.
- **What we took:** TB47D battery: **99.9 Wh**, 22.2 V, 4500 mAh. Hover time **17 min with a 500 g payload**.
- **Where we use it:** energy model, Eq. aircraft power: battery energy C = 99.9 Wh = 359 640 J.

## [5] DJI Matrice 100 User Manual (V1.0, 2015)

- **Link (archived copy):** https://manuals.plus/m/d9fe4c2e7336fe5fcbcedf78b1600286992cce3aa842e0b124ae99b8b654788f.pdf
- **In this repo:** link only (DJI copyright).
- **What we took:** printed pp. 69–71. The note on **p. 70**: the hover test ends at **10% battery**,
  with no wind, 10 m above sea level.
- **Where we use it:** average aircraft power
  `P_A = 0.9 × 359 640 J / 1020 s ≈ 317.33 W` (90% of the energy used in 17 min).
- **Our own choice:** using this hover value as a constant power for every UAV is our simplification.

## [6] Halperin et al., HotPower 2010 — 802.11n power

- **Citation:** D. Halperin, B. Greenstein, A. Sheth, D. Wetherall, "Demystifying 802.11n Power Consumption," HotPower 2010.
- **Link:** https://www.usenix.org/legacy/events/hotpower/tech/full_papers/Halperin.pdf
- **In this repo:** link only.
- **What we took:** Table 3, Intel 5300 card: idle **0.82 W**, transmit **1.28 W**, receive **0.94 W**.
- **Where we use it:** radio energy per bit at our chosen rate R = 65 Mbit/s, with idle power subtracted:
  `ε_T ≈ 7.08 nJ/bit`, `ε_R ≈ 1.85 nJ/bit`.
- **Our own choice:** the rate R and the time-in-state method. The estimate does not include wireless overhead,
  retries or rate changes.

## [7] Zeng, Xu, Zhang, IEEE TWC 2019 — UAV energy (background only)

- **Citation:** Y. Zeng, J. Xu, R. Zhang, "Energy Minimization for Wireless Communication With Rotary-Wing UAV,"
  *IEEE Trans. Wireless Commun.*, 18(4), 2329–2345, 2019, doi:10.1109/TWC.2019.2902559.
- **Link:** https://arxiv.org/abs/1804.02238
- **In this repo:** link only (IEEE copyright).
- **What we took:** the idea of separating **propulsion (flight) energy** and **communication energy**.
- **Where we use it:** background for the energy model. We do **not** use its propulsion formula or its numbers.

## [8] Linux kernel documentation — Interface statistics

- **Link:** https://docs.kernel.org/networking/statistics.html
- **In this repo:** link only.
- **What we took:** the meaning of the interface byte and packet counters.
- **Where we use it:** battery feedback. We read the counters with `ip -s -j link show`
  (not with OpenFlow port counters) and turn transmitted/received bytes into radio energy.

## [9] RFC 7679 — One-Way Delay Metric (IPPM)

- **Link:** https://www.rfc-editor.org/rfc/rfc7679.html
- **In this repo:** link only.
- **What we took:** the standard way to define one-way delay, and why clocks and host timestamps matter.
- **Where we use it:** to explain the limits of our timing values. Our values come from software capture;
  they are **not** the RFC metric and not full application delay.

## [10] RFC 7680 — One-Way Loss Metric (IPPM)

- **Link:** https://www.rfc-editor.org/rfc/rfc7680.html
- **In this repo:** link only.
- **What we took:** loss depends on how long you wait for a packet.
- **Where we use it:** our delivery metric says "absent by the end of the capture", not loss over infinite time.

## [11] RFC 4594 — DiffServ Service Classes

- **Link:** https://www.rfc-editor.org/rfc/rfc4594.html
- **In this repo:** link only.
- **What we took:** common practice for DSCP: **EF (46)** for telephony and **AF41 (34)** for multimedia conferencing.
- **Where we use it:** our voice flow is marked DSCP 46 and our video flow DSCP 34.
- **Note:** in 5G the DSCP values are operator configuration; RFC 4594 is guidance, not a rule.

## [12] Tropea et al., DRCN 2025 — scenario and recruiting

- **Citation:** M. Tropea, A. R. Masaquiza Caiza, L. M. Samaniego Campoverde, M. G. Spina, F. De Rango,
  "A Resource-Aware Ant-Based Recruiting Strategy in 5G-assisted FANET Disaster Scenarios,"
  *21st Int. Conf. on the Design of Reliable Communication Networks (DRCN)*, 2025.
- **Link:** https://doi.org/10.1109/DRCN65040.2025.11046096
- **In this repo:** link only (IEEE copyright). A highlighted private copy is kept outside the repository
  (labels C1–C13).
- **Role in our project:** background for the scenario and for the proposed recruiting stage.
  It does **not** validate our routing policy, energy model or results.
- **What we took:**
  - **The scenario** (C1–C3): UAVs restore voice and video communication between people in danger and
    rescue teams, with a multi-hop UAV relay towards the 5G core through a ground station.
    Our u1 → UAV relays → GS story and the Option 2 transport view follow this.
  - **The low-battery rule** (C5–C6, Sec. IV-C and V): routes avoid UAVs below a threshold E_th set to 20%
    of a DJI Matrice battery. Our exclusion threshold is also 20% (our choice, consistent with this paper).
  - **Metrics for choosing a reserve UAV** (C7, Sec. IV-D): number of hops, energy level, recruiting time,
    available bandwidth. These factors are useful for our proposed recruiting stage.
  - **When to recruit and how long it takes** (C9–C10, Sec. IV-D): a recruitment request is sent when energy
    or bandwidth falls below a threshold (E_thr and B_thr, both 50% in their Table I; this is a different
    threshold from the 20% route-avoidance E_th). The recruiting time depends on UAV speed and distance.
    Our report: start at the battery warning and consider the take-off and travel delay.
  - Supporting points: Wi-Fi links between UAVs (C4) support our Wi-Fi radio energy reference [6];
    a weighted metric with coefficients that sum to 1 (C8) has the same structure as our route score;
    MOS, delay, loss and throughput (C13) are useful metrics for our future QoS evaluation.
- **Where we use it:** Part 3 (20% rule) and Part 13 (recruiting design).
- **Difference:**
  - The paper uses **ant colony optimization**, distributed in every UAV (C11). We could investigate
    **GWO** as another search method, with a central SDN controller. We have not implemented or compared
    the two methods; with only a few reserve candidates, all options can be compared directly.
  - The paper **simulates** with OMNeT++, INET and Simu5G (C12). We **emulate** with real packets, queues and
    interface counters in Containernet, and we do not simulate the 5G radio.
  - Recruiting is **not implemented** in our project yet; it is a design idea in the report.

