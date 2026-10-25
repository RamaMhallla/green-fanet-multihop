# Green-Aware SDN Relay Control for a 5G-assisted FANET

**Rama Mhalla and Aurelio Benvenuto** · MSc Telecommunication Engineering, DIMES, University of Calabria
Course: Smart and Programmable Networks, Module 1

A rescue team (`u1`) sends **VOICE** (DSCP 46) and **VIDEO** (DSCP 34) to a ground station (`GS`).
The network has four UAV relays. Each service uses a selected path through these relays.
A **Ryu** SDN controller (OpenFlow 1.3) uses battery levels, configured delays and synthetic
carbon values to choose the paths. It gives voice first priority. When a battery becomes weak,
the planner checks other paths. Depending on capacity and protection rules, it can move traffic,
reduce the video profile or reject a service.

Everything runs in one Ubuntu VM: Containernet, Docker, **one Open vSwitch (`s1`)** and six
containers (`u1`, `GS`, `UAV1`–`UAV4`). The UAVs are layer-2 relays built with Linux `tc`.
These are emulation experiments, not flights with real drones.

**Results page:** [ramamhallla.github.io/green-fanet-multihop](https://ramamhallla.github.io/green-fanet-multihop/)
(static snapshot of the results, source in [`docs/index.html`](docs/index.html))

---

## Status

| Work item | Status |
|---|---|
| Emulator: one OVS switch, four UAV relays (tc wire), Docker image | DONE |
| Route planner: cost, fixed/adaptive weights, joint planning, discharge guard | DONE |
| Safe route updates (VLAN versions, barriers), meters, priority queues | DONE |
| Failure protection with real traffic, scenario A (3 + 3 runs) | DONE (pilot) |
| Probe checks in scenarios A and B | DONE |
| Offline decision map (UAV1 battery 90% → 0%, 1% steps) | DONE |
| Fixed vs adaptive weights with real traffic (3 pairs) | DONE (pilot) |
| Estimated energy model and battery feedback from interface counters | DONE |
| Zone30 guard and the `zoneB01` traffic pair | DONE (pilot) |
| Measurement protocol v2 | PLANNED (defined in the report, not yet in this repository) |
| 5G connection without a full core (Option 2) | PROPOSED (design only, no code here) |
| Clean traffic sender / timing platform | NOT YET |
| QoS targets met (loss, delay) | NOT YET |
| Energy saving or longer flight time | NOT YET |
| Recruiting a reserve UAV | NOT YET |

**DONE** = built and checked. **PILOT** = done, but only a few runs or diagnostic only.
**PLANNED** = prepared, not run. **PROPOSED** = design for discussion. **NOT YET** = not started or not shown.

---

## Repository map

```
config/       network parameters and energy-model parameters
topology/     Containernet topology: u1, GS, UAV1-UAV4, one OVS switch
docker/       Dockerfile of the node image (fanet-node:latest)
core/         planning logic: route cost, policies, guards, energy model (no Ryu, no Docker)
controller/   Ryu applications that install the routes with OpenFlow
sim/          offline checks, experiment runners and report scripts
docs/         results page (GitHub Pages)
references/   sources used in the report, with notes (see references/README.md)
```

Experiment output is written to `results/`. This folder is **not** in the repository
(it holds large capture files); see [Results data](#results-data).

---

## Reading order

### Short path

1. This README
2. [`config/params.py`](config/params.py): drones, links, rates, delays
3. [`core/model.py`](core/model.py): the route cost (report Eq. 1) and the adaptive weights
4. [`core/feedback_guard_policy.py`](core/feedback_guard_policy.py): strict, zone and no guard
5. [`controller/guard_zone_paths.py`](controller/guard_zone_paths.py): the controller of the latest experiment

### Full path

| # | File | What it does | Report |
|---|---|---|---|
| 1 | `README.md` | Overview, status, how to run | — |
| 2 | `config/params.py`, `topology/fanet_topo.py` | Parameters; the emulated network (one switch, tc-wire UAVs, HTB + netem per hop) | Part 1 |
| 3 | `core/model.py` | Shared route calculation: cost, capacity and delay checks | Part 3 |
| 4 | `core/battery_policy.py` | Battery protection: exclude below 20%, voice first, video full or reduced | Part 3 |
| 5 | `core/joint_battery_policy.py` | Joint planner: tries every voice + video pair; discharge guard | Parts 3–4 |
| 6 | `core/weight_comparison_policy.py` | Same joint + guard planner with fixed or adaptive weights | Part 6 |
| 7 | `core/feedback_guard_policy.py`, `core/guard_zone_protocol.py` | Guard variants; the 28% start / 30% zone-guard protocol | Part 9 |
| 8 | `core/uav_energy_model.py`, `core/energy_feedback.py`, `config/energy_feedback.reference.json` | Estimated energy model (DJI M100 hover + Intel 5300 radio) and battery feedback from counters | Parts 7–8 |
| 9 | `core/battery_enforcement.py` | Queue tree (voice / video / control), VLAN ids per update, meter ids | Part 5 |
| 10 | `controller/battery_paths.py`, `controller/joint_battery_paths.py`, `controller/guard_zone_paths.py` | Ryu engine: VLAN-versioned, barrier-ordered updates; joint and zone-guard controllers | Part 5 |
| 11 | `sim/run_guard_zone_feedback.py`, `sim/guard_zone_report.py` | Latest experiment runner and its report | Part 10 |

---

## Run without the VM (plain Python 3)

These scripts run offline: no Docker, no Ryu and no network changes.
They print checks or calculated decisions. Some also save reports under `results/`.

```bash
git clone https://github.com/RamaMhallla/green-fanet-multihop.git
cd green-fanet-multihop

python3 sim/check_paths.py                    # one route cost example
python3 sim/check_capacity.py                 # admission plan (capacity and delay rules)
python3 sim/check_weights.py                  # adaptive weight values at different battery levels
python3 sim/check_battery_policy.py           # battery protection on the lab graph
python3 sim/check_joint_battery_candidate.py  # joint planner and discharge guard
python3 sim/check_weight_comparison.py        # same planner, fixed vs adaptive weights
python3 sim/run_planner_decision_map.py       # decision map 90% -> 0% (report Result 4)
python3 sim/audit_feedback_guard.py           # strict / zone / no guard audit
python3 sim/check_energy_feedback.py          # energy-feedback arithmetic and planner
python3 sim/check_guard_zone_feedback.py      # rehearsal of the zone-guard protocol
```

`run_planner_decision_map.py` also writes an `index.html` with the figures.

---

## Run in the lab VM

**Needs:** Ubuntu VM with Docker and Open vSwitch; Python 3;
Containernet installed in its own virtual environment at `~/containernet-venv`;
Ryu installed in a virtual environment at `~/ryuenv` (the runners call `~/ryuenv/bin/ryu-manager`).

```bash
# 1. Build the node image (once)
docker build -t fanet-node:latest docker/

# 2. Terminal 1: start the topology with the Containernet environment (needs root).
#    Keep this terminal open while the experiments run in terminal 2.
sudo "$HOME/containernet-venv/bin/python3" topology/fanet_topo.py

# 3. Terminal 2: run one experiment arm (the runner starts Ryu itself)
sudo -v                                         # do NOT use "sudo python3" for the runners
python3 sim/run_guard_zone_feedback.py --scenario B --weights fixed    --kind udp --pair myPair
python3 sim/run_guard_zone_feedback.py --scenario B --weights adaptive --kind udp --pair myPair

# 4. Report for the two arms
python3 sim/guard_zone_report.py results/guard-zone-feedback-trials/<fixed-run> results/guard-zone-feedback-trials/<adaptive-run>
```

Use `--kind functional` for a quick probe check instead of real UDP traffic.

---
### Open the results page from the VM (SSH tunnel)

We tested opening the results page from Windows through an SSH tunnel
to the Ubuntu VM. This shows the static results page.
It does not read live controller or battery state.

In the Ubuntu VM:

```bash
python3 -m http.server 8080 \
  --bind 127.0.0.1 \
  --directory "$HOME/green-fanet-multihop/docs"
```

The web server listens only on the VM's loopback address.

On Windows, open PowerShell. Our VirtualBox NAT rule forwards
host port 2022 to guest port 22:

```powershell
ssh -N -p 2022 -L 127.0.0.1:8080:127.0.0.1:8080 rama@127.0.0.1
```

Enter the Ubuntu user's password and keep both terminals open.
If your SSH port or username is different, change those values.

Open http://127.0.0.1:8080 in the Windows browser.

To stop, press Ctrl+C in PowerShell to close the tunnel,
then Ctrl+C in the Ubuntu terminal to stop the web server.
This does not stop the public GitHub Pages website.
---

## Experiments

### Historical experiments (kept, not repeated)

| Experiment | Main scripts | Planner |
|---|---|---|
| Ping trials with synthetic battery states | `sim/run_live_trial.py`, `controller/live_paths.py` | first controller (`core/lab_scenario.py`) |
| UDP trials with a battery event | `sim/run_udp_trial*.py`, `controller/live_paths*.py` | first controller (`core/lab_scenario.py`) |
| Source calibration and loopback checks | `sim/run_udp_calibration*.py`, `sim/run_source_loopback_check.py` | — |
| Failure protection, scenario A (3 + 3 runs): frozen vs protection | `sim/run_battery_resilience_pilot.py` | joint + guard (protection arm) |
| Voice queue 100 vs 128 packets | `sim/run_voice_buffer_*.py` | joint + guard |
| Fixed vs adaptive weights, scheduled battery | `sim/run_weight_comparison.py` | joint + strict guard |

Two energy experiments used **different energy parameters**; do not mix their numbers:

| Experiment | Main script | Energy parameters |
|---|---|---|
| Energy observation, scheduled battery (`energyB01`) | `sim/run_weight_energy_trial.py` | Earlier illustrative parameters (156 W baseline) |
| Automatic battery feedback (`feedbackB01`) | `sim/run_energy_feedback_trial.py` | Reference-derived composite model (318.15 W baseline) |

Earlier failed or inconclusive runs are kept and reported as they are.

### Latest tested protocol

**Zone30 guard with model-based battery feedback** (`zoneB01`): both arms use the joint planner
and the 30% zone guard; UAV1 starts at 28%; all four batteries are updated from the energy model
and the measured interface counters. Code: `core/guard_zone_protocol.py`,
`controller/guard_zone_paths.py`, `sim/run_guard_zone_feedback.py`, `sim/guard_zone_report.py`.

| Result in `zoneB01`, scenario B | Fixed weights | Adaptive weights |
|---|---:|---:|
| VOICE packets captured at source / GS | 5000 / 5000 | 5000 / 5000 |
| VIDEO packets captured at source / GS | 17500 / 17230 | 17500 / 16818 |
| VIDEO source IDs absent at GS | 270 | 682 |
| VIDEO moved off UAV1 | No | Yes, at sampled 25.776% |
| Source check | FAIL | FAIL |

Both methods replan. Only the weights differ.
Adaptive weights moved video away from UAV1, but this run had more
missing video packets. This pair does not show better QoS or energy saving.

### Prepared: measurement protocol v2

Defined in the progress report (Part 11): a mean-rate gate and a burst descriptor for the
traffic source, instead of the v1 source rules. Not yet in this repository and not yet run.

### Proposed: 5G Option 2

The FANET as an emulated QoS-aware transport for a proposed 5G N3 backhaul, with a small
session-request interface to Ryu. Design only (report Part 12); there is no code for it here.

---

## Results data

Raw experiment folders (`results/`, packet captures, logs) are kept locally and are not in this
repository because of their size. The main numbers are in the progress report and on the
[results page](https://ramamhallla.github.io/green-fanet-multihop/). The offline results can be
recreated with the commands in [Run without the VM](#run-without-the-vm-plain-python-3).

---

## Known limitations

- **Irregular traffic sender.** Most UDP runs fail the v1 source check: the sender in the VM is
  not regular enough. Timing values are software-capture values, not standard one-way delay.
- **Energy is estimated, not measured.** Hovering dominates (about 318 W per UAV); relaying
  4.2 Mbit/s adds about 0.04 W. No energy saving or longer flight time is shown.
- **Small samples.** Pilots are 1–3 runs per arm; the results are descriptive.
- **No real 5G and no real drones.** DSCP classes are a lab mapping; there is no 5G core.

---

## References

The sources used in the report are listed in [`references/README.md`](references/README.md),
with what we took from each one. Two open-access papers ([2], [3]) are included with highlights.
