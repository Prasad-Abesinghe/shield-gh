# SOA3 — Random-Forest IDS for Gray-Hole Detection (Arízaga-Silva et al., 2025)

**Baseline paper:** J.A. Arízaga-Silva, A. Medina Santiago, M. Espinosa-Tlaxcaltecatl,
C. Muñiz-Montero, *"Machine Learning-Powered IDS for Gray Hole Attack Detection in
VANETs"*, World Electric Vehicle Journal (MDPI) **2025, 16, 526.**
DOI: 10.3390/wevj16090526.

The paper trains a **Random Forest** on network-traffic features extracted from
NS-3 simulations to classify each vehicle as a gray-hole attacker or benign.
Its tuned model uses **15 estimators, max_depth 15** and reports an F1-score of
**0.9927** under 10-fold stratified cross-validation.

This is a **faithful re-implementation** of that IDS, wired to our SHIELD-GH
NS-3 simulation so that the classifier is trained and evaluated on **real,
event-driven simulation data** — not synthetic numbers.

---

## What is real (and why it satisfies the supervisor requirements)

| Requirement | How SOA3 meets it |
|---|---|
| **Real, event-driven data feeds the model** | `routing.cc` `soa3_monitor_window()` writes, every window, each node's REAL counters — `node_total_received`, `node_total_forwarded`, `dp_drop_counter`, `cp_drop_counter` — straight from the running simulation. Enabled with `--use_soa3_detection=1`. |
| **No abstracted / fake model** | The classifier is a real `sklearn.ensemble.RandomForestClassifier` (paper's 15 estimators / depth 15), trained and tested on the simulation features. Nothing is hard-coded or faked. |
| **Sweep the independent variable** | `soa3_rf_sweep_real.py` runs the real ns-3 sim at each attacker percentage and plots every metric vs attacker %. |
| **Plot mean ± 95% CI** | Each point is the mean over repeated stratified k-fold CV (the paper's own protocol); error bars are the 95% CI of that mean. |
| **Distinct linestyle+colour, gridlines, labelled axes with units** | See `results/soa3_real_sweep_panel.png`. |

---

## Files

| File | Purpose |
|---|---|
| `soa3_rf_sweep_real.py` | **Main deliverable.** Real ns-3-driven attacker-% sweep. Runs the sim per %, trains/evaluates the real RF with repeated stratified k-fold CV, writes `results/soa3_real_sweep_results.csv` and the CI plots. |
| `soa3_random_forest.py` | Single-run RF IDS: leave-one-window-out evaluation over one simulation's real feature CSV. Produces per-node predictions and per-window metrics. |
| `README.md` | This file. |
| `SOA3_Sweep_Results_Report.md` | Results write-up with the plots and discussion. |

The NS-3 side lives in `scratch/routing.cc` between the
`// state of art (start) SOA3` / `// state of art (end) SOA3` markers
(`write_soa3_csv_header`, `soa3_monitor_window`, the `--use_soa3_detection`
command-line flag, and its scheduling in `main`).

---

## Requirements

```bash
pip install --user scikit-learn pandas numpy matplotlib
```

## How to run

**Full real sweep + CI plots** (runs ns-3 once per attacker level):

```bash
cd scratch/State_of_Art_3
# Distinct attacker counts on the 5-node routing_test net:
#   20% -> 1 attacker, 40% -> 2, 60% -> 3, 80% -> 4
python3 soa3_rf_sweep_real.py --percts 20,40,60,80 --simTime 30
```

Reuse the cached per-% simulation CSVs (skip re-running ns-3):

```bash
python3 soa3_rf_sweep_real.py --percts 20,40,60,80 --reuse
```

**Single run** (one attacker level, leave-one-window-out):

```bash
cd ../..                                   # ns-3 root
./waf --run "routing --routing_test=true --routing_algorithm=4 \
             --attack_number=1 --attack_percentage=50 --N_Vehicles=5 \
             --use_soa3_detection=1"
cd scratch/State_of_Art_3
python3 soa3_random_forest.py
```

## Outputs (written to `ns-3.35/results/`)

- `soa3_rf_features.csv` — real per-window, per-node features from the last sim run.
- `soa3_real_cache/soa3_p<pct>.csv` — cached feature CSV per attacker level.
- `soa3_real_sweep_results.csv` — mean ± 95% CI for every metric per attacker %.
- `soa3_real_sweep_panel.png` — combined 2×2 metrics panel.
- `soa3_real_sweep_accuracy.png`, `soa3_real_sweep_mcc.png` — headline figures.

---

## Note on the test-network size

`routing_test` is capped at `total_size = 5` vehicles (a hard ceiling from the
Gurobi link-lifetime model), so the real ns-3 topology is small. Attacker
percentages therefore map to integer attacker counts: 20 %→1, 40 %→2, 60 %→3,
80 %→4. We sweep those four **distinct** attacker densities. Even on this small
test network the metrics move clearly with attacker density — detection accuracy
and MCC fall as the malicious class grows and the majority-class assumption that
the paper analyses (Section 5, Eqs. 4–15) breaks down — which is exactly the
behaviour the supervisor asked to see plotted.
