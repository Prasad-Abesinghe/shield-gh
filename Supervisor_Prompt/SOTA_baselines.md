Here are the detailed instructions. Now, you can run the SOTA baselines. Do not run the proposed method until the debugging is cleared. 👇👇👇


---

## Paper 1 — SHIELD-GH Detection (Elsevier, Galle Map)

---

### SOTA Experiments E1–E5

Each experiment runs five systems side by side: SHIELD-GH full mode, SHIELD-GH lightweight mode only, B1 (Malik 2023), B2 (Alabdulatif 2024), B3 (Ahsan 2024). Every figure and table must show all five as separate series. Lightweight mode means signatures S1–S6 plus MATD plus ZKP gate only — no LLM, no FL, no fusion with AI terms.

---

**E1 — 2D Attack Grid (Attack Penetration × Attack Intensity)**

This experiment answers: how does detection and mitigation quality change as the attacker population grows and as individual attackers become more aggressive? You run every combination of attacker percentage and drop rate, producing a grid of 36 operating points per system.

Set up your run configuration as follows. Fix N=200 vehicles, v=80 km/h, and all six attack variants (S1 through S6) active simultaneously on every attacking node. Do not run variants separately for this experiment — all attacking nodes behave as a mixed-variant attacker pool. Sweep attacker penetration p through the values 0%, 20%, 40%, 60%, 80%, 100% and independently sweep drop rate ρ_a through the same six values. Every combination of p and ρ_a forms one simulation run. For each of the 36 (p, ρ_a) pairs, run the simulation once for the full SHIELD-GH system, once for the lightweight-only system, once for B1, once for B2, and once for B3. This produces 180 total simulation runs for E1.

At p=0% the attack is inactive regardless of drop rate — this is your no-attack baseline row that verifies the system produces MCC=1.0 and FIR near 0 under no threat. At p=100% every node is an attacker, which tests saturation behavior.

For each completed run record five metrics: M1 (MCC), M2 (GHSR), M3 (AVCR), M4 (FIR), M5 (ESRL). Produce six heatmaps — one per metric — where the x-axis is ρ_a from 0% to 100% and the y-axis is p from 0% to 100%. Each heatmap shows all five systems as separate panels side by side with a shared color scale so the reader can visually compare where each system degrades.

---

**E2 — Vehicle Mobility Sweep**

This experiment answers: does detection remain accurate and false isolation remain low as vehicles move faster, and does MATD correction visibly reduce false isolation compared to baselines that have no mobility correction?

Fix N=200 vehicles, p=40% attackers, ρ_a=40% drop rate, all six attack variants active. Sweep vehicle speed through six equal steps: 10, 42, 74, 106, 138, and 170 km/h. For each speed level you must configure SUMO so every vehicle actually travels at that exact speed with no stochastic deviation. To do this: open the SUMO vType definitions file and for every vehicle class (car, bus, lorry, van, truck) set speedFactor to 1.0 and speedDev to 0.0. Set the maxSpeed attribute in each vType to the target speed in metres per second (divide km/h by 3.6 to convert). Then open the OSM network file and override the speed attribute on every road edge to the same target value in m/s. Do not rely on road class defaults from OSM — they must be explicitly overridden. After making these changes, run a short zero-attack test and confirm from the SUMO FCD output that every vehicle's logged speed matches the target within 0.5 km/h.

Run each of the six speed levels for SHIELD-GH full, SHIELD-GH lightweight, B1, and B3. Do not include B2 — it has no mobility model and its results at different speeds are meaningless. At each speed level, record M1 (MCC), M2 (GHSR), M4 (FIR), M5 (ESRL), and the communication overhead sub-metric of M6 (Ω_comm). Produce line plots with speed on the x-axis, one line per system. The most important plot is M4 (FIR) — at low speeds FIR should be near zero for all systems; as speed increases, SHIELD-GH full and SHIELD-GH lightweight should maintain low FIR while B1 and B3 show rising false isolation rates because they have no mobility correction. If this pattern does not appear in your results, the SUMO speed configuration was not applied correctly.

---

**E3 — Scalability**

This experiment answers: does the framework maintain detection quality and acceptable overhead as the network grows larger?

Fix v=80 km/h, p=40%, ρ_a=40%, all six variants active. Sweep vehicle population N through six equal steps: 50, 100, 150, 200, 250, 300. At each N level set the RSU count to N divided by 25, rounded to the nearest integer (so N=50 gives 2 RSUs, N=300 gives 12 RSUs). Run each N level for all five systems. Record M1, M2, M4, M5 for comparison between systems. Additionally record all three sub-metrics of M6 (Ω_comp, Ω_comm, Ω_store) as functions of N for SHIELD-GH full only — these quantify how protocol overhead scales. Finally record M9 (η_rekey), which is the ratio of PQC-LKH Kyber operations to unicast Kyber operations at each N, comparing SHIELD-GH full against a unicast-only re-keying baseline.

For M9, print and record the exact number of Kyber enc operations performed during each re-keying event in the PQC-LKH configuration and in the unicast configuration separately. The PQC-LKH count should equal ceiling(log₂ N) at each N value — verify this explicitly and include it in your results. If the count does not match ceiling(log₂ N), the LKH tree traversal is not working correctly and must be fixed before reporting these results.

Produce line plots with N on the x-axis. The detection metric plots (M1, M2, M4, M5) show all five systems. The overhead plots show SHIELD-GH full only, with three subplots for the three M6 sub-metrics. The M9 plot shows two lines — PQC-LKH operation count and unicast operation count — with a third line showing the theoretical ceiling(log₂ N) curve to validate that the implementation matches theory.

---

**E4 — Attack Evasiveness Index (AEI)**

This experiment answers: as attackers become progressively harder to detect by optimising their intermittency, duty cycle, and targeting selectivity simultaneously, at what point does the lightweight mode fail and the full LLM-FL mode become necessary?

Fix N=200, v=80 km/h, p=40%, all variants active. The AEI parameter ξ runs from 0.0 to 1.0 in six equal steps: 0.0, 0.2, 0.4, 0.6, 0.8, 1.0. At each ξ value compute the three attack parameters as follows. The intermittent period T* equals ξ multiplied by T_max where T_max is 30 seconds — so at ξ=0.0 the intermittent period is zero (continuous attack, fully detectable) and at ξ=1.0 it is 30 seconds (very long period, hard to detect autocorrelation). The duty cycle d equals 0.8 minus ξ multiplied by 0.75 — so at ξ=0.0 the duty cycle is 0.80 (attacker active 80% of cycle) and at ξ=1.0 it is 0.05 (attacker active only 5% of cycle, very sparse). The targeted flow count k_t equals the maximum of 1 and the floor of (1 minus ξ) multiplied by 20 — so at ξ=0.0 the attacker targets 20 flows (very broad, detectable) and at ξ=1.0 it targets only 1 flow (very selective, hard to detect via KL divergence). The fixed-rate attacks S1 and S4 remain active at ρ_a=40% across all ξ levels — they have no evasiveness dimension in this experiment.

Run each ξ level for SHIELD-GH full, SHIELD-GH lightweight, B1, and B3. Record M1, M2, M3, M4, M5 at each ξ point. In the M1 (MCC) plot, add a vertical dashed line at the ξ value where SHIELD-GH lightweight mode MCC first drops below 0.5 — this is the evasiveness threshold beyond which the lightweight mode is insufficient and the full LLM-FL mode becomes the primary detector. The visual effect you are looking for is SHIELD-GH full maintaining high MCC beyond this dashed line while SHIELD-GH lightweight and the baselines collapse.

---

**E5 — Per-Variant Comparison Table**

This experiment answers: for each individual attack variant in isolation at a standard operating point, how does each system perform?

Fix N=200, v=80 km/h, p=40%, ρ_a=40%, ξ=0.4. Run six separate simulations — in each simulation activate only one attack variant and deactivate all others. The six runs correspond to: S1 only active, S2 only active, S3 only active, S4 only active, S5 only active, S6 only active. Run each of these six configurations for all five systems (SHIELD-GH full, SHIELD-GH lightweight, B1, B2, B3). This produces 30 simulation runs total.

Produce a single table. The rows are S1 through S6. The columns are SHIELD-GH full, SHIELD-GH lightweight, B1, B2, B3. Each cell contains four numbers: M1 (MCC), M2 (GHSR), M4 (FIR), M5 (ESRL). For cells where a baseline has no detection capability for that variant, write N/A. B1 covers S1 and partial S2 only — mark S3 through S6 as N/A for B1. B2 covers S1 and S2 data-plane only — mark S3 through S6 as N/A for B2. B3 covers S1, S2, S3 data-plane only — mark S4, S5, S6 as N/A for B3.

---

### Paper 1 Ablation Experiments A1–A10, A15

For every ablation experiment, run two configurations at every independent variable value: the full SHIELD-GH system and the ablated version. Record the target metrics for both at each point. Plot both as separate lines so the reader can see the contribution of the removed component as the gap between the two curves.

---

**A1 — MATD Mobility Correction**

The full system computes a mobility-corrected PDR by adding the expected handoff-induced loss rate ρ_ho back to the observed PDR before applying any signature threshold. The ablated version skips this correction — the observed raw PDR is passed directly to the signature engine without any adjustment. To implement this ablation, leave the MATD object instantiated and call its ComputeHandoffLoss function as normal — but instead of adding the result to the observed PDR, set corrPDR equal to the raw observed PDR. The variable corrPDR is still passed to all downstream components (signatures, reputation update, fusion) — nothing else in the pipeline changes. Only the numerical value of corrPDR differs.

Set the independent variable to vehicle speed and sweep through six values: 10, 42, 74, 106, 138, 170 km/h using the same SUMO speed-override procedure described in E2. At each speed level run the full system and the ablated version. Record M1 (MCC) and M4 (FIR). The expected pattern is: at low speeds (10 km/h) the two configurations produce similar MCC and FIR because handoff loss is negligible. As speed increases, the ablated version should show rising FIR as legitimate nodes with handoff-induced PDR drops are incorrectly flagged, while the full system maintains low FIR by correcting for this loss.

---

**A2 — Data-Plane Signatures S1–S3**

The full system evaluates three data-plane signatures: S1 (fixed-rate PDR threshold and variance check), S2 (autocorrelation of the binary drop indicator), and S3 (KL-divergence of the per-source PDR distribution). The ablated version disables all three of these formal signature evaluations and replaces them with a minimal substitute: if the mobility-corrected PDR is below 0.50, set S_total to 0.5; otherwise set S_total to 0.0. This substitute is intentionally simple — it represents the weakest possible PDR-based signal that keeps the fusion receiving a numerical input rather than a zero or null. The LLM score Q_i and reputation term (1−R_i) continue operating normally in the fusion. Only the S_total term is replaced.

Set the independent variable to ρ_a and sweep through six values: 0%, 20%, 40%, 60%, 80%, 100%. Activate only the S1 (DP-FR) attack variant in this experiment — this isolates the contribution of the fixed-rate detection mechanism. Record M1 (MCC) and M3 (AVCR). The gap between the two MCC curves shows the contribution of the formal S1–S3 signature design over the minimal threshold substitute.

---

**A3 — Controller-Plane Signatures S4–S6**

The full system evaluates three controller-plane signatures: S4 (per-flow-rule drop probability threshold), S5 (autocorrelation of malicious flow-rule counts), and S6 (non-wildcard drop rules on safety-critical traffic absent from the whitelist). The ablated version disables all three CP signature evaluations — forces S4=S5=S6=0 at every window. The controller trust module Tc(t) continues operating — it still decrements based on the Ψ_c aggregate anomaly path whenever sub-threshold suspicious rules accumulate above ψ_thresh. This is the substitute: Ψ_c continues as the sole mechanism for detecting controller anomalies. The individual signature triggers are removed but the aggregate soft signal remains.

Set the independent variable to α_CP, the fraction of all attackers assigned as controller-plane attackers, and sweep through six values: 0%, 20%, 40%, 60%, 80%, 100% with total p=40% fixed. Activate only the S4 (CP-FR) attack variant. Record M1 (MCC) and M3 (AVCR). At α_CP=0% all attackers are data-plane and the absence of CP signatures does not matter — both curves should match. As α_CP increases, the ablated curve should show declining MCC because Ψ_c alone cannot catch all CP-FR attacks that the formal S4 signature would have caught.

---

**A4 — LLM Semantic Scorer**

The full system uses Qwen2.5-7B to compute Q_i, a 7-class threat score for each node each window, and weights it in the fusion with μ₂=0.20. The ablated version sets Q_i=0.0 for every node every window and sets μ₂=0. To keep the fusion equation normalized, redistribute the μ₂ weight to μ₁ — set μ₁=0.85, μ₃=0.15. The fusion still runs and produces a verdict every window based on S_total and (1−R_i) only. The LLM bridge subprocess is not called in the ablated version — this also means the ablated runs complete much faster, which is expected.

Set the independent variable to ρ_a and sweep through six values: 0%, 20%, 40%, 60%, 80%, 100%. Activate only the S2 (DP-IT) intermittent attack variant — this is the variant where the LLM's temporal pattern reasoning is most valuable and where signatures alone are weakest. Record M1 (MCC) and M3 (AVCR). The expected pattern is: at high ρ_a (60-80%) signatures already perform well and the LLM adds little, so the two curves converge. At low ρ_a (10-20%) the intermittent signal is ambiguous and the LLM's ability to reason over multiple windows should give the full system a visible advantage.

---

**A5 — Federated Learning**

The full system runs live FL aggregation — every 10 detection windows, each vehicle client performs local LoRA fine-tuning on its observed window data and submits a gradient update; the aggregator verifies the hash commitment, runs FedAvg, and updates the global model for the next 10 windows. The ablated version replaces this with a static model — before the simulation starts, train the model offline once on the full training dataset and fix its weights for the entire run. During the simulation, this static model still produces Q_i scores at every window; it just never updates its weights based on what it observes during the run.

To verify the ablation is correctly implemented, print the global model weight L2 norm at window 1 and window 30 in both configurations. In the full system the norms must differ (model is updating). In the ablated version the norms must be identical (model is static). If they are identical in both, FL is not running in either configuration and both are using the static model.

Set the independent variable to the Dirichlet non-IID heterogeneity parameter α that controls how skewed each vehicle's local data distribution is. Sweep through six values: 0.1, 0.3, 0.5, 0.7, 0.9, and IID (uniform). Lower α means more heterogeneous local data across vehicles — this is where FL's ability to aggregate diverse local information matters most. Record M1 (MCC) and M10 (FL poisoning robustness MCC at ρ_p=0, no poisoning in this experiment). The gap between the full-system and ablated-system curves should be largest at α=0.1 and smallest at the IID setting.

---

**A6 — Gradient Hash Integrity**

The full system commits a SHA-256 hash of each vehicle's gradient update to the blockchain before transmission. The aggregator retrieves this commitment and re-hashes the received gradient — if the hashes do not match, the update is rejected and does not enter FedAvg. The ablated version skips the hash comparison — the aggregator accepts every received gradient update regardless of whether its hash matches the blockchain commitment. The blockchain commitment is still written every round (the log remains intact) but the accept/reject decision always accepts.

To verify the ablation is working, inject one known-poisoned gradient — a gradient deliberately modified after the hash commitment is made — and confirm that the full system rejects it (prints a rejection log line) while the ablated version accepts it (includes it in the FedAvg round). If both accept or both reject, the ablation is not correctly implemented.

Set the independent variable to the poisoning fraction ρ_p — the fraction of vehicles submitting poisoned gradients — and sweep through six values: 0%, 10%, 20%, 30%, 40%, 50%. At each ρ_p level run the simulation and record M10 (the global model MCC under this level of poisoning). At ρ_p=0% both configurations should produce the same M10 because no poisoning occurs. As ρ_p increases, the ablated system's M10 should decline while the full system maintains stable M10 because rejected poisoned updates are excluded from FedAvg.

---

**A7 — DEBSC Cryptographic ZKP Gate**

The full system requires both the statistical reputation gate AND the ZKP proof gate to fail before isolation proceeds (Eq. debsc). The ablated version removes the ZKP requirement — the DEBSC isolates a node whenever (1−R_i) > θ_R, regardless of whether the ZKP proof passed or failed. The ZKP proofs are still generated, transmitted, verified, and recorded in the blockchain every window — the cryptographic machinery is unchanged. Only the isolation decision no longer consults the ZKP result.

Set the independent variable to ρ_a and sweep through six values: 0%, 20%, 40%, 60%, 80%, 100%. Record M2 (GHSR) and M4 (FIR). The key expected finding is in FIR: the full system should maintain low FIR across all ρ_a values because legitimate nodes with genuine handoff-induced PDR drops still produce valid ZKP proofs (they forwarded everything they received), blocking false isolation. The ablated system should show elevated FIR because those same legitimate nodes' reputation scores are low enough to trigger the statistical gate alone.

---

**A8 — ZKP ABSENT State (Three-State Model)**

The full system uses a three-state ZKP model: PASS (proof submitted, cryptographically valid, cross-reference consistent), FAIL (proof submitted but invalid or cross-reference inconsistent), and ABSENT (no proof submitted within deadline T_zkp). ABSENT triggers the same isolation pathway as FAIL. The ablated version uses a two-state model: when no proof is received within T_zkp, the result defaults to PASS instead of ABSENT. A submitted-and-invalid proof still produces FAIL. Only the missing-proof case is treated differently.

Set the independent variable to the proof-withholding fraction — the percentage of attacker nodes that strategically withhold their ZKP proofs entirely rather than submitting false ones — and sweep through six values: 0%, 20%, 40%, 60%, 80%, 100%. To implement proof-withholding for attacker nodes, add a flag to those nodes that causes them to skip the proof submission step while still receiving and dropping packets normally. At each fraction level, assign that percentage of attacker nodes to withholding status and the remainder to normal (false-proof-submitting) attacker status.

Record M7 (PEDR — proof evasion detection rate). At 0% withholding both configurations detect all attackers via FAIL proofs and M7 is identical. As the withholding fraction increases, the two-state ablated version's M7 declines because withheld proofs are treated as PASS and those attackers escape detection. The full system's M7 should remain high because ABSENT is treated identically to FAIL.

---

**A9 — RSU Cross-Reference**

The full system validates ZKP proofs in two stages: first cryptographic verification of the Pedersen proof, then cross-referencing the committed forwarding count against the RSU-independently-observed count within tolerance ε_obs. A proof that passes cryptographic verification but fails the cross-reference is classified FAIL. The ablated version skips the cross-reference stage — proofs are accepted as PASS on cryptographic validity alone without checking against the RSU-observed count. The RSU still independently observes and logs the count, but the comparison is not performed.

Set the independent variable to the fabricated-commitment fraction — the percentage of attacker nodes that generate cryptographically valid Pedersen proofs but commit to a forwarded count that is higher than what they actually forwarded. Sweep through six values: 0%, 20%, 40%, 60%, 80%, 100%. At each fraction level that percentage of attackers fabricates valid proofs, and the remainder submits no proof (ABSENT). Record M7 (PEDR). The full system catches fabricated-commitment attackers via the cross-reference discrepancy; the ablated system accepts their proofs as valid and M7 declines as the fabrication fraction grows.

---

**A10 — Probationary Mode**

The full system places any vehicle with fewer than N_min blockchain-recorded RSU interactions in PROBATIONARY mode. In this mode the reputation-based statistical gate is suspended and replaced by a single-strike ZKP rule — any ZKP result of FAIL or ABSENT immediately triggers graduated response level 2 (rate-limiting and mandatory per-batch ZKP verification) without requiring a low reputation score. The ablated version removes this distinction — all vehicles are in ACTIVE mode from their first window, meaning new vehicles must accumulate sufficient adverse reputation before the statistical gate can trigger, giving pseudonym-cycling attackers a free window.

Set the independent variable to the pseudonym rotation rate — the number of fresh identity registrations per minute across the attacker population. Sweep through six values: 0, 2, 4, 6, 8, 10 rotations per minute. A vehicle that rotates its pseudonym starts with a fresh blockchain identity and zero interaction history, re-entering probationary mode in the full system or immediately entering ACTIVE mode in the ablated system. Record M4 (FIR) and M7 (PEDR). FIR may rise in both configurations at high rotation rates if new legitimate vehicles are also inadvertently flagged — this is expected and informative. M7 (detection rate for attackers) should remain high in the full system due to the single-strike ZKP rule catching freshly-registered attackers immediately, while declining in the ablated version where new attackers have a reputation-accumulation grace period.

---

**A15 — PQC-LKH Group Re-Keying (shared with Paper 2)**

The full system uses a binary tree Logical Key Hierarchy with Kyber-1024 at each internal node. When a node is isolated, only the ⌈log₂N⌉ nodes on the path from the isolated node's leaf to the root are re-keyed, requiring ⌈log₂N⌉ Kyber enc operations. The ablated version uses unicast re-keying — when a node is isolated, the RSU sends individual Kyber.Enc messages to each of the remaining N−1 vehicles, each receiving its own ciphertext. The cryptographic guarantee is identical (every remaining vehicle gets a fresh group session key that the isolated node cannot derive), but the cost is O(N) instead of O(log N).

Set the independent variable to N and sweep through six values: 50, 100, 150, 200, 250, 300 vehicles. At each N value, trigger exactly one isolation event per run and count the exact number of Kyber enc operations performed in the PQC-LKH configuration and in the unicast configuration. Also measure wall-clock time for each re-keying event. Record M6 (Ω_comp — computational overhead measured as operation count, and Ω_comm — communication overhead measured as total ciphertext bytes broadcast) and M9 (η_rekey = ⌈log₂N⌉ divided by N−1). For the PQC-LKH configuration, print and verify that the operation count equals exactly ⌈log₂N⌉ at each N. For the unicast configuration, verify the operation count equals exactly N−1.

---

## Paper 2 — SHIELD-GH-G Governance (Elsevier, Galle Map)

Paper 2 has no external SOTA baselines. Every experiment compares the full governance system against a minimum-alternative ablated version. Both configurations are run at every independent variable value and plotted as two lines.

---

**A11 — Aggregate Controller Anomaly Score Ψ_c**

The full system maintains a running count Ψ_c(t) over a sliding window W_c of all controller-issued flow rules whose drop probability falls in the sub-threshold range (τ_sub, τ_c) — individually below the S4 trigger but collectively suspicious. When Ψ_c(t) exceeds ψ_thresh the controller trust score Tc is decremented by δ_agg even without an individual S4 trigger. The ablated version disables this aggregation — sets Ψ_c(t)=0 at all times and removes the δ_agg decrement path. Controller trust still decrements on hard individual S4-S6 trigger events via δ_sig. The ablated version represents a hard-threshold-only controller anomaly detector.

Set the independent variable to the sub-threshold rule injection rate — the number of malicious flow rules per minute installed by the compromised controller, each with a drop probability in the range (τ_sub, τ_c), deliberately kept individually below the S4 trigger. Sweep through six values: 0, 4, 8, 12, 16, 20 rules per minute. At each rate, run both configurations and record M8 (CADR — controller anomaly detection rate, defined as the fraction of compromised controllers whose trust score falls below θ_c within the simulation duration). At low rates both configurations detect nothing because individual rules are below threshold. As the rate increases, the full system's CADR should rise because Ψ_c accumulates evidence; the ablated version's CADR should remain near zero because no individual rule triggers S4.

---

**A12 — Multi-Controller Architecture**

The full system operates with M=3 registered controllers, each with its own trust score Tc maintained on the blockchain, and uses ordered-list failover to select a replacement when any controller's Tc falls below θ_c. The ablated version reduces to a single-controller architecture — removes the M-controller registry entirely. When the sole controller's Tc falls below θ_c the system enters degraded mode: graduated response level 2 applies to all suspected nodes (rate-limiting and mandatory per-batch ZKP verification), but no replacement controller is selected because none exists.

Set the independent variable to the number of simultaneously compromised controllers and sweep through six values: 0, 1, 2, 3, 4, 5. In the full system with M=3 controllers, compromising 1 controller triggers failover to the next eligible controller. Compromising 2 triggers failover again. Compromising all 3 exhausts the failover list and the system enters degraded mode. In the ablated single-controller system, compromising 1 controller immediately causes degraded mode. Values of 4 and 5 represent over-saturation scenarios included for completeness. Record M2 (GHSR) and M11 (CFRT — controller failover recovery time, defined as the time from DEBSC detecting Tc<θ_c to the replacement controller's first whitelist-verified flow rule taking effect). For the single-controller ablation, M11 is undefined when Tc<θ_c since no recovery occurs — record this as infinity or maximum simulation duration.

---

**A13 — Ordered-List Failover vs Highest-Trust Selection**

The full system uses ordered-list failover — when a controller fails, the replacement is the first eligible entry (with Tc > θ_c) in the segment-specific ordered list stored on the blockchain, where list order was fixed at bootstrap by geographic proximity and capacity. The same controller is not chosen repeatedly; load distributes across the controller fleet as different segments fail over to different ordered-list entries. The ablated version uses highest-trust selection — when any controller fails the replacement is always the globally highest-trust registered controller (still requiring Tc > θ_c for eligibility). Over time this concentrates all fallback load on whichever single controller has accumulated the highest trust, creating a new dominant controller.

Set the independent variable to the number of concurrently failing segments and sweep through six values: 1, 2, 3, 4, 5, M−1 (where M=3 means the maximum is 2 concurrently failing segments, so extend the sweep by treating higher values as the maximum-feasible scenario with the current M). Record M11 (CFRT) at each point. With ordered-list failover, CFRT should remain roughly constant as more segments fail because different controllers absorb different segments' load. With highest-trust selection, CFRT should grow as more segments simultaneously redirect to the same highest-trust controller, which becomes overloaded.

---

**A14 — DKG Joint Key Generation**

The full system generates the root Kyber key pair for the PQC-LKH tree jointly via Pedersen Distributed Key Generation — the active controller and all registered RSUs each contribute a secret polynomial share, and no single participant holds complete private key material. All re-keying broadcasts require a threshold co-signature from the controller and k_key−1 RSUs. The ablated version reverts to single-controller key generation — the controller alone generates the root key pair and holds the complete private key. Re-keying broadcasts are still threshold-co-signed (this requirement is unchanged) but the key material itself originates from and is fully known to one entity.

Set the independent variable to the number of simultaneously compromised entities and sweep through six values: 0, 1, 2, 3, 4, 5 (where entity means the controller counts as one, each RSU counts as one). In the full DKG configuration, compromising any single entity — including the controller — does not reveal the root private key because each entity only holds a share. The root key is only recoverable if t or more participants collude, where t is the DKG reconstruction threshold. In the ablated configuration, compromising the controller alone immediately reveals the complete root key, allowing fraudulent re-keying broadcasts. Record M2 (GHSR) and M11 (CFRT) at each compromise level. The full system should show no performance degradation until the number of compromised entities reaches t; the ablated system should show immediate degradation when the single compromised entity is the controller (value 1).

---

**A16 — VRF Dynamic Endorser Selection**

The full system selects endorsers per-transaction using a Verifiable Random Function. Before any RSU evaluates the VRF, a deterministic seed is committed to the blockchain bound to the transaction ID, block height, and timestamp. Each eligible RSU (those with Trj ≥ θ_RSU and sufficient interaction history) evaluates the VRF using its private key and the seed, producing a pseudorandom output with a verifiable proof. The top k_end RSUs ranked by their VRF outputs are selected as endorsers. This selection is unpredictable to an adversary before the seed is committed but verifiable by anyone afterward. The ablated version uses first-k-to-respond selection — among trust-eligible RSUs, the first k_end to respond within deadline T_q are accepted as endorsers. The trust eligibility filter is unchanged; only the selection mechanism differs.

Set the independent variable to the compromised RSU fraction — the percentage of RSUs whose trust score Trj has been driven below θ_RSU through previous misbehavior — and sweep through six values: 0%, 10%, 20%, 30%, 40%, 50%. At each fraction level, those RSUs are excluded from the eligible pool by the trust filter in both configurations. For the remaining eligible RSUs, the VRF configuration selects unpredictably while the first-k-to-respond configuration selects whichever respond fastest. In a scenario where compromised RSUs collude to respond first (fastest response time), the first-k-to-respond configuration can be gamed even if the compromised RSUs have not yet fallen below θ_RSU. Record M2 (GHSR) and M12 (EPAR — endorser pool availability rate, defined as the probability of operating in NORMAL mode as a function of the compromise fraction).

---

**A17 — Flow Rule Whitelist Governance**

The full system requires k_wl=3 RSU co-signatures before any flow rule can be added to the blockchain-stored whitelist. A controller can propose a rule addition, but the rule only becomes active after k_wl independent RSUs co-sign the proposal. A compromised controller cannot whitelist its own malicious rules. S6 detection still fires on any unapproved non-wildcard drop rule targeting safety-critical traffic. The ablated version removes the co-signature requirement for whitelist updates — the active controller can add rules to the whitelist unilaterally without any RSU co-signature. S6 detection still runs but is now ineffective against a controller that adds its own malicious rules to the whitelist before deploying them, since S6 checks absence from the whitelist as a condition.

Set the independent variable to the malicious rule injection rate and sweep through six values: 0, 4, 8, 12, 16, 20 unapproved targeted flow rules per minute injected by the compromised controller. In the full system these rules are detected by S6 (they are not in the co-signature-governed whitelist) and the controller's trust score decrements. In the ablated system the controller adds these rules to the whitelist first and then deploys them — S6 does not trigger because the whitelist check passes. Record M1 (MCC) and M3 (AVCR). The full system's MCC should remain stable as the injection rate increases. The ablated system's AVCR should decline specifically for the S6 (CP-TS) variant as that variant's signature is bypassed.

---

## Paper 3 — IEEE Transactions (Colombo Map)

---

**TX-E1 — SOTA: Compound DP+CP Mixed Attack**

This experiment tests how each system responds when attackers operate simultaneously across both the data plane and the controller plane, a scenario not tested in either Elsevier paper.

Fix N=200, v=80 km/h, ρ_a=40%, Colombo map. Total attacker penetration is fixed at p=40%. The independent variable is α_CP, the fraction of all attacker nodes assigned as controller-plane attackers. Sweep α_CP through five values: 0%, 25%, 50%, 75%, 100%. At α_CP=0% all 40% of attacking nodes execute data-plane attacks only (S1-S3). At α_CP=100% all 40% execute controller-plane attacks only (S4-S6). At intermediate values the attacker pool is split proportionally — for example at α_CP=50% half the attacker nodes execute DP attacks and the other half execute CP attacks simultaneously. Controller compromise is not a separate parameter here — the CP attackers are by definition nodes executing flow-rule injection attacks, which incrementally drives down controller trust scores as CP signatures fire.

Compare five systems: SHIELD-GH full, SHIELD-GH lightweight, B1, B2, B3. Record M1, M2, M4, M5 at each α_CP value. Produce a grouped bar chart with five groups on the x-axis (one per α_CP level) and within each group four clusters of bars (one cluster per metric), with each cluster showing all five systems. The expected pattern: B1, B2, B3 maintain reasonable performance at α_CP=0% (pure DP attacks) but collapse at α_CP values above 25% as CP attacks appear — none of the baselines have CP detection capability. SHIELD-GH lightweight degrades gracefully because it has CP signatures. SHIELD-GH full maintains coverage across the full range.

---

**TX-E2 — System-Level Ablation**

This experiment compares five complete system-level configurations, each representing a meaningful architectural choice. Unlike the component-level ablations in Papers 1 and 2 which toggle individual mechanisms, these configurations each represent a major subsystem being absent or present.

The five configurations are:

SA1 (Full SHIELD-GH) — all components active: signatures S1-S6, MATD, ZKP gate, DEBSC, LLM-FL, fusion, multi-controller architecture with M=3 controllers, DKG key generation, VRF endorser selection, PQC-LKH re-keying.

SA2 (No governance layer) — disable: multi-controller architecture (revert to single controller), DKG (revert to single-controller key generation), VRF (revert to first-k-to-respond endorser selection), PQC-LKH (revert to unicast Kyber re-keying). The substitute for each is the minimum working alternative — single controller still manages flows and issues FlowMods; unicast Kyber still re-keys remaining nodes after isolation; first-k-to-respond still selects endorsers. Detection components (signatures, MATD, LLM-FL, ZKP) are fully unchanged.

SA3 (No full-mode AI) — disable: LLM scoring (set Q_i=0.0 for all nodes), FL aggregation (static model never updated), fusion AI terms (set μ₂=0, renormalize to μ₁=0.85, μ₃=0.15). All governance components remain active. The substitute for the AI detection is the signature + reputation fusion alone.

SA4 (No ZKP gate) — disable: the ZKP gate condition in DEBSC (set zkp_gate_enabled=0). The DEBSC still evaluates the statistical reputation gate and still isolates nodes — but isolation is triggered by the statistical gate alone without requiring ZKP failure as a second condition. ZKP proofs are still generated, transmitted, and logged — only the isolation decision ignores them. All other components active.

SA5 (No MATD) — disable: MATD correction (set corrPDR=rawPDR, passing uncorrected observed PDR directly to all downstream components). All other components active including LLM, ZKP, governance.

The independent variable for TX-E2 is attack variant — run one simulation per variant per configuration, for six variants (S1-S6) × five configurations = 30 runs total. Fix N=200, v=80 km/h, p=40%, ρ_a=40%, Colombo map.

Record M1 (MCC) and M4 (FIR) for each variant-configuration combination. Produce two radar charts side by side. Each chart has six spokes (one per attack variant S1 through S6). Each chart has five overlaid closed polygons, one per SA configuration. The first chart shows M1 (MCC) — larger polygon means better detection coverage. The second chart shows M4 (FIR) — smaller polygon means fewer false isolations. Color-code each SA configuration consistently across both charts.

The expected pattern in the MCC radar: SA1 should show the largest polygon (best coverage across all six variants). SA2 should collapse on S4-S6 spokes (no governance means CP attacks are not mitigated even if detected). SA3 should collapse on S2 and S5 spokes (intermittent variants need LLM temporal reasoning). SA4 should show elevated FIR in the FIR radar because ZKP gate removal allows statistical false positives through. SA5 should show a collapsed S1 MCC spoke at high speed because MATD is not correcting handoff loss.

---

**TX-E3 and TX-E4** follow the instructions issued previously without change.