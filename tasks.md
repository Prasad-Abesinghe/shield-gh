01. Identify all design flows and send me a list of flows with suggestions to overcome them. (07/06/2026)

02. Complete the revisions sent by the supervisor and updating the report including the figures (09/06/2026)

03. Get a real world map for your simulation writing as M and SUMO. Get a dense urban map with many intersections and crosses.
State of the art implementation must be finished. You should verify that implemented state of the art  is connected to the simulation variables properly and your plots are correctly plotted.
(Scenarios group - Finish information slicing for my routing algorithm) (16/06/2026)

04. Attack detection groups should finish full blockchain implementation (and it's related all algorithms, equations) for the revised paper with full smart contract verification. Connect ns3 to blockchain and verify also by sending appropriate data from the real simulation (17/06/2026)

05. Implement all cryptographic content including key sharing (logical key hierarchy), authentication , etc. and send me evidence.  (23/06/2026)
    -- DONE (2026-07-03): scratch/shield_gh_crypto/ (standalone Python, GENUINE PQC via
       liboqs 0.15.0 Kyber-512/768 + ML-DSA-44/Dilithium-2; classical X25519/Ed25519 fallback).
       PQC-LKH logical key hierarchy (O(log N) re-key, Eq 3.34-3.36), Dilithium FlowMod auth +
       key revocation/failover (Alg 5), Pedersen+ZKP 3-state gate + DEBSC (Eq 3.29/3.30/debsc,
       Alg 6), (k,n) threshold blacklisting + Pedersen DKG + threshold re-key (Eq 3.31-3.33).
       Evidence: 31 pytest pass (27 PQC + 4 fallback, 85% core cov) + vectors/evidence_transcript.txt
       (attacker V3 detected->isolated->re-keyed-out, honest V5 spared, forged cmd rejected) +
       golden_vector.json. Run: bash scratch/shield_gh_crypto/verify_all.sh

06.01  LLM selection evidence, ML and LLM component implementation
06.02  AI/LLM model model selection results and pipeline settings to report
06.03  Implement all ML and or LLM content and send me evidence of all information (30/06/2026)

07. Integrate the full system and verify fine tuning and plot graphs for t=10 s completing with state of the arts (06/07/2026)

08. Run full simulations in HPC lab and collect results (13/07/2026)

09. Analyzing the results and writing results part of your paper as per supervisor's instructions (20/07/2026)

10. Writing discussion part of your paper supervisor's instructions (24/07/2026)

11. Writing the appendix of your paper as per supervisor's instructions (26/07/2026)

12. Submitting final report for supervisor's review (28/07/2026)

13. Addressing all supervisor's comments and resubmit for revise (04/08/2026)

14. Addressing all supervisor's comments and resubmit for revise (06/08/2026)

15. Creating graphical improvements for your demo. .... A GUI for the demo (10/08/2026)

16. Create final presentation (12/08/2026)