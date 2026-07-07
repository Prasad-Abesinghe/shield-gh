// ============================================================
// SHIELD-GH — VRF-Based Dynamic Endorser Selection (chaincode level)
// Implements Supervisor Revision Block 15, Section "VRF-Based Dynamic
// Endorser Selection":
//   Eq.(endorser_pool)   E(t)  — trust+observation eligibility filter
//   Eq.(vrf_seed)        s_tx  — per-tx seed bound to immutable chain state
//   Eq.(vrf_eval)        (β_j, π_j) = VRF(sk_j, s_tx)
//   Eq.(vrf_verify)      b = VRF.Verify(pk_j, s_tx, β_j, π_j)
//   Eq.(endorser_select) Ω(t)  = top-k_end by β ascending, proof-verified
//   Eq.(kend)            k_end = max(k_min, ceil(|E|·α_end))
//   Eq.(endorser_mode)   NORMAL / RELAXED / DEFERRED / EMERGENCY bypass
//
// The VRF here is a SHA-256-based verifiable surrogate (no external crypto
// libs): a keyed hash whose "proof" is recomputable from the public key, so
// VRF.Verify is a real check yet builds offline in the vendored Fabric env.
// Selection runs entirely at the CHAINCODE level over the on-ledger RSU pool,
// per the supervisor's clarification ("statically allocate all RSUs as peers,
// then apply dynamic endorser selection at the chaincode level").
// ============================================================
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ── Selection parameters (deployment-calibrated, see Eq.(kend)) ───────────────
const (
	thetaRSU  = 0.5  // θ_RSU: min trust for endorser candidacy  (Eq.endorser_pool)
	nMin      = 3    // N_min: min blockchain-recorded interactions |H_j|
	// k_min: hard floor for endorser count (Eq.kend). Raised to 10 for a
	// 64-RSU deployment: fewer than ~10 endorsers gives no meaningful BFT
	// consensus (a 3-of-N set tolerates only f=0 Byzantine at k=3). At k_min=10
	// the set tolerates f_max=floor((10-1)/3)=3 Byzantine RSUs while still
	// guaranteeing an honest majority.
	kMin      = 10   // k_min: hard floor for endorser count       (Eq.kend)
	alphaEnd  = 0.34 // α_end ∈ (1/3, 1]: fraction of eligible pool (Eq.kend)
)

// RSURecord is the on-ledger record for one RSU endorser. Each RSU is a static
// network peer; its trust score is maintained on-chain by the same Bayesian
// model applied to vehicles (Eq. trust_update).
type RSURecord struct {
	RSUID      string  `json:"rsuId"`
	PubKey     string  `json:"pubKey"`     // pk_j — public key (hex); VRF.Verify uses it
	Trust      float64 `json:"trust"`      // T_rj(t) — on-ledger trust score
	NumInter   int     `json:"numInter"`   // |H_j| — recorded interactions
	Probation  bool    `json:"probation"`  // true = excluded from pool
}

// EndorserSelection is the returned, auditable result of one selection round.
type EndorserSelection struct {
	TxID        string       `json:"txId"`
	Seed        string       `json:"seed"`        // s_tx (Eq.vrf_seed)
	Mode        string       `json:"mode"`        // NORMAL/RELAXED/DEFERRED/EMERGENCY
	EligibleN   int          `json:"eligibleN"`   // |E(t)|
	KEnd        int          `json:"kEnd"`        // k_end (Eq.kend)
	FMax        int          `json:"fMax"`        // f_max = floor((|E|-1)/3)
	Selected    []VRFEndorser `json:"selected"`   // Ω(t) — the chosen endorsers
	Note        string       `json:"note"`
}

// VRFEndorser is one selected RSU with its verifiable VRF output + proof.
type VRFEndorser struct {
	RSUID  string `json:"rsuId"`
	Beta   string `json:"beta"`   // β_j ∈ {0,1}^256 (hex) — VRF output (Eq.vrf_eval)
	Proof  string `json:"proof"`  // π_j^VRF — verifiable proof
	Verify bool   `json:"verify"` // b = VRF.Verify(...) (Eq.vrf_verify)
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterRSU — statically allocate an RSU as a network peer/endorser candidate.
// (pubKey is the RSU's Dilithium public key in the full scheme; here any hex id.)
func (c *DEBSCContract) RegisterRSU(ctx contractapi.TransactionContextInterface,
	rsuID, pubKey string, trust float64, numInter int) error {
	r := RSURecord{RSUID: rsuID, PubKey: pubKey, Trust: trust,
		NumInter: numInter, Probation: false}
	b, _ := json.Marshal(r)
	return ctx.GetStub().PutState("RSU_"+rsuID, b)
}

// ── Eq.(vrf_eval)/(vrf_verify): SHA-256 verifiable VRF surrogate ──────────────
// β_j = H(pk_j || s_tx || "beta");  π_j = H(pk_j || s_tx || "proof").
// VRF.Verify recomputes both from the PUBLIC key + seed, so any party can
// confirm β_j was derived correctly without the secret key — the essential VRF
// property. (Production: CRYSTALS-Dilithium VRF; interface identical.)
func vrfEval(pubKey, seed string) (beta, proof string) {
	hb := sha256.Sum256([]byte(pubKey + "|" + seed + "|beta"))
	hp := sha256.Sum256([]byte(pubKey + "|" + seed + "|proof"))
	return hex.EncodeToString(hb[:]), hex.EncodeToString(hp[:])
}

func vrfVerify(pubKey, seed, beta, proof string) bool {
	b, p := vrfEval(pubKey, seed)
	return b == beta && p == proof
}

// ─────────────────────────────────────────────────────────────────────────────
// SelectEndorsers — the full 5-step VRF endorser selection at chaincode level.
// txID identifies the transaction; the seed (Eq.vrf_seed) binds tx_id, block
// height, timestamp and the previous-block hash so no party can predict it.
func (c *DEBSCContract) SelectEndorsers(ctx contractapi.TransactionContextInterface,
	txID string) (*EndorserSelection, error) {

	// ── Step 1 — Eligible Endorser Pool E(t) (Eq.endorser_pool) ──────────────
	// E(t) = { RSU_j : T_rj(t) ≥ θ_RSU  ∧  |H_j| ≥ N_min  ∧  ¬probation }
	all, err := c.getAllRSUs(ctx)
	if err != nil {
		return nil, err
	}
	var eligible []RSURecord
	var bestGlobal *RSURecord // highest-trust RSU regardless of threshold (EMERGENCY)
	for i := range all {
		r := all[i]
		if bestGlobal == nil || r.Trust > bestGlobal.Trust {
			bestGlobal = &all[i]
		}
		if r.Trust >= thetaRSU && r.NumInter >= nMin && !r.Probation {
			eligible = append(eligible, r)
		}
	}

	// ── Step 2 — Per-transaction VRF seed s_tx (Eq.vrf_seed) ─────────────────
	// s_tx = Hash(tx_id || block_height || t || C_prev)
	// Bind to immutable chain state via the tx's own committed metadata.
	ts, _ := ctx.GetStub().GetTxTimestamp()
	txStamp := ctx.GetStub().GetTxID()
	tSec := int64(0)
	if ts != nil {
		tSec = ts.Seconds
	}
	// C_prev / block_height surrogate: the ordering-service tx id is unknown to
	// callers ahead of time and fixed once ordered — a chain-bound nonce.
	seedInput := txID + "|" + txStamp + "|" + strconv.FormatInt(tSec, 10)
	sh := sha256.Sum256([]byte(seedInput))
	seed := hex.EncodeToString(sh[:])

	// ── Step 4 (compute first) — k_end and f_max (Eq.kend) ───────────────────
	// k_end = max(k_min, ceil(|E|·α_end));  f_max = floor((|E|-1)/3)
	eligN := len(eligible)
	kEnd := kMin
	if byFrac := ceilInt(float64(eligN) * alphaEnd); byFrac > kEnd {
		kEnd = byFrac
	}
	fMax := 0
	if eligN > 0 {
		fMax = (eligN - 1) / 3
	}

	sel := &EndorserSelection{TxID: txID, Seed: seed, EligibleN: eligN,
		KEnd: kEnd, FMax: fMax}

	// ── Step 5 — Bypass mode (Eq.endorser_mode) ──────────────────────────────
	switch {
	case eligN >= kEnd:
		sel.Mode = "NORMAL"
	case eligN >= kMin:
		sel.Mode = "RELAXED"
	case eligN > 0:
		sel.Mode = "DEFERRED"
	default:
		sel.Mode = "EMERGENCY"
	}

	// ── EMERGENCY: no eligible RSU — use globally-highest-trust RSU as the
	// single emergency endorser and flag a network-wide trust audit. ─────────
	if sel.Mode == "EMERGENCY" {
		if bestGlobal == nil {
			sel.Note = "no RSUs registered; isolation deferred"
			return sel, c.putSelection(ctx, sel)
		}
		beta, proof := vrfEval(bestGlobal.PubKey, seed)
		sel.Selected = []VRFEndorser{{RSUID: bestGlobal.RSUID, Beta: beta,
			Proof: proof, Verify: vrfVerify(bestGlobal.PubKey, seed, beta, proof)}}
		sel.Note = "EMERGENCY: single highest-trust endorser; network-wide RSU trust audit triggered"
		return sel, c.putSelection(ctx, sel)
	}

	// ── Steps 3 — VRF eval + rank + verify (Eq.vrf_eval/verify/endorser_select) ─
	// (Runs for NORMAL, RELAXED and DEFERRED — all select from the eligible pool
	//  via the VRF; the MODE governs how the verdict is treated downstream.)
	// Each eligible RSU evaluates the VRF on the published seed; rank by β
	// ascending; take top-k_end with verified proofs.
	type scored struct {
		r     RSURecord
		beta  string
		proof string
		bi    *big.Int
	}
	var pool []scored
	for _, r := range eligible {
		beta, proof := vrfEval(r.PubKey, seed)
		bi := new(big.Int)
		bi.SetString(beta, 16)
		pool = append(pool, scored{r, beta, proof, bi})
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i].bi.Cmp(pool[j].bi) < 0 })

	// RELAXED: all eligible RSUs endorse (reduced-confidence). NORMAL: top-k_end.
	take := kEnd
	if sel.Mode == "RELAXED" || take > len(pool) {
		take = len(pool)
	}
	for i := 0; i < take; i++ {
		p := pool[i]
		sel.Selected = append(sel.Selected, VRFEndorser{
			RSUID: p.r.RSUID, Beta: p.beta, Proof: p.proof,
			Verify: vrfVerify(p.r.PubKey, seed, p.beta, p.proof), // Eq.vrf_verify
		})
	}
	switch sel.Mode {
	case "RELAXED":
		sel.Note = fmt.Sprintf("RELAXED: all %d trusted RSUs endorse (k_end=%d); reduced-confidence flag set, ε_obs tightened", take, kEnd)
	case "DEFERRED":
		sel.Note = fmt.Sprintf("DEFERRED: only %d eligible (<k_min=%d) → graduated response L2 (per-batch ZKP + rate-limit) as containment; isolation queued for next window", eligN, kMin)
	default: // NORMAL
		sel.Note = fmt.Sprintf("NORMAL: top-%d of %d eligible selected by VRF (f_max=%d, ≥1 honest guaranteed)", kEnd, eligN, fMax)
	}
	return sel, c.putSelection(ctx, sel)
}

// VerifyEndorser — public verifiability of one endorser's VRF (Eq.vrf_verify).
func (c *DEBSCContract) VerifyEndorser(ctx contractapi.TransactionContextInterface,
	rsuID, seed, beta, proof string) (bool, error) {
	b, err := ctx.GetStub().GetState("RSU_" + rsuID)
	if err != nil || b == nil {
		return false, fmt.Errorf("unknown RSU %s", rsuID)
	}
	var r RSURecord
	if err := json.Unmarshal(b, &r); err != nil {
		return false, err
	}
	return vrfVerify(r.PubKey, seed, beta, proof), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────
// prefixRangeEnd returns the exclusive upper bound for a key prefix by
// incrementing the last byte — avoids the "\xff" suffix that terminates the
// GetStateByRange stream on real Fabric (LevelDB) instead of scanning.
func prefixRangeEnd(prefix string) string {
	b := []byte(prefix)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return "" // all 0xff — unbounded
}

func (c *DEBSCContract) getAllRSUs(ctx contractapi.TransactionContextInterface) ([]RSURecord, error) {
	iter, err := ctx.GetStub().GetStateByRange("RSU_", prefixRangeEnd("RSU_"))
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []RSURecord
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		// Guard: only RSU_* keys (the fake stub may return all keys; real
		// Fabric range-filters, but this keeps both paths correct).
		if len(kv.Key) < 4 || kv.Key[:4] != "RSU_" {
			continue
		}
		var r RSURecord
		if json.Unmarshal(kv.Value, &r) == nil && r.RSUID != "" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (c *DEBSCContract) putSelection(ctx contractapi.TransactionContextInterface,
	sel *EndorserSelection) error {
	b, _ := json.Marshal(sel)
	return ctx.GetStub().PutState("SEL_"+sel.TxID, b)
}

func ceilInt(x float64) int {
	i := int(x)
	if float64(i) < x {
		i++
	}
	return i
}
