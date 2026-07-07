// ============================================================
// SHIELD-GH — unit tests for VRF-Based Dynamic Endorser Selection
// (Supervisor Revision Block 15). Uses the same in-memory fakeStub
// pattern as debsc_test.go; no running Fabric needed.
// ============================================================
package main

import (
	"strconv"
	"testing"

	"github.com/golang/protobuf/ptypes/timestamp"
)

// The fakeStub in debsc_test.go embeds shim.ChaincodeStubInterface, so
// GetTxID/GetTxTimestamp resolve to nil methods and would panic. Provide them
// here (same package) so SelectEndorsers can run under test.
func (s *fakeStub) GetTxID() string { return "tx-unit-test" }
func (s *fakeStub) GetTxTimestamp() (*timestamp.Timestamp, error) {
	return &timestamp.Timestamp{Seconds: 1_700_000_000}, nil
}

// helper: register a batch of RSUs on the fake ledger.
func regRSUs(t *testing.T, cc *DEBSCContract, c *fakeCtx, rsus []RSURecord) {
	t.Helper()
	for _, r := range rsus {
		if err := cc.RegisterRSU(c, r.RSUID, r.PubKey, r.Trust, r.NumInter); err != nil {
			t.Fatalf("RegisterRSU %s: %v", r.RSUID, err)
		}
	}
}

// NORMAL mode at 64-RSU deployment scale: k_end scales with the pool
// (ceil(|E|·α_end)), giving a real BFT quorum — NOT a fixed tiny set.
func TestSelectEndorsers_NormalModeAtScale(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	// 64 eligible RSUs (trust ≥ θ_RSU, interactions ≥ N_min).
	var rsus []RSURecord
	for i := 1; i <= 64; i++ {
		rsus = append(rsus, RSURecord{
			RSUID: "rsu" + strconv.Itoa(i), PubKey: "pk" + strconv.Itoa(i),
			Trust: 0.9, NumInter: 10,
		})
	}
	regRSUs(t, cc, c, rsus)

	sel, err := cc.SelectEndorsers(c, "txScale")
	if err != nil {
		t.Fatalf("SelectEndorsers: %v", err)
	}
	if sel.Mode != "NORMAL" {
		t.Fatalf("mode = %s, want NORMAL", sel.Mode)
	}
	if sel.EligibleN != 64 {
		t.Fatalf("|E| = %d, want 64", sel.EligibleN)
	}
	// k_end = max(10, ceil(64*0.34)) = max(10, 22) = 22
	if sel.KEnd != 22 {
		t.Fatalf("k_end = %d, want 22 (scales with 64-RSU pool)", sel.KEnd)
	}
	if len(sel.Selected) != 22 {
		t.Fatalf("selected = %d, want 22", len(sel.Selected))
	}
	// f_max = floor((64-1)/3) = 21; k_end(22) > f_max(21) → honest majority.
	if sel.FMax != 21 {
		t.Fatalf("f_max = %d, want 21", sel.FMax)
	}
	for _, e := range sel.Selected {
		if !e.Verify {
			t.Fatalf("endorser %s VRF proof failed to verify", e.RSUID)
		}
	}
}

// k_min floor: at least 10 endorsers whenever the pool is large enough,
// even if α_end·|E| would round lower.
func TestSelectEndorsers_KMinFloor(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	// 15 eligible → ceil(15*0.34)=6, but k_min=10 floor applies.
	var rsus []RSURecord
	for i := 1; i <= 15; i++ {
		rsus = append(rsus, RSURecord{
			RSUID: "r" + strconv.Itoa(i), PubKey: "p" + strconv.Itoa(i),
			Trust: 0.8, NumInter: 8,
		})
	}
	regRSUs(t, cc, c, rsus)
	sel, _ := cc.SelectEndorsers(c, "txFloor")
	if sel.KEnd != 10 {
		t.Fatalf("k_end = %d, want 10 (k_min floor)", sel.KEnd)
	}
	if sel.Mode != "NORMAL" || len(sel.Selected) != 10 {
		t.Fatalf("mode=%s selected=%d, want NORMAL/10", sel.Mode, len(sel.Selected))
	}
}

// Determinism: same seed inputs → same selection (VRF is deterministic per seed).
func TestSelectEndorsers_Deterministic(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	regRSUs(t, cc, c, []RSURecord{
		{RSUID: "a", PubKey: "pka", Trust: 0.8, NumInter: 5},
		{RSUID: "b", PubKey: "pkb", Trust: 0.8, NumInter: 5},
		{RSUID: "cc", PubKey: "pkc", Trust: 0.8, NumInter: 5},
		{RSUID: "d", PubKey: "pkd", Trust: 0.8, NumInter: 5},
	})
	s1, _ := cc.SelectEndorsers(c, "sameTx")
	s2, _ := cc.SelectEndorsers(c, "sameTx")
	if len(s1.Selected) != len(s2.Selected) {
		t.Fatalf("nondeterministic set size")
	}
	for i := range s1.Selected {
		if s1.Selected[i].RSUID != s2.Selected[i].RSUID {
			t.Fatalf("nondeterministic selection at %d: %s vs %s",
				i, s1.Selected[i].RSUID, s2.Selected[i].RSUID)
		}
	}
	// different tx id → different seed → (very likely) different ordering
	s3, _ := cc.SelectEndorsers(c, "otherTx")
	if s1.Seed == s3.Seed {
		t.Fatalf("seed should differ across tx ids")
	}
}

// Eligibility filter (Eq.endorser_pool): low-trust or under-observed RSUs excluded.
func TestSelectEndorsers_EligibilityFilter(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	regRSUs(t, cc, c, []RSURecord{
		{RSUID: "good1", PubKey: "p1", Trust: 0.9, NumInter: 10}, // eligible
		{RSUID: "good2", PubKey: "p2", Trust: 0.6, NumInter: 4},  // eligible
		{RSUID: "good3", PubKey: "p3", Trust: 0.7, NumInter: 3},  // eligible
		{RSUID: "lowtrust", PubKey: "p4", Trust: 0.3, NumInter: 10}, // trust < θ_RSU
		{RSUID: "newbie", PubKey: "p5", Trust: 0.9, NumInter: 1},    // |H| < N_min
	})
	sel, _ := cc.SelectEndorsers(c, "txF")
	if sel.EligibleN != 3 {
		t.Fatalf("|E| = %d, want 3 (2 filtered out)", sel.EligibleN)
	}
	for _, e := range sel.Selected {
		if e.RSUID == "lowtrust" || e.RSUID == "newbie" {
			t.Fatalf("ineligible RSU %s was selected", e.RSUID)
		}
	}
}

// RELAXED mode: pool below k_end but ≥ k_min → all eligible endorse.
// Just above the floor: exactly k_min=10 eligible → NORMAL with 10 endorsers.
func TestSelectEndorsers_AtKMinBoundary(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	var rsus []RSURecord
	for i := 1; i <= 10; i++ {
		rsus = append(rsus, RSURecord{RSUID: "r" + strconv.Itoa(i),
			PubKey: "p" + strconv.Itoa(i), Trust: 0.8, NumInter: 8})
	}
	regRSUs(t, cc, c, rsus)
	sel, _ := cc.SelectEndorsers(c, "txBound")
	// |E|=10 == k_min == k_end → NORMAL, exactly 10 endorsers.
	if sel.Mode != "NORMAL" || sel.KEnd != 10 || len(sel.Selected) != 10 {
		t.Fatalf("mode=%s k_end=%d selected=%d, want NORMAL/10/10",
			sel.Mode, sel.KEnd, len(sel.Selected))
	}
}

// DEFERRED mode: 0 < |E| < k_min(10) → contain + defer.
func TestSelectEndorsers_DeferredMode(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	// 9 eligible (< k_min=10) → DEFERRED.
	var rsus []RSURecord
	for i := 1; i <= 9; i++ {
		rsus = append(rsus, RSURecord{RSUID: "a" + strconv.Itoa(i),
			PubKey: "pa" + strconv.Itoa(i), Trust: 0.9, NumInter: 5})
	}
	regRSUs(t, cc, c, rsus)
	sel, _ := cc.SelectEndorsers(c, "txD")
	if sel.Mode != "DEFERRED" || sel.EligibleN != 9 {
		t.Fatalf("mode=%s |E|=%d, want DEFERRED/9", sel.Mode, sel.EligibleN)
	}
}

// EMERGENCY mode: no eligible RSU → single highest-trust emergency endorser.
func TestSelectEndorsers_EmergencyMode(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	regRSUs(t, cc, c, []RSURecord{
		{RSUID: "low1", PubKey: "p1", Trust: 0.3, NumInter: 10},
		{RSUID: "low2", PubKey: "p2", Trust: 0.45, NumInter: 10}, // highest, still < θ
	})
	sel, _ := cc.SelectEndorsers(c, "txE")
	if sel.Mode != "EMERGENCY" {
		t.Fatalf("mode = %s, want EMERGENCY", sel.Mode)
	}
	if len(sel.Selected) != 1 || sel.Selected[0].RSUID != "low2" {
		t.Fatalf("emergency endorser = %v, want [low2]", sel.Selected)
	}
}

// VRF.Verify (Eq.vrf_verify): tampered β must fail verification.
func TestVRFVerify_TamperFails(t *testing.T) {
	beta, proof := vrfEval("pkX", "seed123")
	if !vrfVerify("pkX", "seed123", beta, proof) {
		t.Fatalf("honest VRF output should verify")
	}
	if vrfVerify("pkX", "seed123", beta[:60]+"deadbeef", proof) {
		t.Fatalf("tampered β must NOT verify")
	}
	if vrfVerify("pkOTHER", "seed123", beta, proof) {
		t.Fatalf("wrong public key must NOT verify")
	}
}
