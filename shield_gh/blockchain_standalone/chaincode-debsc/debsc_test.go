// ============================================================
// SHIELD-GH DEBSC — Formal unit tests with dummy data
// Verifies the smart contract's functional correctness against a
// self-contained in-memory ledger fake (no running Fabric needed).
//
// Run:  go test -v ./...
//
// Covers every chaincode function and the Eq. 3.19 dual-gate truth table:
//   (1-Ri)>θR  ×  ZKP-fail  →  {MONITOR, MONITOR, MONITOR, ISOLATE}
// ============================================================
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
)

// ── In-memory fake of the chaincode stub (implements only what DEBSC uses) ──
// Embeds shim.ChaincodeStubInterface so the type satisfies the interface; any
// method the contract does NOT use stays nil and is never called by these tests.
type fakeStub struct {
	shim.ChaincodeStubInterface
	state map[string][]byte
}

func newFakeStub() *fakeStub { return &fakeStub{state: map[string][]byte{}} }

func (s *fakeStub) PutState(k string, v []byte) error { s.state[k] = v; return nil }
func (s *fakeStub) GetState(k string) ([]byte, error) { return s.state[k], nil }

func (s *fakeStub) GetStateByRange(start, end string) (shim.StateQueryIteratorInterface, error) {
	it := &fakeIterator{}
	for k, v := range s.state {
		it.kvs = append(it.kvs, kv{k, v})
	}
	return it, nil
}

// ── In-memory iterator fake ─────────────────────────────────────────────────
type kv struct {
	k string
	v []byte
}
type fakeIterator struct {
	shim.StateQueryIteratorInterface
	kvs []kv
	pos int
}

func (it *fakeIterator) HasNext() bool { return it.pos < len(it.kvs) }
func (it *fakeIterator) Next() (*queryresult.KV, error) {
	cur := it.kvs[it.pos]
	it.pos++
	return &queryresult.KV{Key: cur.k, Value: cur.v}, nil
}
func (it *fakeIterator) Close() error { return nil }

// ── Fake transaction context returning our fake stub ────────────────────────
type fakeCtx struct {
	contractapi.TransactionContextInterface
	stub *fakeStub
}

func (c *fakeCtx) GetStub() shim.ChaincodeStubInterface { return c.stub }

func newCtx() *fakeCtx { return &fakeCtx{stub: newFakeStub()} }

// ── Helpers ─────────────────────────────────────────────────────────────────
func readRec(t *testing.T, c *fakeCtx, id string) NodeRecord {
	t.Helper()
	b := c.stub.state[id]
	if b == nil {
		t.Fatalf("record %s not found on ledger", id)
	}
	var r NodeRecord
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("unmarshal %s: %v", id, err)
	}
	return r
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

// CommitForwardingRecord must derive reputation, ZKP validity and suspicion
// correctly from dummy (nFwd, nRx) inputs.
func TestCommitForwardingRecord_DummyData(t *testing.T) {
	cc := &DEBSCContract{}

	cases := []struct {
		name           string
		nFwd, nRx      int
		wantRep        float64
		wantZKP        bool
		wantSuspicion  int
	}{
		{"perfect honest", 100, 100, 1.0, true, 0},
		{"mild loss honest", 98, 100, 0.98, false, 0}, // ZKP strict: fwd!=rx
		{"grey hole 60% drop", 40, 100, 0.40, false, 1},
		{"total black hole", 0, 100, 0.0, false, 1},
		{"no traffic", 0, 0, 1.0, true, 0}, // nRx=0 -> rep 1.0; ZKP trivially valid (0==0)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCtx()
			if err := cc.CommitForwardingRecord(c, "n", tc.nFwd, tc.nRx); err != nil {
				t.Fatalf("commit failed: %v", err)
			}
			r := readRec(t, c, "n")
			if r.Reputation != tc.wantRep {
				t.Errorf("reputation: got %.3f want %.3f", r.Reputation, tc.wantRep)
			}
			if r.ZKPValid != tc.wantZKP {
				t.Errorf("zkpValid: got %v want %v", r.ZKPValid, tc.wantZKP)
			}
			if r.SuspicionLvl != tc.wantSuspicion {
				t.Errorf("suspicion: got %d want %d", r.SuspicionLvl, tc.wantSuspicion)
			}
		})
	}
}

// EvaluateIsolation must implement the Eq. 3.19 dual-gate truth table exactly:
// ISOLATE only when (1-Ri)>θR AND ZKP failed; otherwise MONITOR.
func TestEvaluateIsolation_DualGateTruthTable(t *testing.T) {
	cc := &DEBSCContract{}
	const thetaR = 0.4

	cases := []struct {
		name      string
		nFwd, nRx int
		expect    string // substring expected in the result
	}{
		// statGate=F, zkp ok      -> MONITOR  (honest)
		{"honest perfect", 100, 100, "MONITOR"},
		// statGate=F, zkp fail    -> MONITOR  (mild loss, reputation still high)
		{"mild loss", 95, 100, "MONITOR"},
		// statGate=T, zkp fail    -> ISOLATE  (grey hole: BOTH gates)
		{"grey hole", 40, 100, "ISOLATE"},
		// statGate=T, zkp fail    -> ISOLATE  (black hole)
		{"black hole", 0, 100, "ISOLATE"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCtx()
			if err := cc.CommitForwardingRecord(c, "x", tc.nFwd, tc.nRx); err != nil {
				t.Fatalf("commit: %v", err)
			}
			res, err := cc.EvaluateIsolation(c, "x", thetaR)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !strings.Contains(res, tc.expect) {
				t.Errorf("got %q, want it to contain %q", res, tc.expect)
			}
		})
	}
}

// A node that fails the statistical gate but keeps a VALID ZKP must NOT be
// isolated — this is the false-positive protection for honest mobile vehicles.
func TestEvaluateIsolation_StatGateButValidZKP_NotIsolated(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()

	// Manually craft a record: low reputation (stat gate fires) but ZKP valid.
	rec := NodeRecord{NodeID: "mobile", NFwd: 50, NRx: 100, Reputation: 0.5, ZKPValid: true}
	b, _ := json.Marshal(rec)
	c.stub.state["mobile"] = b

	res, err := cc.EvaluateIsolation(c, "mobile", 0.4)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !strings.Contains(res, "MONITOR") {
		t.Errorf("honest-but-mobile node should be MONITOR, got %q", res)
	}
}

// Isolation decision must be PERSISTED on the ledger after an isolate verdict.
func TestEvaluateIsolation_PersistsIsolatedFlag(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	_ = cc.CommitForwardingRecord(c, "ghost", 30, 100) // grey hole
	if _, err := cc.EvaluateIsolation(c, "ghost", 0.4); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	r := readRec(t, c, "ghost")
	if !r.Isolated {
		t.Errorf("attacker should be isolated=true on ledger, got false")
	}
}

// EvaluateIsolation on an unknown node must return MONITOR, not error.
func TestEvaluateIsolation_UnknownNode(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	res, err := cc.EvaluateIsolation(c, "nobody", 0.4)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !strings.Contains(res, "MONITOR") {
		t.Errorf("unknown node should be MONITOR, got %q", res)
	}
}

// GetAllNodes must return every committed record (ledger-wide query).
func TestGetAllNodes(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	_ = cc.CommitForwardingRecord(c, "a", 100, 100)
	_ = cc.CommitForwardingRecord(c, "b", 30, 100)
	_ = cc.CommitForwardingRecord(c, "c", 70, 100)

	all, err := cc.GetAllNodes(c)
	if err != nil {
		t.Fatalf("getall: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 records, got %d", len(all))
	}
}

// InitLedger must seed the demo records without error.
func TestInitLedger(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()
	if err := cc.InitLedger(c); err != nil {
		t.Fatalf("init: %v", err)
	}
	if len(c.stub.state) != 2 {
		t.Errorf("expected 2 seeded nodes, got %d", len(c.stub.state))
	}
}

// ReadNode must error on a missing node and return the record for an existing one.
func TestReadNode(t *testing.T) {
	cc := &DEBSCContract{}
	c := newCtx()

	if _, err := cc.ReadNode(c, "missing"); err == nil {
		t.Errorf("expected error reading missing node")
	}

	_ = cc.CommitForwardingRecord(c, "real", 80, 100)
	r, err := cc.ReadNode(c, "real")
	if err != nil {
		t.Fatalf("read real: %v", err)
	}
	if r.NodeID != "real" || r.NFwd != 80 || r.NRx != 100 {
		t.Errorf("unexpected record: %+v", r)
	}
}
