// ============================================================
// SOA2 SCBC/VCBC chaincode — formal unit tests (no running Fabric).
// Verifies Alg. 1-5 of Alabdulatif et al. against an in-memory ledger fake.
//
// Run:  go test -v -cover ./...
// ============================================================
package main

import (
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
)

// ── In-memory fake stub (implements only what the contract uses) ────────────
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

// ── Fake transaction context returning the fake stub ────────────────────────
type fakeCtx struct {
	contractapi.TransactionContextInterface
	stub *fakeStub
}

func (c *fakeCtx) GetStub() shim.ChaincodeStubInterface { return c.stub }

func newCtx() (*fakeCtx, *SCBCVCBCContract) {
	return &fakeCtx{stub: newFakeStub()}, &SCBCVCBCContract{}
}

// ── Alg.3 classification truth table ────────────────────────────────────────
func TestClassify(t *testing.T) {
	cases := []struct {
		name              string
		delivered, notDel int
		wantStatus        string
	}{
		{"black-drops-all", 0, 10, "black"},     // rating 0
		{"grey-partial", 3, 7, "grey"},          // rating 30 <= 50
		{"grey-at-threshold", 5, 5, "grey"},     // rating 50, not > 50
		{"white-good", 9, 1, "white"},           // rating 90 > 50
		{"white-no-relays", 0, 0, "white"},      // initially white
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := classify(tc.delivered, tc.notDel, defaultThreshold)
			if got != tc.wantStatus {
				t.Fatalf("classify(%d,%d) status = %q, want %q",
					tc.delivered, tc.notDel, got, tc.wantStatus)
			}
		})
	}
}

func TestCommitAndRead(t *testing.T) {
	ctx, cc := newCtx()
	if err := cc.CommitRelayRecord(ctx, "node5", 40, 60, 1); err != nil {
		t.Fatal(err)
	}
	rec, err := cc.ReadNode(ctx, "node5")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "grey" { // rating 40 <= 50
		t.Fatalf("got status %q want grey", rec.Status)
	}
	if rec.Rating != 40.0 {
		t.Fatalf("got rating %v want 40", rec.Rating)
	}
}

func TestReadMissing(t *testing.T) {
	ctx, cc := newCtx()
	if _, err := cc.ReadNode(ctx, "ghost"); err == nil {
		t.Fatal("expected error reading nonexistent node")
	}
}

// ── Alg.1 SCBC: classifies every node by delivered ratio ────────────────────
func TestRunSCBC(t *testing.T) {
	ctx, cc := newCtx()
	cc.CommitRelayRecord(ctx, "honest", 95, 5, 0)   // white
	cc.CommitRelayRecord(ctx, "black", 0, 50, 1)    // black
	cc.CommitRelayRecord(ctx, "grey", 20, 80, 1)    // grey

	nodes, err := cc.RunSCBC(ctx, defaultThreshold)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"honest": "white", "black": "black", "grey": "grey"}
	if len(nodes) != 3 {
		t.Fatalf("got %d nodes want 3", len(nodes))
	}
	for _, n := range nodes {
		if want[n.NodeID] != n.Status {
			t.Fatalf("node %s status %q want %q", n.NodeID, n.Status, want[n.NodeID])
		}
	}
}

// ── Alg.4 makeVoting + Alg.5 VCBC: pre-filters by miner reputation ──────────
func TestRunVCBC(t *testing.T) {
	ctx, cc := newCtx()
	cc.CommitRelayRecord(ctx, "honest", 90, 10, 0)
	cc.CommitRelayRecord(ctx, "blackvote", 0, 50, 1)
	cc.CommitRelayRecord(ctx, "greyvote", 30, 70, 1)
	// miner prior votes
	cc.SetReputation(ctx, "honest", "w")
	cc.SetReputation(ctx, "blackvote", "b")
	cc.SetReputation(ctx, "greyvote", "g")

	survivors, err := cc.RunVCBC(ctx, defaultThreshold)
	if err != nil {
		t.Fatal(err)
	}
	// Only the white-voted honest node should survive the voting pre-filter.
	if len(survivors) != 1 || survivors[0].NodeID != "honest" {
		t.Fatalf("VCBC voting kept %v, want only [honest]", survivors)
	}
	if survivors[0].Status != "white" {
		t.Fatalf("survivor status %q want white", survivors[0].Status)
	}
}

func TestMakeVotingUnit(t *testing.T) {
	in := []*NodeRecord{
		{NodeID: "a", Reputation: "w"},
		{NodeID: "b", Reputation: "g"},
		{NodeID: "c", Reputation: "b"},
		{NodeID: "d", Reputation: ""}, // unknown -> kept
	}
	out := makeVoting(in)
	if len(out) != 2 {
		t.Fatalf("got %d survivors want 2", len(out))
	}
	if !strings.Contains(out[0].NodeID+out[1].NodeID, "a") {
		t.Fatalf("expected node a to survive voting")
	}
}

func TestGetAllNodesSorted(t *testing.T) {
	ctx, cc := newCtx()
	cc.CommitRelayRecord(ctx, "node3", 1, 1, 0)
	cc.CommitRelayRecord(ctx, "node1", 1, 1, 0)
	cc.CommitRelayRecord(ctx, "node2", 1, 1, 0)
	all, err := cc.GetAllNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if all[0].NodeID != "node1" || all[2].NodeID != "node3" {
		t.Fatalf("GetAllNodes not sorted: %v", all)
	}
}
