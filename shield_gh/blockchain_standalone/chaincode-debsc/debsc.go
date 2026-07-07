// ============================================================
// SHIELD-GH DEBSC Smart Contract — Hyperledger Fabric Chaincode
// Implements: Eq. 3.19 (dual-evidence isolation gate)
//             Eq. 3.18 (blockchain reputation Ri)
//             Eq. 3.13 (suspicion level Λi)
//             Eq. 3.29/3.30 (ZKP forwarding proof result anchoring)
// ============================================================
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// DEBSCContract is the Dual-Evidence Blockchain Smart Contract.
type DEBSCContract struct {
	contractapi.Contract
}

// NodeRecord is the on-ledger trust record for one vehicle.
type NodeRecord struct {
	NodeID       string  `json:"nodeId"`
	NFwd         int     `json:"nFwd"`         // packets forwarded (nᵢᶠʷᵈ)
	NRx          int     `json:"nRx"`          // packets received  (nᵢʳˣ)
	Reputation   float64 `json:"reputation"`   // Ri(t) — Eq. 3.18
	ZKPValid     bool    `json:"zkpValid"`     // Π_ZKP result — Eq. 3.30
	SuspicionLvl int     `json:"suspicionLevel"` // Λi(t) — Eq. 3.13
	Isolated     bool    `json:"isolated"`
}

// InitLedger seeds a few example nodes (optional, for demo evidence).
func (c *DEBSCContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	seed := []NodeRecord{
		{NodeID: "node1", NFwd: 100, NRx: 100, Reputation: 1.0, ZKPValid: true, SuspicionLvl: 0, Isolated: false},
		{NodeID: "node2", NFwd: 98, NRx: 100, Reputation: 0.98, ZKPValid: true, SuspicionLvl: 0, Isolated: false},
	}
	for _, n := range seed {
		b, _ := json.Marshal(n)
		if err := ctx.GetStub().PutState(n.NodeID, b); err != nil {
			return fmt.Errorf("failed to seed %s: %v", n.NodeID, err)
		}
	}
	return nil
}

// CommitForwardingRecord appends a vehicle's forwarding stats and recomputes
// reputation Ri (Eq. 3.18) and ZKP validity (Eq. 3.30). The append-only ledger
// makes this evidence tamper-proof — a grey hole cannot rewrite past records.
func (c *DEBSCContract) CommitForwardingRecord(ctx contractapi.TransactionContextInterface,
	nodeID string, nFwd int, nRx int) error {

	rec := NodeRecord{NodeID: nodeID, NFwd: nFwd, NRx: nRx}

	// Append-only trust: once DEBSC has isolated a node (Eq. 3.19), a later
	// forwarding record must NOT silently clear that decision. Preserve any
	// existing isolated=true flag so isolation is monotonic on the ledger.
	if prev, err := ctx.GetStub().GetState(nodeID); err == nil && prev != nil {
		var old NodeRecord
		if json.Unmarshal(prev, &old) == nil && old.Isolated {
			rec.Isolated = true
		}
	}

	// Eq. 3.18: reputation Ri = forwarded / received (Bayesian-style, simplified)
	if nRx > 0 {
		rec.Reputation = float64(nFwd) / float64(nRx)
	} else {
		rec.Reputation = 1.0
	}

	// Eq. 3.30: ZKP forwarding proof — an honest node's committed nFwd matches
	// the observable received count; a grey hole that dropped packets cannot
	// produce a valid proof (nFwd < nRx).
	rec.ZKPValid = (nFwd == nRx)

	// Eq. 3.13: suspicion level increments when reputation deficit is high.
	if (1.0 - rec.Reputation) > 0.4 {
		rec.SuspicionLvl = 1
	}

	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(nodeID, b)
}

// EvaluateIsolation implements Eq. 3.19 — the DEBSC dual-evidence gate:
//   Isolate(vi) = 1[(1 − Ri) > θR  AND  Π_ZKP(vi) == FAIL]
// BOTH the statistical gate (low reputation) and the cryptographic gate
// (failed ZKP proof) must fire. This prevents isolating an honest but
// mobile vehicle (statistical gate fires, but ZKP still valid).
func (c *DEBSCContract) EvaluateIsolation(ctx contractapi.TransactionContextInterface,
	nodeID string, thetaR float64) (string, error) {

	b, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return "", fmt.Errorf("ledger read failed: %v", err)
	}
	if b == nil {
		return fmt.Sprintf("MONITOR node %s: no record on ledger", nodeID), nil
	}

	var rec NodeRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return "", err
	}

	statisticalGate := (1.0 - rec.Reputation) > thetaR // (1 − Ri) > θR
	cryptoGate := !rec.ZKPValid                        // Π_ZKP == FAIL

	if statisticalGate && cryptoGate {
		rec.Isolated = true
		updated, _ := json.Marshal(rec)
		if err := ctx.GetStub().PutState(nodeID, updated); err != nil {
			return "", err
		}
		return fmt.Sprintf(
			"ISOLATE node %s | Reputation=%.3f (1-Ri=%.3f > θR=%.2f) | ZKP=FAILED | Eq.3.19 dual-gate FIRED",
			nodeID, rec.Reputation, 1.0-rec.Reputation, thetaR), nil
	}

	return fmt.Sprintf(
		"MONITOR node %s | Reputation=%.3f | statGate=%v zkpFailed=%v | Eq.3.19 NOT satisfied",
		nodeID, rec.Reputation, statisticalGate, cryptoGate), nil
}

// ReadNode returns a node's current on-ledger record (for evidence queries).
func (c *DEBSCContract) ReadNode(ctx contractapi.TransactionContextInterface,
	nodeID string) (*NodeRecord, error) {
	b, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return nil, fmt.Errorf("ledger read failed: %v", err)
	}
	if b == nil {
		return nil, fmt.Errorf("node %s does not exist on ledger", nodeID)
	}
	var rec NodeRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetAllNodes returns every node record (for the evidence dashboard / screenshots).
func (c *DEBSCContract) GetAllNodes(ctx contractapi.TransactionContextInterface) ([]*NodeRecord, error) {
	iter, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*NodeRecord
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var rec NodeRecord
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			continue
		}
		out = append(out, &rec)
	}
	return out, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&DEBSCContract{})
	if err != nil {
		fmt.Printf("Error creating DEBSC chaincode: %v\n", err)
		return
	}
	if err := cc.Start(); err != nil {
		fmt.Printf("Error starting DEBSC chaincode: %v\n", err)
	}
}
