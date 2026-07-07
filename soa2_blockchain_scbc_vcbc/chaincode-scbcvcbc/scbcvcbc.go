// ============================================================
// SOA2 — Alabdulatif et al. (CMES 2024, vol.138 no.2, pp.2005-2021)
// "Mitigating Blackhole and Greyhole Routing Attacks in VANETs
//  Using Blockchain Based Smart Contracts"
//
// Hyperledger Fabric chaincode implementing the paper's two
// blockchain smart contracts:
//   SCBC — Self-Classification Blockchain Based Contract  (Alg. 1-3)
//   VCBC — Voting-Classification Blockchain Based Contract (Alg. 4-5)
//
// Node classification (paper §4.3):
//   rating = deliveredCount*100 / (deliveredCount + notDeliveredCount)
//     rating == 0          -> "black"  (drops everything)
//     0 < rating <= thr    -> "grey"   (unpredictable / partial drop)
//     rating  > thr        -> "white"  (good relay, usable by AODV)
//
// This is the SECOND state-of-the-art baseline (SOA2). It is kept
// fully separate from SHIELD-GH (our method) and from SOA1.
// ============================================================
package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SCBCVCBCContract bundles both smart contracts from the paper.
type SCBCVCBCContract struct {
	contractapi.Contract
}

// NodeRecord is the on-ledger relay record for one vehicle (the
// node tuple of Alg. 1/5: nodeName, deliveredCount, notDeliveredCount).
type NodeRecord struct {
	NodeID            string  `json:"nodeId"`
	DeliveredCount    int     `json:"deliveredCount"`    // successful relays
	NotDeliveredCount int     `json:"notDeliveredCount"` // dropped relays
	Rating            float64 `json:"rating"`            // Alg.3: delivered*100/times
	Status            string  `json:"status"`            // white | grey | black
	Reputation        string  `json:"reputation"`        // miner vote: w | g | b (VCBC)
	IsAttacker        int     `json:"isAttacker"`        // ground truth (eval only)
}

const defaultThreshold = 50.0 // τ in Alg.3 (% rating). Paper: rate is a percentage.

// updateNode implements Alg. 3 (Update node status): classify a node
// from its delivered / not-delivered relay counts.
func classify(delivered, notDelivered int, threshold float64) (float64, string) {
	times := delivered + notDelivered
	if times == 0 {
		// No relays assigned yet — treat as provisionally white (Alg.: "initially white").
		return 100.0, "white"
	}
	rating := float64(delivered) * 100.0 / float64(times)
	switch {
	case rating == 0: // Alg.3 line 4-5
		return rating, "black"
	case rating > threshold: // Alg.3 line 7-8
		return rating, "white"
	default: // Alg.3 line 10
		return rating, "grey"
	}
}

// CommitRelayRecord appends/updates a vehicle's relay statistics and
// recomputes its SCBC classification (Alg. 1-3). The append-only ledger
// makes the delivered/dropped evidence tamper-proof — a grey/black hole
// cannot rewrite its own history.
func (c *SCBCVCBCContract) CommitRelayRecord(ctx contractapi.TransactionContextInterface,
	nodeID string, deliveredCount int, notDeliveredCount int, isAttacker int) error {

	rating, status := classify(deliveredCount, notDeliveredCount, defaultThreshold)
	rec := NodeRecord{
		NodeID:            nodeID,
		DeliveredCount:    deliveredCount,
		NotDeliveredCount: notDeliveredCount,
		Rating:            rating,
		Status:            status,
		IsAttacker:        isAttacker,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(nodeID, b)
}

// SetReputation records a miner's prior vote for a node (VCBC, Alg.4).
// rep must be "w" (white), "g" (grey) or "b" (black).
func (c *SCBCVCBCContract) SetReputation(ctx contractapi.TransactionContextInterface,
	nodeID string, rep string) error {

	b, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return fmt.Errorf("ledger read failed: %v", err)
	}
	var rec NodeRecord
	if b == nil {
		rec = NodeRecord{NodeID: nodeID, Status: "white", Rating: 100.0}
	} else if err := json.Unmarshal(b, &rec); err != nil {
		return err
	}
	rec.Reputation = rep
	nb, _ := json.Marshal(rec)
	return ctx.GetStub().PutState(nodeID, nb)
}

// RunSCBC implements Alg. 1 (SCBC). With no prior knowledge of neighbours,
// every node on the ledger is classified purely from its delivered ratio.
// Returns the list of nodes that may be used as AODV relays (status==white).
func (c *SCBCVCBCContract) RunSCBC(ctx contractapi.TransactionContextInterface,
	threshold float64) ([]*NodeRecord, error) {

	all, err := c.GetAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, rec := range all {
		rec.Rating, rec.Status = classify(rec.DeliveredCount, rec.NotDeliveredCount, threshold)
		nb, _ := json.Marshal(rec)
		if err := ctx.GetStub().PutState(rec.NodeID, nb); err != nil {
			return nil, err
		}
	}
	return all, nil
}

// makeVoting implements Alg. 4: drop every node whose miner reputation is
// grey or black, keeping only the highly-reputed subset for the second phase.
func makeVoting(nodes []*NodeRecord) []*NodeRecord {
	kept := make([]*NodeRecord, 0, len(nodes))
	for _, n := range nodes {
		if n.Reputation == "g" || n.Reputation == "b" {
			continue // Alg.4 line 3-4: retrieve (remove) n from N
		}
		kept = append(kept, n)
	}
	return kept
}

// RunVCBC implements Alg. 5 (VCBC): first a voting pre-filter (Alg.4) using
// miners' stored reputations, then the SCBC delivered-ratio classification
// on the surviving high-reputation subset. This is why VCBC reaches good PDR
// earlier than SCBC (paper §6) — bad nodes are excluded before relaying.
func (c *SCBCVCBCContract) RunVCBC(ctx contractapi.TransactionContextInterface,
	threshold float64) ([]*NodeRecord, error) {

	all, err := c.GetAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	survivors := makeVoting(all) // Alg.5 line 3: N1 <- makeVoting(N)
	for _, rec := range survivors {
		rec.Rating, rec.Status = classify(rec.DeliveredCount, rec.NotDeliveredCount, threshold)
		nb, _ := json.Marshal(rec)
		if err := ctx.GetStub().PutState(rec.NodeID, nb); err != nil {
			return nil, err
		}
	}
	return survivors, nil
}

// ReadNode returns one node's current on-ledger record.
func (c *SCBCVCBCContract) ReadNode(ctx contractapi.TransactionContextInterface,
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

// GetAllNodes returns every node record, sorted by NodeID for stable output.
func (c *SCBCVCBCContract) GetAllNodes(ctx contractapi.TransactionContextInterface) ([]*NodeRecord, error) {
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
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SCBCVCBCContract{})
	if err != nil {
		fmt.Printf("Error creating SCBC/VCBC chaincode: %v\n", err)
		return
	}
	if err := cc.Start(); err != nil {
		fmt.Printf("Error starting SCBC/VCBC chaincode: %v\n", err)
	}
}
