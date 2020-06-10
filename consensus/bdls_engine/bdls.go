package bdls_engine

import (
	"sync"
	"time"

	"github.com/Sperax/bdls"
)

// BDLSConsensus wraps bdls.Consensus for thread-safety
type BDLSConsensus struct {
	consensus   *bdls.Consensus
	consensusMu sync.Mutex
}

// NewBDLSConsensus wrappers the consensus core into a a thread-safe consensus
func NewBDLSConsensus(consensus *bdls.Consensus) *BDLSConsensus {
	lc := new(BDLSConsensus)
	lc.consensus = consensus
	return lc
}

// Update wraps the Update function in consensus
func (lc *BDLSConsensus) Update(now time.Time) error {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.Update(now)
	}
	return nil
}

// ReceiveMessage wraps the ReceiveMessage function in consensus
func (lc *BDLSConsensus) ReceiveMessage(bts []byte, now time.Time) error {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.ReceiveMessage(bts, time.Now())
	}
	return nil
}
