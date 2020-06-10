package bdls_engine

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/bdls"
	"golang.org/x/crypto/sha3"
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

func (lc *BDLSConsensus) CurrentProof() *bdls.SignedProto {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.CurrentProof()
	}
	return nil
}

func (lc *BDLSConsensus) CurrentState() (height uint64, round uint64, data bdls.State) {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.CurrentState()
	}
	return 0, 0, nil
}

func (lc *BDLSConsensus) Join(p bdls.PeerInterface) bool {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.Join(p)
	}
	return false
}

func (lc *BDLSConsensus) Leave(addr net.Addr) bool {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.Leave(addr)
	}
	return false
}

func (lc *BDLSConsensus) Propose(s bdls.State) {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		lc.consensus.Propose(s)
	}
}

func (lc *BDLSConsensus) SetLatency(latency time.Duration) {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		lc.consensus.SetLatency(latency)
	}
}

func (lc *BDLSConsensus) ValidateDecideMessage(bts []byte, targetState []byte) error {
	lc.consensusMu.Lock()
	defer lc.consensusMu.Unlock()
	if lc.consensus != nil {
		return lc.consensus.ValidateDecideMessage(bts, targetState)
	}
	return errors.New("consensus not initialized")
}

func RLPHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
