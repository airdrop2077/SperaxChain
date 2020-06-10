package bdls_engine

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/event"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/SperaxChain/rpc"
	"github.com/Sperax/bdls"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	MaxUnconfirmedBlocks = 1024
)

// For message exchange
type (
	ConsensusMessageOutput []byte
	ConsensusMessageInput  []byte
	UnconfirmedBlock       struct{ Block *types.Block }
)

// BDLSEngine implements blockchain consensus engine
type BDLSEngine struct {
	fake bool

	// event mux to send consensus message as events
	mux *event.TypeMux

	// private key to sign mesasges
	privateKey *ecdsa.PrivateKey

	// parameters adjustable at each height
	participants []*ecdsa.PublicKey

	// consensus in-progress blocks
	unconfirmedBlocks *lru.Cache

	// Currently working consensus
	consensusMu sync.Mutex
}

func New(privateKey *ecdsa.PrivateKey, mux *event.TypeMux) *BDLSEngine {
	engine := new(BDLSEngine)
	engine.mux = mux
	engine.privateKey = privateKey

	cache, err := lru.New(MaxUnconfirmedBlocks)
	if err != nil {
		panic(err)
	}
	engine.unconfirmedBlocks = cache

	return engine
}

func NewFaker() *BDLSEngine {
	engine := New(nil, nil)
	engine.fake = true
	return engine
}

func RLPHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

// SetParticipants for next height
func (e *BDLSEngine) SetParticipants(participants []*ecdsa.PublicKey) {
	e.consensusMu.Lock()
	defer e.consensusMu.Unlock()
	e.participants = participants
}

///////////////////////////////////////////////////////////////////////////////
// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *BDLSEngine) Author(header *types.Header) (common.Address, error) {
	return common.Address{}, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *BDLSEngine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	parentHeader := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parentHeader == nil {
		return errors.New("unknown ancestor")
	}
	if seal {
		if err := e.VerifySeal(chain, header); err != nil {
			return err
		}
	}
	return nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (e *BDLSEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := e.VerifyHeader(chain, header, seals[i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()

	return abort, results
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (e *BDLSEngine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	if e.fake {
		return nil
	}

	// step 0. Check decision field is not nil
	if len(header.Decision) == 0 {
		log.Debug("VerifySeal", "header.Decision", "decision field is nil")
		return errors.New("decision field is nil")
	}
	// step 1. Get the SealHash(without Decision field) of this header
	sealHash := e.SealHash(header).Bytes()

	// step 2. create a consensus object to validate this message at the correct height
	config := &bdls.Config{
		Epoch:         time.Now(),
		VerifierOnly:  true,
		StateCompare:  func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(bdls.State) bool { return true },
		CurrentHeight: header.Number.Uint64() - 1,
	}

	// TODO: to set the participants from previous blocks?
	// currently it's fixed
	config.Participants = e.participants

	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("new consensus:", err)
		return err
	}

	// step 3. validate decide message integrity
	err = consensus.ValidateDecideMessage(header.Decision, sealHash)
	if err != nil {
		log.Debug("VerifySeal", "ValidateDecideMessage", err)
		return err
	}

	return nil
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *BDLSEngine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *BDLSEngine) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction) {
	accumulateRewards(chain.Config(), state, header)
	header.Root = state.IntermediateRoot(true)
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *BDLSEngine) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (*types.Block, error) {
	accumulateRewards(chain.Config(), state, header)
	header.Root = state.IntermediateRoot(true)
	return types.NewBlock(header, txs, receipts), nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (e *BDLSEngine) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	// preparation
	e.unconfirmedBlocks.Purge()

	// start new consensus round
	// step 1. Get the SealHash(without Decision field) of this header
	e.consensusMu.Lock()
	sealHash := e.SealHash(block.Header())

	// step 2. setup consensus config at given height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: block.NumberU64() - 1,
		PrivateKey:    e.privateKey,
		Participants:  e.participants, // TODO: set participants correctly
		StateCompare:  func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(s bdls.State) bool {
			h := common.BytesToHash(s)
			// check if it's a known proposed block
			if _, ok := e.unconfirmedBlocks.Get(h); ok {
				return true
			}
			return false
		},

		// consensus message will be routed through engine
		MessageCallback: e.messageCallback,
	}
	e.consensusMu.Unlock()

	// step 3. create the consensus object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("new consensus:", err)
		return err
	}

	// step 4. start propose the seal hash
	consensus.Propose(sealHash.Bytes())

	// step 5. create a consensus message subscriber's loop
	go func() {
		// subscribe to consensus message input
		consensusSub := e.mux.Subscribe(ConsensusMessageInput{})
		defer consensusSub.Unsubscribe()
		consensusMessageChan := consensusSub.Chan()

		// subscribe to pre-exchanged unmined blocks
		unconfirmedSub := e.mux.Subscribe(UnconfirmedBlock{})
		defer unconfirmedSub.Unsubscribe()
		unconfirmedBlockChan := unconfirmedSub.Chan()

		updateTick := time.NewTicker(20 * time.Millisecond)
		for {
			select {
			case obj, ok := <-consensusMessageChan:
				if !ok {
					return
				}

				if ev, ok := obj.Data.(ConsensusMessageInput); ok {
					consensus.ReceiveMessage(ev, time.Now()) // input to core
					newHeight, newRound, newState := consensus.CurrentState()

					// height confirmed, should broadcast this mined block if it's my proposal
					if newHeight == block.NumberU64() {
						log.Debug("CONSENSUS <decide>", "height", newHeight, "round", newRound, "hash", newHeight, newRound, common.BytesToHash(newState))
						blkHash := common.BytesToHash(newState)
						value, ok := e.unconfirmedBlocks.Get(blkHash)

						if ok {
							// seal the block with proof
							header := value.(*types.Block).Header()
							bts, err := consensus.CurrentProof().Marshal()
							if err != nil {
								log.Crit("consensusMessenger", "consensus.CurrentProof", err)
								panic(err)
							}
							header.Decision = bts // store the the proof in block header

							// the mined block
							mined := value.(*types.Block).WithSeal(header)

							// broadcast this block
							results <- mined
							return
						}
					}
				}
			case obj, ok := <-unconfirmedBlockChan:
				if !ok {
					return
				}

				if ev, ok := obj.Data.(UnconfirmedBlock); ok {
					e.unconfirmedBlocks.Add(ev.Block.Hash(), ev.Block)
					log.Debug("unconfirmed block", "hash", ev.Block.Hash())
				}

			case <-updateTick.C:
				consensus.Update(time.Now())
			case <-stop:
				return
			}
		}
	}()
	return nil
}

// the message callback to redirect the message to p2p
func (e *BDLSEngine) messageCallback(m *bdls.Message, signed *bdls.SignedProto) {
	bts, err := signed.Marshal()
	if err != nil {
		log.Error("messageCallback", "signed.Marshal", err)
		return
	}

	// broadcast the message out
	err = e.mux.Post(ConsensusMessageOutput(bts))
	if err != nil {
		log.Error("messageCallback", "mux.Post", err)
		return
	}
}

// SealHash returns the hash of a block prior to it being sealed.
func (e *BDLSEngine) SealHash(header *types.Header) (hash common.Hash) {
	copied := types.CopyHeader(header)
	copied.Decision = nil
	return copied.Hash()
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (e *BDLSEngine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return common.Big1
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *BDLSEngine) APIs(chain consensus.ChainReader) []rpc.API {
	// TODO
	return nil
}

// Close terminates any background threads maintained by the consensus engine.
func (e *BDLSEngine) Close() error {
	// TODO
	return nil
}

// mining reward computation
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header) {
	state.AddBalance(common.Address{}, big.NewInt(100))
}
