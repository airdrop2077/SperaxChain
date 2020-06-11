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
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/event"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/SperaxChain/rpc"
	"github.com/Sperax/bdls"
	"golang.org/x/crypto/sha3"
)

const (
	MaxUnconfirmedBlocks = 1024
)

// For consensus message I/O
type (
	ConsensusMessageOutput []byte
	ConsensusMessageInput  []byte
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

	// Currently working consensus
	consensusMu sync.Mutex
}

func New(privateKey *ecdsa.PrivateKey, mux *event.TypeMux) *BDLSEngine {
	engine := new(BDLSEngine)
	engine.mux = mux
	engine.privateKey = privateKey
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
	if header.Decision == nil {
		sp, err := bdls.DecodeSignedMessage(header.Decision)
		if err != nil {
			return common.Address{}, err
		}
		pubkey := &ecdsa.PublicKey{Curve: bdls.DefaultCurve, X: big.NewInt(0).SetBytes(sp.X[:]), Y: big.NewInt(0).SetBytes(sp.Y[:])}
		return crypto.PubkeyToAddress(*pubkey), nil
	}

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
	// start new consensus round
	// step 1. Get the SealHash(without Decision field) of this header
	e.consensusMu.Lock()
	sealHash := e.SealHash(block.Header())

	// mesasge out call back to handle auxcilliary messages along with the consensus message
	messageOutCallback := func(m *bdls.Message, signed *bdls.SignedProto) {
		// for <roundchange> message, we need to append the types.Block to the message
		switch m.Type {
		case bdls.MessageType_RoundChange:
			blockData, err := rlp.EncodeToBytes(block)
			if err != nil {
				log.Error("messageOutCallBack", "rlp.EncodeToBytes", err)
			}
			signed.AuxData = blockData
		}

		bts, err := signed.Marshal()
		if err != nil {
			log.Error("messageOutCallback", "signed.Marshal", err)
			return
		}

		// broadcast the message out
		err = e.mux.Post(ConsensusMessageOutput(bts))
		if err != nil {
			log.Error("messageOutCallback", "mux.Post", err)
			return
		}
	}

	// message validator for incoming messages which has correctly signed
	messageValidator := func(m *bdls.Message, signed *bdls.SignedProto) bool {
		// for roundchange message, we need to verify the block integrity in auxdata
		switch m.Type {
		case bdls.MessageType_RoundChange:
			var blk types.Block
			err := rlp.DecodeBytes(signed.AuxData, &blk)
			if err != nil {
				log.Debug("messageValidator", "rlp.DecodeBytes", err)
				return false
			}

			// step 1. compare hash with block in auxdata
			if blk.Hash() != common.BytesToHash(m.State) {
				return false
			}
			// step 2. validate this message

			// step 3. for a valid <roundchange> message,  clear the auxdata before consensus processing
			signed.AuxData = nil
			return true
		}

		return true
	}

	// step 2. setup consensus config at given height
	config := &bdls.Config{
		Epoch:            time.Now(),
		CurrentHeight:    block.NumberU64() - 1,
		PrivateKey:       e.privateKey,
		Participants:     e.participants, // TODO: set participants correctly
		StateCompare:     func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate:    func(s bdls.State) bool { return true }, // we postpone the state check after a block has mined
		MessageValidator: messageValidator,
		// consensus message will be routed through engine
		MessageOutCallback: messageOutCallback,
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
		// subscribe to consensus message input via event mux
		var consensusMessageChan <-chan *event.TypeMuxEvent
		if e.mux != nil {
			consensusSub := e.mux.Subscribe(ConsensusMessageInput{})
			defer consensusSub.Unsubscribe()
			consensusMessageChan = consensusSub.Chan()
		}

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

					// new height confirmed, only proposer broadcast this mined block
					if newHeight == block.NumberU64() {
						log.Debug("CONSENSUS <decide>", "height", newHeight, "round", newRound, "hash", newHeight, newRound, common.BytesToHash(newState))
						blkHash := common.BytesToHash(newState)
						if blkHash == sealHash {
							// the proposer will seal the block with proof and broadcast
							header := block.Header()
							bts, err := consensus.CurrentProof().Marshal()
							if err != nil {
								log.Crit("consensusMessenger", "consensus.CurrentProof", err)
								panic(err)
							}

							// store the the proof in block header
							header.Decision = bts

							// the mined block
							mined := block.WithSeal(header)
							// broadcast this block
							results <- mined
							return
						}
					}
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
