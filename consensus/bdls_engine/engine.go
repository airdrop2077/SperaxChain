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

// For consensus message event I/O
type (
	// protocol manager will subscribe to this consensus message
	ConsensusMessageOutput []byte
	// protocol manager will deliver this consensus message type
	ConsensusMessageInput []byte
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

	// participants address
	addresses []common.Address

	// pre-validator for <roundchange> message
	stateAt       func(hash common.Hash) (*state.StateDB, error)
	hasBadBlock   func(hash common.Hash) bool
	processBlock  func(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error)
	validateState func(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error

	// mutex for BDLSEngine
	mu sync.Mutex
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

// BytesHash computes keccak256 hash for a slice
func BytesHash(bts []byte) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, bts)
	hw.Sum(h[:0])
	return h
}

// SetParticipants for next height
func (e *BDLSEngine) SetParticipants(participants []*ecdsa.PublicKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.participants = participants
	e.addresses = nil
	for k := range participants {
		e.addresses = append(e.addresses, crypto.PubkeyToAddress(*e.participants[k]))
	}
}

// SetBlockValidator starts the validating engine
// NOTE(xtaci): this must be set before Seal operations
func (e *BDLSEngine) SetBlockValidator(hasBadBlock func(common.Hash) bool,
	processBlock func(*types.Block, *state.StateDB) (types.Receipts, []*types.Log, uint64, error),
	validateState func(*types.Block, *state.StateDB, types.Receipts, uint64) error,
	stateAt func(hash common.Hash) (*state.StateDB, error)) {

	e.mu.Lock()
	defer e.mu.Unlock()

	e.hasBadBlock = hasBadBlock
	e.processBlock = processBlock
	e.validateState = validateState
	e.stateAt = stateAt
}

///////////////////////////////////////////////////////////////////////////////
// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *BDLSEngine) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// Signer returns the signer of this header
func (e *BDLSEngine) Signer(header *types.Header) (common.Address, error) {
	if header.Decision != nil {
		sp, err := bdls.DecodeSignedMessage(header.Decision)
		if err != nil {
			return common.Address{}, err
		}
		pubkey := &ecdsa.PublicKey{Curve: bdls.DefaultCurve, X: big.NewInt(0).SetBytes(sp.X[:]), Y: big.NewInt(0).SetBytes(sp.Y[:])}
		return crypto.PubkeyToAddress(*pubkey), nil
	}
	return common.Address{}, errors.New("cannot retrieve signer")
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
	e.mu.Lock()
	sealHash := e.SealHash(block.Header())

	// known blocks from <roundchange> messages
	knownBlocks := make(map[common.Address]*types.Block)

	// to lookup the block for current consensus height
	lookupBlock := func(hash common.Hash) *types.Block {
		// loop to find the block
		for _, v := range knownBlocks {
			if v.Hash() == hash {
				return v
			}
		}
		return nil
	}

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
		// clear all auxdata before consensus processing
		defer func() {
			signed.AuxData = nil
		}()

		switch m.Type {
		case bdls.MessageType_RoundChange:
			// For incoming <roundchange> message(proposal), we should validate the block sent
			// via sp.AuxData field,  ahead of consensus processing.
			var blk types.Block
			err := rlp.DecodeBytes(signed.AuxData, &blk)
			if err != nil {
				log.Error("messageValidator", "rlp.DecodeBytes", err)
				return false
			}

			// step 1. compare hash with block in auxdata
			if e.SealHash(blk.Header()) != common.BytesToHash(m.State) {
				return false
			}

			// step 2. validate the proposed block
			if !e.verifyProposal(&blk) {
				return false
			}

			// step 3. record or replace this block, the coinbase has verified against signature in VerifyProposal
			for k := range e.addresses {
				if e.addresses[k] == blk.Coinbase() {
					knownBlocks[blk.Coinbase()] = &blk
					return true
				}
			}
			return false
		}

		return true
	}

	// step 2. setup consensus config at given height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: block.NumberU64() - 1,
		PrivateKey:    e.privateKey,
		// TODO(xtaci): (shuffle and set participants sequence based on some random number)
		Participants: e.participants,
		StateCompare: func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(s bdls.State) bool {
			// make sure all states are known from <roundchange> exchanging
			hash := common.BytesToHash(s)
			if lookupBlock(hash) != nil {
				return true
			}
			return false
		},
		MessageValidator: messageValidator,
		// consensus message will be routed through engine
		MessageOutCallback: messageOutCallback,
	}
	e.mu.Unlock()

	// step 3. create the consensus object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("new consensus:", err)
		return err
	}

	// step 4. propose the block hash
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

		// the consensus updater ticker
		updateTick := time.NewTicker(20 * time.Millisecond)
		defer updateTick.Stop()

		// the core consensus message loop
		for {
			select {
			case obj, ok := <-consensusMessageChan: // from p2p
				if !ok {
					return
				}

				if ev, ok := obj.Data.(ConsensusMessageInput); ok {
					consensus.ReceiveMessage(ev, time.Now()) // input to core
					newHeight, newRound, newState := consensus.CurrentState()

					// new height confirmed, only proposer broadcast this mined block
					if newHeight == block.NumberU64() {
						log.Debug("CONSENSUS <decide>", "height", newHeight, "round", newRound, "hash", newHeight, newRound, common.BytesToHash(newState))
						hash := common.BytesToHash(newState)

						// assemble the block with proof
						if newblock := lookupBlock(hash); newblock != nil {
							// found the block, then we can seal the block with the proof
							header := newblock.Header()
							bts, err := consensus.CurrentProof().Marshal()
							if err != nil {
								log.Crit("consensusMessenger", "consensus.CurrentProof", err)
								panic(err)
							}

							// store the the proof in block header
							header.Decision = bts

							// the mined block
							mined := newblock.WithSeal(header)
							// broadcast this block
							results <- mined

							// as block integrity is verified ahead in <roundchange> message,
							// it's safe to stop the consensus loop now
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

// VerifyProposal implements blockchain specific block validator
func (e *BDLSEngine) verifyProposal(block *types.Block) bool {
	// for <roundchange> message
	// The coinbase should be the person who signed the block
	addr, err := e.Signer(block.Header())
	if err != nil {
		log.Error("Could not recover signer of the block", "e.Signer()", err)
		return false
	} else if addr != block.Header().Coinbase {
		log.Error("The signer of this block does not match the coinbase", "addr", addr, "coinbase", block.Header().Coinbase, "func", "Verify")
		return false
	}

	// check bad block
	if e.hasBadBlock != nil {
		if e.hasBadBlock(block.Hash()) {
			log.Error("messageValidator", "e.hasBadBlock", block.Hash())
			return false
		}
	}

	// check transaction trie
	txnHash := types.DeriveSha(block.Transactions())
	if txnHash != block.Header().TxHash {
		log.Error("messageValidator validate transactions", "txnHash", txnHash, "Header().TxHash", block.Header().TxHash)
		return false
	}

	// Process the block to verify that the transactions are valid and to retrieve the resulting state and receipts
	// Get the state from this block's parent.
	state, err := e.stateAt(block.Header().ParentHash)
	if err != nil {
		log.Error("verify - Error in getting the block's parent's state", "parentHash", block.Header().ParentHash.Hex(), "err", err)
		return false
	}

	// Make a copy of the state
	state = state.Copy()

	// Apply this block's transactions to update the state
	receipts, _, usedGas, err := e.processBlock(block, state)
	if err != nil {
		log.Error("verify - Error in processing the block", "err", err)
		return false
	}

	// Validate the block
	if err := e.validateState(block, state, receipts, usedGas); err != nil {
		log.Error("verify - Error in validating the block", "err", err)
		return false
	}

	return true
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
	state.AddBalance(header.Coinbase, big.NewInt(100))
}
