// BSD 3-Clause License
//
// Copyright (c) 2020, Sperax
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package bdls_engine

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	fmt "fmt"
	"math/big"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/accounts"
	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/ethdb"
	"github.com/Sperax/SperaxChain/event"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/SperaxChain/rpc"
	"github.com/Sperax/bdls"
	proto "github.com/gogo/protobuf/proto"
)

const (
	// minimum difference between two consecutive block's timestamps in second
	minBlockPeriod = 3
)

// Message exchange between consensus engine & protocol manager
type (
	// protocol manager will subscribe and broadcast this type of message
	MessageOutput []byte
	// protocol manager will deliver the incoming consensus message via this type to this engine
	MessageInput []byte
)

var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errInvalidDifficulty is returned if the difficulty of a block is not 1
	errInvalidDifficulty = errors.New("invalid difficulty")
	// errInvalidW
	errInvalidW = errors.New("invalid W")
	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")
	// errInvalidNonce is returned if a block's nonce is invalid
	errInvalidNonce = errors.New("invalid nonce")
	// errNonEmptyDecision is returned if a block's decision field is not empty
	errNonEmptyDecision = errors.New("non-empty decision field in proposal")
	// errEmptyDecision is returned if a block's decision field is empty
	errEmptyDecision = errors.New("empty decision field")
	// invalid input consensus message
	errInvalidConsensusMessage = errors.New("invalid input consensus message")
	// errInvalidTimestamp is returned if the timestamp of a block is lower than the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")
)

var (
	defaultDifficulty = big.NewInt(1)            // difficulty in block headers is always 1
	nilUncleHash      = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	emptyNonce        = types.BlockNonce{}       // nonce in block headers is always all-zeros
)

// MessageHash return the consistent hash based on SignedMessage content,
// not including signature R, S, which has random number in ecdsa signing.
func MessageHash(bts []byte) (common.Hash, error) {
	sp, err := bdls.DecodeSignedMessage(bts)
	if err != nil {
		return common.Hash{}, errInvalidConsensusMessage
	}

	// convert the hash bytes in bdls to common.Hash
	return common.BytesToHash(sp.Hash()), nil
}

// PublicKey to Identity conversion, for use in BDLS
func PubKeyToIdentity(pubkey *ecdsa.PublicKey) (ret bdls.Identity) {
	// for a publickey first we convert to ethereum common.Address
	commonAddress := crypto.PubkeyToAddress(*pubkey)
	// then we just byte copy to Identiy struct
	copy(ret[:], commonAddress[:])
	return
}

// BDLSEngine implements BDLS-based blockchain consensus engine
type BDLSEngine struct {
	// ephermal private key for header verification
	ephermalKey *ecdsa.PrivateKey

	// event mux to exchange consensus message with protocol manager
	mux *event.TypeMux

	// the account manager to get private key as a participant
	accountManager *accounts.Manager

	// as the block will be exchanged via <roundchange> message,
	// we need to validate these blocks in-flight, so we need processBlock at given height with state,
	// and compare the results with related fields in block header.
	stateAt       func(hash common.Hash) (*state.StateDB, error)
	hasBadBlock   func(hash common.Hash) bool
	processBlock  func(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error)
	validateState func(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error

	// database
	db ethdb.Database

	// mutex for fields
	mu sync.Mutex
}

// New creates a ethereum compatible BDLS engine with account manager for signing and mux for
// message exchanging
func New(accountManager *accounts.Manager, mux *event.TypeMux, db ethdb.Database) *BDLSEngine {
	engine := new(BDLSEngine)
	engine.mux = mux
	engine.accountManager = accountManager
	engine.db = db

	// create an ephermal key for verification
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Crit("BDLS generate ephermal key", "crypto.GenerateKey", err)
	}
	engine.ephermalKey = priv
	return engine
}

// SetBlockValidator starts the validating engine, this will be set by miner while starting.
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

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *BDLSEngine) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *BDLSEngine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	err := e.verifyHeader(chain, header, nil)
	if err != nil {
		return err
	}

	if err := e.VerifySeal(chain, header); err != nil {
		return err
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
// NOTE(xtaci): downloader's batch verification
func (e *BDLSEngine) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Ensure the block's parent exist
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	// Ensure that the nonce is empty
	if header.Nonce != (emptyNonce) {
		return errInvalidNonce
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in BDLS
	if header.UncleHash != nilUncleHash {
		return errInvalidUncleHash
	}

	// Ensure that the block's difficulty is 1
	if header.Difficulty == nil || header.Difficulty.Cmp(defaultDifficulty) != 0 {
		return errInvalidDifficulty
	}

	// Verify W has correctly set
	if e.RandAtBlock(chain, header) != header.W {
		return errInvalidW
	}

	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+minBlockPeriod > header.Time {
		return errInvalidTimestamp
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
			err := e.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()

	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of a given engine.
func (e *BDLSEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errInvalidUncleHash
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (e *BDLSEngine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	// check parent
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	// step 0. Check proof field is not nil
	if len(header.Decision) == 0 {
		return errEmptyDecision
	}

	// step 1. Get the SealHash(without Decision field) of this header to verify against
	sealHash := e.SealHash(header).Bytes()

	// step 2. create a consensus config to validate this message at the correct height
	config := &bdls.Config{
		Epoch:            time.Now(),
		PrivateKey:       e.ephermalKey,
		StateCompare:     func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate:    func(bdls.State) bool { return true },
		CurrentHeight:    header.Number.Uint64() - 1,
		PubKeyToIdentity: PubKeyToIdentity,
	}

	// step 3. check if the coinbase is a valid proposer at given height
	// NOTE(xtaci): the state is related to some HEIGHT
	state, err := e.stateAt(header.ParentHash)
	if err != nil {
		return errors.New("Error in getting the block's parent's state")
	}

	stakingObject, err := e.GetStakingObject(state)
	if err != nil {
		return errors.New("Error in getting staking Object")
	}

	if !e.IsProposer(chain, header, stakingObject) {
		return errors.New(fmt.Sprint("Not a valid proposer at height", header.Number))
	}

	// step 4. create the consensus object along with participants to validate decide message
	config.Participants = e.CreateValidators(chain, header, stakingObject)

	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("VerifySeal", "bdls.NewConsensus", err)
		return err
	}

	// step 5. validate decide message to the block
	err = consensus.ValidateDecideMessage(header.Decision, sealHash)
	if err != nil {
		log.Debug("VerifySeal", "consensus..ValidateDecideMessage", err)
		return err
	}

	return nil
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *BDLSEngine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// unused fields, force to set to empty
	header.Nonce = emptyNonce
	// use the same difficulty for all blocks
	header.Difficulty = defaultDifficulty
	// check parent
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	// set header's timestamp(unix time) to at least minBlockPeriod since last block
	header.Time = parent.Time + minBlockPeriod
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}

	// TODO(xtaci): correctly set participants based on rules
	state, err := e.stateAt(header.ParentHash)
	if err != nil {
		log.Error("consensusTask - Error in getting the block's parent's state", "parentHash", header.ParentHash.Hex(), "err", err)
		return errors.New("stateAt")
	}
	stakingObject, err := e.GetStakingObject(state)
	if err != nil {
		log.Error("consensusTask - Error in getting staking Object", "parentHash", header.ParentHash.Hex(), "err", err)
		return errors.New("GetStakingObject")
	}
	// set W
	header.W = e.RandAtBlock(chain, header)

	// set proposer's R
	privateKey := e.waitForPrivateKey(header.Coinbase, nil)
	for k := range stakingObject.Stakers {
		staker := stakingObject.Stakers[k]
		if staker.Address == header.Coinbase {
			seed := e.deriveStakingSeed(privateKey, staker.StakingFrom)
			header.R = common.BytesToHash(e.hashChain(seed, header.Number.Uint64()-staker.StakingFrom))
			break
		}
	}

	// set proposer's signature
	sign, err := crypto.Sign(header.Hash().Bytes(), privateKey)
	if err != nil {
		log.Error("cyrpto.sign", "error", err)
		return err
	}
	header.Signature = sign

	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *BDLSEngine) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	accumulateRewards(chain.Config(), state, header)
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = nilUncleHash
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *BDLSEngine) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	accumulateRewards(chain.Config(), state, header)
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = nilUncleHash
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (e *BDLSEngine) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	go e.consensusTask(chain, block, results, stop)
	return nil
}

// waitForPrivateKey gets private key from account manager
func (e *BDLSEngine) waitForPrivateKey(coinbase common.Address, stop <-chan struct{}) *ecdsa.PrivateKey {
	for {
		select {
		case <-stop:
			return nil
		default:
			log.Debug("looking for the wallet of coinbase:", "coinbase", coinbase)
			e.mu.Lock()
			wallet, err := e.accountManager.Find(accounts.Account{Address: coinbase})
			if err != nil {
				e.mu.Unlock()
				log.Error("cannot find the wallet of coinbase", "coinbase", coinbase)
				return nil
			}

			priv, err := wallet.GetPrivateKey(accounts.Account{Address: coinbase})
			if err != nil {
				e.mu.Unlock()
				<-time.After(time.Second) // wait for a second before retry
				continue
			}
			e.mu.Unlock()

			return priv
		}
	}
}

// verify the proposal block
func (e *BDLSEngine) verifyProposal(chain consensus.ChainReader, block *types.Block, height uint64, stakingObject *StakingObject) bool {
	header := block.Header()
	// verify the block number
	if header.Number.Uint64() != height {
		log.Warn("mismatched block number", "actual", header.Number.Uint64(), "expected", height)
		return false
	}

	// verify header fields
	if err := e.verifyHeader(chain, header, nil); err != nil {
		log.Error("verifyHeader", "err", err)
		return false
	}

	// ensure it's a valid proposer
	if !e.verifyProposer(chain, stakingObject, header) {
		log.Error("verifyProposer failed")
		return false
	}

	// validate the states of transactions
	if !e.verifyStates(block) {
		log.Error("verifyStates failed")
		return false
	}

	return true
}

// a consensus task for a specific block
func (e *BDLSEngine) consensusTask(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) {
	privateKey := e.waitForPrivateKey(block.Coinbase(), stop)
	// time compensation to avoid fast block generation
	delay := time.Unix(int64(block.Header().Time), 0).Sub(time.Now())

	// wait for the timestamp of header, use this to adjust the block period
	select {
	case <-time.After(delay):
	case <-stop:
		results <- nil
		return
	}

	// start new consensus round
	e.mu.Lock()
	// retrieve staking object at parent height
	state, err := e.stateAt(block.Header().ParentHash)
	if err != nil {
		log.Error("consensusTask - Error in getting the block's parent's state", "parentHash", block.Header().ParentHash.Hex(), "err", err)
		return
	}
	stakingObject, err := e.GetStakingObject(state)
	if err != nil {
		log.Error("consensusTask - Error in getting staking Object", "parentHash", block.Header().ParentHash.Hex(), "err", err)
		return
	}

	// step 1. prepare callbacks(closures)
	// we need to prepare 3 closures for this height, one to track proposals from local or remote,
	// one to exchange the message from consensus core to p2p module, one to validate consensus
	// messages with proposed blocks from remote.

	// known proposed blocks from each participants' <roundchange> messages
	allKeptBlocks := make(map[common.Address][]*types.Block)

	// to lookup the block for current consensus height
	lookupProposal := func(hash common.Hash) *types.Block {
		// loop to find the block
		for _, blocks := range allKeptBlocks {
			for _, b := range blocks {
				if b.Hash() == hash {
					return b
				}
			}
		}
		return nil
	}

	// mesasge out call back to handle auxcilliary messages along with the consensus message
	messageOutCallback := func(m *bdls.Message, signed *bdls.SignedProto) {
		log.Debug("consensus sending message", "type", m.Type)
		switch m.Type {
		case bdls.MessageType_RoundChange:
			// for <roundchange> message, we need to send the corresponding block
			// as proposal.
			blockHash := common.BytesToHash(m.State)
			var outblock *types.Block
			// externally proposed block
			outblock = lookupProposal(blockHash)

			// impossible situation here, all outgoing proposals in <roundchange>
			// are to be known.
			if outblock == nil {
				log.Error("cannot locate the proposed block", "hash", blockHash)
				return
			}

			// marshal the proposal block to binary and embed it in signed.AuxData
			blockData, err := rlp.EncodeToBytes(outblock)
			if err != nil {
				log.Error("messageOutCallBack", "rlp.EncodeToBytes", err)
			}

			// set auxdata & random number
			signed.AuxData = blockData
		}

		// all outgoing signed message will be delivered to ProtocolManager
		// and finally to send to peers.
		bts, err := signed.Marshal()
		if err != nil {
			log.Error("messageOutCallback", "signed.Marshal", err)
			return
		}

		// broadcast the message via event mux
		err = e.mux.Post(MessageOutput(bts))
		if err != nil {
			log.Error("messageOutCallback", "mux.Post", err)
			return
		}
	}

	// message validator for incoming messages which has correctly signed
	messageValidator := func(c *bdls.Consensus, m *bdls.Message, signed *bdls.SignedProto) bool {
		log.Debug("consensus received message", "type", m.Type)
		// clear all auxdata before consensus processing,
		// we don't want the consensus core to keep this external field AuxData
		// but we will keep RN field
		defer func() {
			signed.AuxData = nil
		}()

		switch m.Type {
		case bdls.MessageType_RoundChange:
			// For incoming <roundchange> message(proposal), we should validate the block sent
			// via sp.AuxData field, ahead of consensus processing.
			var proposal types.Block
			err := rlp.DecodeBytes(signed.AuxData, &proposal)
			if err != nil {
				log.Error("messageValidator", "rlp.DecodeBytes", err)
				return false
			}

			// ensure the hash is to the block in auxdata
			if proposal.Hash() != common.BytesToHash(m.State) {
				log.Error("messageValidator auxdata hash", "block hash", proposal.Hash(), "state hash", common.BytesToHash(m.State))
				return false
			}

			// verify proposal
			if !e.verifyProposal(chain, &proposal, block.NumberU64(), stakingObject) {
				log.Error("messageValidator verifyProposal failed")
				return false
			}

			// A simple DoS prevention mechanism:
			// 1. Remove previously kept blocks which has NOT been accepted in consensus.
			// 2. Always record the latest proposal from a proposer, before consensus continues
			var keptBlocks []*types.Block
			var repeated bool
			for _, pBlock := range allKeptBlocks[block.Coinbase()] {
				if c.HasProposed(pBlock.Hash().Bytes()) {
					keptBlocks = append(keptBlocks, pBlock)
					// repeated valid block
					if pBlock.Hash() == proposal.Hash() {
						repeated = true
					}
				}
			}

			if !repeated { // record latest proposal of a block
				keptBlocks = append(keptBlocks, &proposal)
			}
			allKeptBlocks[proposal.Coinbase()] = keptBlocks

			return true
		}

		return true
	}

	// step 2. setup consensus config at the given height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: block.NumberU64() - 1,
		PrivateKey:    privateKey,
		StateCompare:  func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(s bdls.State) bool {
			// make sure all states are known from <roundchange> exchanging
			hash := common.BytesToHash(s)
			if lookupProposal(hash) != nil {
				return true
			}

			return false
		},
		PubKeyToIdentity: PubKeyToIdentity,
		MessageValidator: messageValidator,
		// consensus message will be routed through engine
		MessageOutCallback: messageOutCallback,
	}
	config.Participants = e.CreateValidators(chain, block.Header(), stakingObject)
	e.mu.Unlock()

	// step 3. create the consensus object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("bdls.NewConsensus", "err", err)
		return
	}

	// step 5: step delay by last block timestamp
	consensus.SetLatency(time.Second)

	// step 5. create a consensus message subscriber's loop
	// subscribe to consensus message input via event mux
	var consensusMessageChan <-chan *event.TypeMuxEvent
	if e.mux != nil {
		consensusSub := e.mux.Subscribe(MessageInput{})
		defer consensusSub.Unsubscribe()
		consensusMessageChan = consensusSub.Chan()
	} else {
		log.Error("mux is nil")
		return
	}

	// the consensus updater ticker
	updateTick := time.NewTicker(20 * time.Millisecond)
	defer updateTick.Stop()

	// if i'm the proposer, propose the block
	if e.IsProposer(chain, block.Header(), stakingObject) {
		allKeptBlocks[block.Coinbase()] = append(allKeptBlocks[block.Coinbase()], block)
		consensus.Propose(block.Hash().Bytes())
	}

	// TODO(xtaci) if i'm the committee member

	// the core consensus message loop
	log.Warn("CONSENSUS TASK STARTED", "coinbase", block.Coinbase(), "height", block.NumberU64())

	var proposed bool
	for {
		select {
		case obj := <-consensusMessageChan: // consensus message
			if ev, ok := obj.Data.(MessageInput); ok {
				var em EngineMessage
				err := proto.Unmarshal(ev, &em)
				if err != nil {
					log.Error("proto.Unmarshal", "err", err)
				}

				// we add an extra encapsulation for consensus contents
				switch em.Type {
				case EngineMessageType_Proposal:
					if !proposed {
						var proposal types.Block
						err := rlp.DecodeBytes(em.Message, &proposal)
						if err != nil {
							log.Error("proposerMessage", "rlp.DecodeBytes", err)
							continue
						}

						// verify proposal
						if !e.verifyProposal(chain, &proposal, block.NumberU64(), stakingObject) {
							log.Error("messageValidator verifyProposal failed")
							continue
						}

						// record & propose the block from a proposer
						allKeptBlocks[proposal.Coinbase()] = append(allKeptBlocks[proposal.Coinbase()], &proposal)
						consensus.Propose(proposal.Hash().Bytes())
						proposed = true
					}

				case EngineMessageType_Consensus:
					err := consensus.ReceiveMessage(em.Message, time.Now()) // input to core
					if err != nil {
						log.Debug("consensus receive:", "err", err)
					}
					newHeight, newRound, newState := consensus.CurrentState()

					// new height confirmed, only proposer broadcast this mined block
					if newHeight == block.NumberU64() {
						log.Warn("CONSENSUS <decide>", "height", newHeight, "round", newRound, "hash", newHeight, newRound, common.BytesToHash(newState))
						hash := common.BytesToHash(newState)

						// every validator can finalize this block to it's local blockchain now
						newblock := lookupProposal(hash)
						if newblock != nil {
							header := newblock.Header()
							bts, err := consensus.CurrentProof().Marshal()
							if err != nil {
								log.Crit("consensusMessenger", "consensus.CurrentProof", err)
								panic(err)
							}

							// store the the proof in block header
							header.Decision = bts

							// broadcast the mined block if i'm the proposer
							mined := newblock.WithSeal(header)
							// as block integrity is verified ahead in <roundchange> message,
							// it's safe to stop the consensus loop now
							results <- mined
						}
						return
					}
				}
			}

		case <-updateTick.C:
			consensus.Update(time.Now())
		case <-stop:
			results <- nil
			return
		}
	}
	return
}

// verify the proposer in block header
func (e *BDLSEngine) verifyProposer(chain consensus.ChainReader, stakingObject *StakingObject, header *types.Header) bool {
	// ensure the coinbase is a valid proposer
	if !e.IsProposer(chain, header, stakingObject) {
		log.Error("invalid proposer at given height", "height", header.Number, "proposer", header.Coinbase)
		return false
	}

	// ensure the block proposer is identical to coinbase
	copyHeader := types.CopyHeader(header)
	copyHeader.Signature = nil
	copyHeader.Decision = nil
	pk, err := crypto.Ecrecover(copyHeader.Hash().Bytes(), header.Signature)
	if err != nil {
		log.Error("ecrecover", "err", err)
		return false
	}
	if !crypto.VerifySignature(pk, copyHeader.Hash().Bytes(), header.Signature) {
		log.Error("verify signature")
		return false
	}

	pubkey, _ := crypto.DecompressPubkey(pk)
	signer := crypto.PubkeyToAddress(*pubkey)
	if signer != header.Coinbase {
		log.Error("signer do not match coinbase", "signer", pubkey, "coinbase", header.Coinbase)
	}
	return true
}

// verify states in block
func (e *BDLSEngine) verifyStates(block *types.Block) bool {
	// TODO: match proposer set

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
	return new(big.Int)
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *BDLSEngine) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "bdls",
		Version:   "1.0",
		Service:   &API{chain: chain, engine: e},
		Public:    true,
	}}
}

// Close terminates any background threads maintained by the consensus engine.
func (e *BDLSEngine) Close() error { return nil }
