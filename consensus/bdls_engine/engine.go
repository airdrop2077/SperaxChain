package bdls_engine

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/accounts"
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

var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errInvalidDifficulty is returned if the difficulty of a block is not 1
	errInvalidDifficulty = errors.New("invalid difficulty")
	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")
	// errInvalidNonce is returned if a block's nonce is invalid
	errInvalidNonce = errors.New("invalid nonce")
	// empty decision field
	errEmptyDecision = errors.New("empty decision field")
	// invalid input consensus message
	errInvalidConsensusMessage = errors.New("invalid input consensus message")
	// errInvalidTimestamp is returned if the timestamp of a block is lower than the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")
)

var (
	defaultDifficulty = big.NewInt(1)
	nilUncleHash      = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	emptyNonce        = types.BlockNonce{}
)

// For consensus message event I/O
type (
	// protocol manager will subscribe to this consensus message
	ConsensusMessageOutput []byte
	// protocol manager will deliver this consensus message type
	ConsensusMessageInput []byte
)

// ConsensusMessageHash return the consistent hash based on SignedMessage content(with out R, S)
func ConsensusMessageHash(bts []byte) (common.Hash, error) {
	sp, err := bdls.DecodeSignedMessage(bts)
	if err != nil {
		return common.Hash{}, errInvalidConsensusMessage
	}

	return common.BytesToHash(sp.Hash()), nil
}

const (
	// minimum difference between two consecutive block's timestamps in second
	minBlockPeriod = 3
)

// PublicKey to Identity conversion, for use in BDLS
func PubKeyToIdentity(pubkey *ecdsa.PublicKey) (ret bdls.Identity) {
	// for a publickey first we convert to ethereum common.Address
	commonAddress := crypto.PubkeyToAddress(*pubkey)
	// then we just byte copy to Coordiante struct
	copy(ret[:], commonAddress[:])
	return
}

// BDLSEngine implements blockchain consensus engine
type BDLSEngine struct {
	// ephermal private key for verification
	ephermalKey *ecdsa.PrivateKey

	// event mux to send consensus message as events
	mux *event.TypeMux

	// the account manager to get private key
	accountManager *accounts.Manager

	// pre-validator for <roundchange> message
	stateAt       func(hash common.Hash) (*state.StateDB, error)
	hasBadBlock   func(hash common.Hash) bool
	processBlock  func(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error)
	validateState func(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error

	// mutex for BDLSEngine
	mu sync.Mutex
}

func New(accountManager *accounts.Manager, mux *event.TypeMux) *BDLSEngine {
	engine := new(BDLSEngine)
	engine.mux = mux
	engine.accountManager = accountManager

	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Crit("BDLS generate ephermal key", "err", err)
	}
	engine.ephermalKey = priv
	return engine
}

// BytesHash computes keccak256 hash for a slice
func BytesHash(bts []byte) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, bts)
	hw.Sum(h[:0])
	return h
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

// Signer returns the final signer of this header
func (e *BDLSEngine) Signer(header *types.Header) (common.Address, error) {
	if len(header.Decision) > 0 {
		sp, err := bdls.DecodeSignedMessage(header.Decision)
		if err != nil {
			return common.Address{}, err
		}

		pubkey := &ecdsa.PublicKey{Curve: e.ephermalKey.Curve, X: big.NewInt(0).SetBytes(sp.X[:]), Y: big.NewInt(0).SetBytes(sp.Y[:])}
		return crypto.PubkeyToAddress(*pubkey), nil
	}
	return common.Address{}, errEmptyDecision
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *BDLSEngine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return e.verifyHeader(chain, header, nil)
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
// NOTE(xtaci): downloader's batch verification
func (e *BDLSEngine) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Short circuit if the header is known, or its parent not
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

	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if header.Difficulty == nil || header.Difficulty.Cmp(defaultDifficulty) != 0 {
		return errInvalidDifficulty
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

	// verify decision content
	if err := e.VerifySeal(chain, header); err != nil {
		return err
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

	// step 0. Check decision field is not nil
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

	// TODO: to set the participants from previous blocks?
	// currently it's fixed to initial validator
	participants := chain.Config().BDLS.Participants
	// type conversion in BDLS core
	for k := range participants {
		var identity bdls.Identity
		copy(identity[:], participants[k][:])
		config.Participants = append(config.Participants, identity)
	}

	// step 3. create the consensus object to validate decide message
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("new consensus:", err)
		return err
	}

	// step 3. validate decide message integrity to sealHash
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

// a consensus task for a specific block
func (e *BDLSEngine) consensusTask(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) {

	// get to private key from account manager
	var privateKey *ecdsa.PrivateKey
WAIT_FOR_PRIVATEKEY:
	for {
		select {
		case <-stop:
			results <- nil
			return
		default:
			log.Debug("looking for the wallet of coinbase:", "coinbase", block.Coinbase())
			e.mu.Lock()
			wallet, err := e.accountManager.Find(accounts.Account{Address: block.Coinbase()})
			if err != nil {
				e.mu.Unlock()
				log.Error("cannot find the wallet of coinbase", "coinbase", block.Coinbase())
				return
			}

			priv, err := wallet.GetPrivateKey(accounts.Account{Address: block.Coinbase()})
			if err != nil {
				e.mu.Unlock()
				<-time.After(time.Second) // wait for a second before retry
				continue
			}
			e.mu.Unlock()

			privateKey = priv
			break WAIT_FOR_PRIVATEKEY
		}
	}

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
		log.Debug("consensus sending message", "type", m.Type)
		// for <roundchange> message, we need to append the corresponding types.Block to the message
		switch m.Type {
		case bdls.MessageType_RoundChange:
			blockHash := common.BytesToHash(m.State)
			var outblock *types.Block

			// find blocks & assembly to auxdata
			if blockHash == e.SealHash(block.Header()) {
				// locally proposed block
				outblock = block
			} else {
				// externally proposed block
				outblock = lookupBlock(blockHash)
			}

			if outblock == nil {
				log.Warn("cannot find block", "hash", blockHash)
				return
			}

			blockData, err := rlp.EncodeToBytes(outblock)
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
		log.Debug("consensus received message", "type", m.Type)
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
				log.Error("messageValidator auxdata hash", "seal hash", e.SealHash(blk.Header()), "state hash", common.BytesToHash(m.State))
				return false
			}

			//  step 2
			parentHeader := chain.GetHeader(blk.ParentHash(), blk.NumberU64()-1)
			if parentHeader == nil {
				log.Error("unknown ancestor", "parenthash", blk.ParentHash(), "number", blk.NumberU64()-1)
				return false
			}

			// step 2. validate the proposed block
			if !e.verifyProposalBlock(&blk) {
				log.Error("verify Proposal block failed")
				return false
			}

			// step 3. record or replace this block, the coinbase has verified against signature in VerifyProposal
			pubkey := &ecdsa.PublicKey{Curve: e.ephermalKey.Curve, X: big.NewInt(0).SetBytes(signed.X[:]), Y: big.NewInt(0).SetBytes(signed.Y[:])}
			signerAddr := crypto.PubkeyToAddress(*pubkey)

			// TODO: to set the participants from previous blocks?
			// currently it's fixed to initial validator
			participants := chain.Config().BDLS.Participants
			for k := range participants {
				if participants[k] == signerAddr {
					knownBlocks[signerAddr] = &blk
					return true
				}
			}

			log.Error("cannot find signer in participant", "addr", signerAddr)
			return false
		}

		return true
	}

	// step 2. setup consensus config at given height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: block.NumberU64() - 1,
		PrivateKey:    privateKey,
		// TODO(xtaci): (shuffle and set participants sequence based on some random number)
		StateCompare: func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(s bdls.State) bool {
			// make sure all states are known from <roundchange> exchanging
			hash := common.BytesToHash(s)
			if lookupBlock(hash) != nil {
				return true
			}

			return false
		},
		PubKeyToIdentity: PubKeyToIdentity,
		MessageValidator: messageValidator,
		// consensus message will be routed through engine
		MessageOutCallback: messageOutCallback,
	}

	participants := chain.Config().BDLS.Participants
	// identity conversion from common.Address
	for k := range participants {
		var identity bdls.Identity
		copy(identity[:], participants[k][:])
		config.Participants = append(config.Participants, identity)
	}

	e.mu.Unlock()

	// step 3. create the consensus object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("bdls.NewConsensus", "err", err)
		return
	}

	// step 4. propose the block hash
	consensus.Propose(sealHash.Bytes())

	// step 5: step delay by last block timestamp
	consensus.SetLatency(time.Second)

	// step 5. create a consensus message subscriber's loop
	// subscribe to consensus message input via event mux
	var consensusMessageChan <-chan *event.TypeMuxEvent
	if e.mux != nil {
		consensusSub := e.mux.Subscribe(ConsensusMessageInput{})
		defer consensusSub.Unsubscribe()
		consensusMessageChan = consensusSub.Chan()
	} else {
		log.Error("mux is nil")
		return
	}

	// the consensus updater ticker
	updateTick := time.NewTicker(20 * time.Millisecond)
	defer updateTick.Stop()

	// the core consensus message loop
	log.Warn("CONSENSUS TASK STARTED", "coinbase", block.Coinbase(), "height", block.NumberU64())
	for {
		select {
		case obj, ok := <-consensusMessageChan: // from p2p
			if !ok {
				log.Error("cosnensusMessageChan closed")
				return
			}

			if ev, ok := obj.Data.(ConsensusMessageInput); ok {
				err := consensus.ReceiveMessage(ev, time.Now()) // input to core
				if err != nil {
					log.Warn("consensus receive:", "err", err)
				}
				newHeight, newRound, newState := consensus.CurrentState()

				// new height confirmed, only proposer broadcast this mined block
				if newHeight == block.NumberU64() {
					log.Warn("CONSENSUS <decide>", "height", newHeight, "round", newRound, "hash", newHeight, newRound, common.BytesToHash(newState))
					hash := common.BytesToHash(newState)

					// every validator can finalize this block to it's local blockchain now
					newblock := lookupBlock(hash)
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

		case <-updateTick.C:
			consensus.Update(time.Now())
		case <-stop:
			results <- nil
			return
		}
	}
	return
}

// VerifyProposalBlock implements blockchain specific block validator
func (e *BDLSEngine) verifyProposalBlock(block *types.Block) bool {
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
	/* TODO(xtaci): implement APIs
	return []rpc.API{{
		Namespace: "bdls",
		Version:   "1.0",
		Service:   nil,
		Public:    true,
	}}
	*/
	return nil
}

// Close terminates any background threads maintained by the consensus engine.
func (e *BDLSEngine) Close() error {
	return nil
}

// mining reward computation
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header) {
	state.AddBalance(header.Coinbase, big.NewInt(100))
}
