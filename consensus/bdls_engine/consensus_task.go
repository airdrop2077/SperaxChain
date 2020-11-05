// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package bdls_engine

import (
	"bytes"
	"sync/atomic"
	"time"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/consensus/bdls_engine/committee"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/event"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/bdls"
	proto "github.com/gogo/protobuf/proto"
)

const (
	baseLatency               = 500 * time.Millisecond
	proposalCollectionTimeout = 5 * time.Second
)

// verify states in block
func (e *BDLSEngine) verifyStates(block *types.Block) bool {
	// check bad block
	if e.hasBadBlock != nil {
		if e.hasBadBlock(block.Hash()) {
			log.Debug("verifyStates - hasBadBlock", "e.hasBadBlock", block.Hash())
			return false
		}
	}

	// check transaction trie
	txnHash := types.DeriveSha(block.Transactions())
	if txnHash != block.Header().TxHash {
		log.Debug("verifyStates - validate transactions failed", "txnHash", txnHash, "Header().TxHash", block.Header().TxHash)
		return false
	}

	// Process the block to verify that the transactions are valid and to retrieve the resulting state and receipts
	// Get the state from this block's parent.
	state, err := e.stateAt(block.Header().ParentHash)
	if err != nil {
		log.Debug("verifyStates - Error in getting the block's parent's state", "parentHash", block.Header().ParentHash.Hex(), "err", err)
		return false
	}

	// Make a copy of the state
	state = state.Copy()

	// Apply this block's transactions to update the state
	receipts, _, usedGas, err := e.processBlock(block, state)
	if err != nil {
		log.Debug("verifyStates - Error in processing the block", "err", err)
		return false
	}

	// Validate the block
	if err := e.validateState(block, state, receipts, usedGas); err != nil {
		log.Debug("verifyStates - Error in validating the block", "err", err)
		return false
	}

	return true
}

// verify the proposer in block header
func (e *BDLSEngine) verifyProposerField(header *types.Header, state *state.StateDB) bool {
	// Ensure the coinbase is a valid proposer
	if !committee.IsProposer(header, state) {
		log.Debug("verifyProposerField - IsProposer", "height", header.Number, "proposer", header.Coinbase)
		return false
	}

	// otherwise we need to verify the signature of the proposer
	hash := e.SealHash(header).Bytes()
	// Ensure the signer is the coinbase
	pubkey, err := crypto.SigToPub(hash, header.Signature)
	if err != nil {
		log.Debug("verifyProposerField - SigToPub", "err", err)
		return false
	}

	signer := crypto.PubkeyToAddress(*pubkey)
	if signer != header.Coinbase {
		log.Debug("verifyProposerField - signer do not match coinbase", "signer", signer, "coinbase", header.Coinbase, "header", header)
		return false
	}

	// Verify signature
	pk, err := crypto.Ecrecover(hash, header.Signature)
	if err != nil {
		log.Debug("verifyProposerField - Ecrecover", "err", err)
		return false
	}
	if !crypto.VerifySignature(pk, hash, header.Signature[:64]) {
		log.Debug("verifyProposerField - verify signature failed", "signature", header.Signature, "hash:", hash)
		return false
	}

	return true
}

// verify a proposed block from remote
func (e *BDLSEngine) verifyRemoteProposal(chain consensus.ChainReader, block *types.Block, height uint64, state *state.StateDB) bool {
	header := block.Header()
	// verify the block number
	if header.Number.Uint64() != height {
		log.Debug("verifyRemoteProposal - mismatched block number", "actual", header.Number.Uint64(), "expected", height)
		return false
	}

	// verify header fields
	if err := e.verifyHeader(chain, header, nil); err != nil {
		log.Debug("verifyRemoteProposal - verifyHeader", "err", err)
		return false
	}

	// ensure it's a valid proposer
	if !e.verifyProposerField(header, state) {
		log.Debug("verifyRemoteProposal - verifyProposer failed")
		return false
	}

	// validate the states of transactions
	if !e.verifyStates(block) {
		log.Debug("verifyRemoteProposal - verifyStates failed")
		return false
	}

	return true
}

// sendProposal
func (e *BDLSEngine) sendProposal(block *types.Block) {
	bts, err := rlp.EncodeToBytes(block)
	if err != nil {
		log.Error("consensusTask", "rlp.EncodeToBytes", err)
		return
	}

	// marshal into EngineMessage and broadcast
	var msg EngineMessage
	msg.Type = EngineMessageType_Proposal
	msg.Message = bts
	msg.Nonce = atomic.AddUint32(&e.nonce, 1)

	out, err := proto.Marshal(&msg)
	if err != nil {
		log.Error("sendProposal", "proto.Marshal", err)
		return
	}

	// post this message
	err = e.mux.Post(MessageOutput(out))
	if err != nil {
		log.Error("sendProposal", "mux.Post", err)
		return
	}
}

// block comparision algorithm for consensus and proposal collection
func (e *BDLSEngine) blockCompare(blockA *types.Block, blockB *types.Block) int {
	// block comparision algorithm:
	// 1. block proposed by base quorum always have the lowest priority
	// 2. block proposed other than base quorum have higher priority
	// 3. same type of proposer compares it's proposer's hash
	// 4. if proposer's hash is identical, compare block hash
	if (committee.IsBaseQuorum(blockA.Coinbase()) && committee.IsBaseQuorum(blockB.Coinbase())) || (!committee.IsBaseQuorum(blockA.Coinbase()) && !committee.IsBaseQuorum(blockB.Coinbase())) {
		// compare proposer's hash
		ret := bytes.Compare(committee.ProposerHash(blockA.Header()).Bytes(), committee.ProposerHash(blockB.Header()).Bytes())
		if ret != 0 {
			return ret
		}
		// otherwise, compare it's block hash
		return bytes.Compare(blockA.Hash().Bytes(), blockB.Hash().Bytes())
	} else if committee.IsBaseQuorum(blockA.Coinbase()) && !committee.IsBaseQuorum(blockB.Coinbase()) {
		// block b has higher priority
		return -1
	}
	return 1
}

// a consensus task for a specific block
func (e *BDLSEngine) consensusTask(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) {

	// create a consensus message subscriber's loop
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

	// retrieve staking object at parent height
	state, err := e.stateAt(block.Header().ParentHash)
	if err != nil {
		log.Error("consensusTask - Error in getting the block's parent's state", "parentHash", block.Header().ParentHash.Hex(), "err", err)
		return
	}

	// the candidate block before consensus begins
	var candidateProposal *types.Block

	// retrieve private key for block signature & consensus message signature
	privateKey := e.waitForPrivateKey(block.Coinbase(), stop)
	if privateKey == nil {
		log.Error("consensusTask - Error in getting privateKey", "account", block.Coinbase())
		return
	}

	// seal with R
	header := block.Header()
	// ignore setting base quorum R
	if !committee.IsBaseQuorum(block.Coinbase()) {
		state, _ := e.stateAt(block.ParentHash())
		staker := committee.GetStakerData(block.Coinbase(), state)
		if header.Number.Uint64() > staker.StakingFrom && header.Number.Uint64() <= staker.StakingTo {
			// if it's in a valid staking period
			seed := committee.DeriveStakingSeed(privateKey, staker.StakingFrom)
			log.Debug("consensusTask", "stakingFrom", staker.StakingFrom, "stakingTo", staker.StakingTo, "block#", header.Number)
			header.R = common.BytesToHash(committee.HashChain(seed, header.Number.Uint64(), staker.StakingTo))
		}
	}

	// R has set, check if I'm the proposer
	if committee.IsProposer(header, state) {
		hash := e.SealHash(header).Bytes()
		sig, err := crypto.Sign(hash, privateKey)
		if err != nil {
			log.Error("Seal", "Sign", err, "sig:", sig)
		}
		// seal with Signature
		header.Signature = sig

		// replace the block with the signed one
		block = block.WithSeal(header)

		// record the candidate block which I proposed
		candidateProposal = block

		// time compensation to avoid fast block generation
		delay := time.Until(time.Unix(int64(block.Header().Time), 0))
		select {
		case <-time.After(delay):
		case <-stop:
			results <- nil
			return
		}

		// send the proposal as a proposer
		e.sendProposal(block)
	}

	// derive the participants from staking object at this height
	participants := committee.CreateValidators(block.Header(), state)

	// check if i'm the validator, stop here if i'm not a validator
	var isValidator bool
	identity := PubKeyToIdentity(&privateKey.PublicKey)
	for k := range participants {
		if participants[k] == identity {
			isValidator = true // mark i'm a validator
			break
		}
	}

	// job is done here if i'm not an validator
	if !isValidator {
		return
	}

	// prepare the maximum proposal by collecting proposals from proposers
	collectProposalTimeout := time.NewTimer(proposalCollectionTimeout)
	collectStart := time.Now()
	log.Warn("AS VALIDATOR", "Address", crypto.PubkeyToAddress(privateKey.PublicKey))
	log.Warn("PROPOSAL PRE-COLLECTION STARTED")

PROPOSAL_COLLECTION:

	// For proposal collection, we wait at least proposalCollectionTimeout and at least one proposal
	for {
		select {
		case obj, ok := <-consensusMessageChan: // consensus message
			if !ok {
				return
			}

			if ev, ok := obj.Data.(MessageInput); ok {
				var em EngineMessage
				err := proto.Unmarshal(ev, &em)
				if err != nil {
					log.Debug("proposal collection", "proto.Unmarshal", err)
					continue PROPOSAL_COLLECTION
				}

				// we add an extra encapsulation for consensus contents
				switch em.Type {
				case EngineMessageType_Proposal:
					var proposal types.Block
					err := rlp.DecodeBytes(em.Message, &proposal)
					if err != nil {
						log.Debug("proposal collection", "rlp.DecodeBytes", err)
						continue PROPOSAL_COLLECTION
					}

					// verify proposal fields
					if !e.verifyRemoteProposal(chain, &proposal, block.NumberU64(), state) {
						log.Debug("proposal collection - verifyRemoteProposal failed")
						continue PROPOSAL_COLLECTION
					}

					// record candidate blocks
					if candidateProposal == nil {
						candidateProposal = &proposal
					} else if e.blockCompare(&proposal, candidateProposal) > 0 {
						candidateProposal = &proposal
					}

					// at least one proposal confirmed, check if we have timeouted
					if time.Since(collectStart) > proposalCollectionTimeout {
						break PROPOSAL_COLLECTION
					}
				}
			}
		case <-collectProposalTimeout.C:
			// if candidate proposal has received, break now,
			// otherwise, wait for at least one proposal
			if candidateProposal != nil {
				break PROPOSAL_COLLECTION
			}
		case <-stop:
			return
		}
	}

	// BEGIN THE CORE CONSENSUS MESSAGE LOOP
	log.Warn("CONSENSUS TASK STARTED", "SEALHASH", e.SealHash(candidateProposal.Header()), "COINBASE", candidateProposal.Coinbase(), "HEIGHT", candidateProposal.NumberU64())

	// known proposed blocks from each participants' <roundchange> messages
	allBlocksInConsensus := make(map[common.Address][]*types.Block)

	// to lookup the block for current consensus height
	lookupConsensusBlock := func(hash common.Hash) *types.Block {
		// loop to find the block
		for _, blocks := range allBlocksInConsensus {
			for _, b := range blocks {
				if b.Hash() == hash {
					return b
				}
			}
		}
		return nil
	}

	// prepare callbacks(closures)
	// we need to prepare 3 closures for this height, one to track proposals from local or remote,
	// one to exchange the message from consensus core to p2p module, one to validate consensus
	// messages with proposed blocks from remote.
	messageOutCallback := func(m *bdls.Message, signed *bdls.SignedProto) {
		log.Debug("BDLS CONSENSUS MESSAGE", "TYPE", m.Type, "HEIGHT", m.Height, "ROUND", m.Round)
		// all outgoing signed message will be delivered to ProtocolManager
		// and finally to send to peers.
		bts, err := signed.Marshal()
		if err != nil {
			log.Error("messageOutCallback", "signed.Marshal", err)
			return
		}

		// marshal into EngineMessage and broadcast
		var msg EngineMessage
		msg.Type = EngineMessageType_Consensus
		msg.Message = bts
		msg.Nonce = atomic.AddUint32(&e.nonce, 1)

		out, err := proto.Marshal(&msg)
		if err != nil {
			log.Error("consensusTask", "proto.Marshal", err)
			return
		}

		// broadcast the message via event mux
		err = e.mux.Post(MessageOutput(out))
		if err != nil {
			log.Error("messageOutCallback", "mux.Post", err)
			return
		}
	}

	// setup consensus config at the given height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: block.NumberU64() - 1,
		PrivateKey:    privateKey,
		StateCompare: func(a bdls.State, b bdls.State) int {
			blockA := lookupConsensusBlock(common.BytesToHash(a))
			blockB := lookupConsensusBlock(common.BytesToHash(b))
			return e.blockCompare(blockA, blockB)
		},
		StateValidate: func(s bdls.State) bool {
			// make sure all states are known from <roundchange> exchanging
			hash := common.BytesToHash(s)
			return lookupConsensusBlock(hash) != nil
		},
		PubKeyToIdentity: PubKeyToIdentity,
		// consensus message will be routed through engine
		MessageOutCallback: messageOutCallback,
		Participants:       participants,
	}

	// create the consensus object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		log.Error("bdls.NewConsensus", "err", err)
		return
	}

	// set expected latency
	// network latency will be dynamically adjusted based on previous
	// blocks.
	latency := baseLatency
	parentHeader := chain.GetHeaderByNumber(block.NumberU64() - 1)
	if parentHeader.Decision != nil {
		sp, err := bdls.DecodeSignedMessage(parentHeader.Decision)
		if err != nil {
			panic(err)
		}

		message, err := bdls.DecodeMessage(sp.Message)
		if err != nil {
			panic(err)
		}

		// update consensus latency based on previous block
		latency = baseLatency * (1 << message.Round)
	}

	log.Warn("CONSENSUS LATENCY SET", "LATENCY", latency)
	consensus.SetLatency(latency)

	// the consensus updater ticker
	updateTick := time.NewTicker(20 * time.Millisecond)
	defer updateTick.Stop()

	// the proposal resending ticker
	resendProposalTick := time.NewTicker(10 * time.Second)
	defer resendProposalTick.Stop()

	// cache the candidate block
	allBlocksInConsensus[candidateProposal.Coinbase()] = append(allBlocksInConsensus[candidateProposal.Coinbase()], candidateProposal)
	// propose the block hash
	consensus.Propose(candidateProposal.Hash().Bytes())

	// core consensus loop
CONSENSUS_TASK:
	for {
		select {
		case obj, ok := <-consensusMessageChan: // consensus message
			if !ok {
				return
			}

			if ev, ok := obj.Data.(MessageInput); ok {
				var em EngineMessage
				err := proto.Unmarshal(ev, &em)
				if err != nil {
					log.Error("proto.Unmarshal", "err", err)
				}

				switch em.Type {
				case EngineMessageType_Consensus:
					err := consensus.ReceiveMessage(em.Message, time.Now()) // input to core
					if err != nil {
						//	log.Debug("consensus receive:", "err", err)
					}
					newHeight, newRound, newState := consensus.CurrentState()

					// new block confirmed
					if newHeight == block.NumberU64() {
						hash := common.BytesToHash(newState)
						log.Warn("BDLS CONSENSUS <decide>", "HEIGHT", newHeight, "ROUND", newRound, "SEALHASH", hash)

						// every validator can finalize this block to it's local blockchain now
						newblock := lookupConsensusBlock(hash)
						if newblock != nil {
							// mined by me
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
							results <- mined
						}
						return
					}
				case EngineMessageType_Proposal: // keep updating local block cache
					var proposal types.Block
					err := rlp.DecodeBytes(em.Message, &proposal)
					if err != nil {
						log.Debug("proposal during consensus", "rlp.DecodeBytes", err)
						continue CONSENSUS_TASK
					}

					// verify proposal fields
					if !e.verifyRemoteProposal(chain, &proposal, block.NumberU64(), state) {
						log.Debug("proposal during consensus - verifyRemoteProposal failed")
						continue CONSENSUS_TASK
					}

					// A simple DoS prevention mechanism:
					// 1. Remove previously kept blocks which has NOT been accepted in consensus.
					// 2. Always record the latest proposal from a proposer, before consensus continues
					var repeated bool
					var keptBlocks []*types.Block
					for _, pBlock := range allBlocksInConsensus[proposal.Coinbase()] {
						if consensus.HasProposed(pBlock.Hash().Bytes()) {
							keptBlocks = append(keptBlocks, pBlock)
							// repeated valid block
							if pBlock.Hash() == proposal.Hash() {
								repeated = true
							}
						}
					}

					if !repeated { // record new proposal of a block
						keptBlocks = append(keptBlocks, &proposal)
					}
					// update cache
					allBlocksInConsensus[proposal.Coinbase()] = keptBlocks
				}
			}

		case <-resendProposalTick.C:
			// we need to resend the proposal periodically to prevent some nodes missed the message
			log.Debug("consensusTask", "resend proposal block#", candidateProposal.Hash())
			e.sendProposal(candidateProposal)
		case <-updateTick.C:
			_ = consensus.Update(time.Now())
		case <-stop:
			return
		}
	}
}
