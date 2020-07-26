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
	"time"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/event"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/bdls"
	proto "github.com/gogo/protobuf/proto"
)

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
			if !e.verifyExternalProposal(chain, &proposal, block.NumberU64(), stakingObject) {
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
	config.Participants = e.CreateValidators(block.Header(), stakingObject)
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
	if e.IsProposer(block.Header(), stakingObject) {
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
					if !proposed { // we only accept one valid proposal
						var proposal types.Block
						err := rlp.DecodeBytes(em.Message, &proposal)
						if err != nil {
							log.Error("proposerMessage", "rlp.DecodeBytes", err)
							continue
						}

						// verify proposal
						if !e.verifyExternalProposal(chain, &proposal, block.NumberU64(), stakingObject) {
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
