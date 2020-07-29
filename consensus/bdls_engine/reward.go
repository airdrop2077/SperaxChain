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
	"math/big"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/bdls"
)

var (
	// Proposer's SPA reward
	ProposerReward       = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	TotalValidatorReward = new(big.Int).Mul(big.NewInt(3000), big.NewInt(params.Ether))
	GasFeeAddress        = common.Address{0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD}
)

// mining reward computation
func (e *BDLSEngine) accumulateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header) {
	if header.Coinbase == StakingAddress {
		// ignore empty block
		return
	}

	// Proposer's reward
	state.AddBalance(header.Coinbase, new(big.Int).Mul(ProposerReward, big.NewInt(params.Ether)))

	// Divide TotalValidatorReward evenly for current block
	sp, err := bdls.DecodeSignedMessage(header.Decision)
	if err != nil {
		panic(err)
	}
	message, err := bdls.DecodeMessage(sp.Message)

	if len(message.Proof) > 0 {
		share := big.NewInt(0).Quo(TotalValidatorReward, big.NewInt(int64(len(message.Proof))))
		for _, proof := range message.Proof {
			address := crypto.PubkeyToAddress(*proof.PublicKey(crypto.S256()))
			// each validator's reward
			state.AddBalance(address, new(big.Int).Mul(share, big.NewInt(params.Ether)))
		}
	}

	// Ensure the parent is not nil
	parentHeader := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parentHeader == nil {
		return
	}

	// retrieve the gas fee account at parent height
	parentState, err := e.stateAt(header.ParentHash)
	if err != nil {
		return
	}

	if parentHeader.Decision != nil {
		sp, err := bdls.DecodeSignedMessage(parentHeader.Decision)
		if err != nil {
			panic(err)
		}
		message, err := bdls.DecodeMessage(sp.Message)

		if len(message.Proof) > 0 {
			// share gas fees from last height
			share := big.NewInt(0).Quo(parentState.GetBalance(GasFeeAddress), big.NewInt(int64(len(message.Proof))))
			for _, proof := range message.Proof {
				address := crypto.PubkeyToAddress(*proof.PublicKey(crypto.S256()))
				state.AddBalance(address, share)
			}
		}
	}
}
