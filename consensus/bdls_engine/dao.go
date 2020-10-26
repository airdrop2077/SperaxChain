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
	GasFeeAddress        = common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
)

// mining reward computation
func (e *BDLSEngine) accumulateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header) {
	// Reward Block Proposer
	state.AddBalance(header.Coinbase, ProposerReward)

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
	sharedGasFee := parentState.GetBalance(GasFeeAddress)

	// reward validators from previous block
	if parentHeader.Decision != nil {
		sp, err := bdls.DecodeSignedMessage(parentHeader.Decision)
		if err != nil {
			panic(err)
		}
		message, err := bdls.DecodeMessage(sp.Message)

		if len(message.Proof) > 0 {
			// gas fee
			gasFeeShare := big.NewInt(0).Quo(sharedGasFee, big.NewInt(int64(len(message.Proof))))
			blockRewardShare := big.NewInt(0).Quo(TotalValidatorReward, big.NewInt(int64(len(message.Proof))))
			for _, proof := range message.Proof {
				address := crypto.PubkeyToAddress(*proof.PublicKey(crypto.S256()))
				state.AddBalance(address, gasFeeShare)
				state.AddBalance(address, blockRewardShare)
			}
		}
	}

	// refund all expired staking tokens at current state
	stakers := GetAllStakers(state)
	for k := range stakers {
		staker := GetStaker(stakers[k], state)
		if header.Number.Uint64() == staker.StakingTo+1 { // expired, refund automatically at height stakingTo+1
			state.AddBalance(staker.Address, staker.StakedValue)
			state.SubBalance(StakingAddress, staker.StakedValue)
			RemoveStaker(stakers[k], state)
		}
	}
}
