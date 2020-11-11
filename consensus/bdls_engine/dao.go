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
	fmt "fmt"
	"math/big"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/consensus/bdls_engine/committee"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/core/vm"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/bdls"
)

var (
	// Proposer's SPA reward
	ProposerReward       = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	TotalValidatorReward = new(big.Int).Mul(big.NewInt(3000), big.NewInt(params.Ether))
	GasFeeAddress        = common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
	Multiplier           = big.NewInt(1e18)
)

const (
	// statistics stored in account storage trie of GasFeeAddress
	// global
	KeyTotalGasFeeRewards    = "/v1/totalGasFeeRewards"
	KeyTotalValidatorRewards = "/v1/totalValidatorRewards"
	KeyTotalProposerRewards  = "/v1/totalProposerRewards"

	// account
	KeyAccountTotalGasFeeRewards = "/v1/%v/totalGasFeeRewards"
	KeyAccountTotalBlockRewards  = "/v1/%v/totalBlockRewards"
)

// getMapValue retrieves the value with key from account: StakingAddress
func getMapValue(addr common.Address, key string, state vm.StateDB) common.Hash {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr)))
	return state.GetState(GasFeeAddress, keyHash)
}

// setMapValue sets the value with key to account: StakingAddress
func setMapValue(addr common.Address, key string, value common.Hash, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr)))
	state.SetState(GasFeeAddress, keyHash, value)
}

// getTotalGasFees retrieves total gas fee reward from account storage trie
func getTotalGasFees(state vm.StateDB) *big.Int {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalGasFeeRewards))
	return state.GetState(GasFeeAddress, keyHash).Big()
}

// setTotalGasFees sets the total gas fee reward to account storage trie
func setTotalGasFees(number *big.Int, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalGasFeeRewards))
	state.SetState(GasFeeAddress, keyHash, common.BigToHash(number))
}

// getTotalValidatorReward retrieves total validators reward from account storage trie
func getTotalValidatorReward(state vm.StateDB) *big.Int {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalValidatorRewards))
	return state.GetState(GasFeeAddress, keyHash).Big()
}

// setTotalValidatorReward sets the total validators reward to account storage trie
func setTotalValidatorReward(number *big.Int, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalValidatorRewards))
	state.SetState(GasFeeAddress, keyHash, common.BigToHash(number))
}

// getTotalProposerReward retrieves total gas fee from account storage trie
func getTotalProposerReward(state vm.StateDB) *big.Int {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalProposerRewards))
	return state.GetState(GasFeeAddress, keyHash).Big()
}

// setTotalProposerReward sets the total gas fee to account storage trie
func setTotalProposerReward(number *big.Int, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalProposerRewards))
	state.SetState(GasFeeAddress, keyHash, common.BigToHash(number))
}

// mining reward computation
func (e *BDLSEngine) accumulateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header) {
	if !committee.IsBaseQuorum(header.Coinbase) {
		// Reward Block Proposer if it's not base quorum
		state.AddBalance(header.Coinbase, ProposerReward)

		// statistics for  total proposer rewards distributed
		totalProposerRewards := getTotalProposerReward(state)
		totalProposerRewards.Add(totalProposerRewards, ProposerReward)
		setTotalProposerReward(totalProposerRewards, state)
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

	// reward validators from previous block
	sharedGasFee := parentState.GetBalance(GasFeeAddress)
	if parentHeader.Decision != nil {
		sp, err := bdls.DecodeSignedMessage(parentHeader.Decision)
		if err != nil {
			panic(err)
		}

		message, err := bdls.DecodeMessage(sp.Message)
		if err != nil {
			panic(err)
		}

		if len(message.Proof) > 0 {
			totalStaked := committee.TotalStaked(parentState)
			// no value staked
			if totalStaked.Cmp(common.Big0) > 0 {
				// gasFeePercentageGain = sharedGasFee * 1e18 / totalStaked
				// we multiplied by 1e18 here to avoid underflow
				gasFeePercentageGain := new(big.Int)
				gasFeePercentageGain.Mul(sharedGasFee, Multiplier)
				gasFeePercentageGain.Div(gasFeePercentageGain, totalStaked)

				// blockRewardPercentageGain = (totalvalidator reward) * 1e18 / totalStaked
				// we multiplied by 1e18 here to avoid underflow
				blockRewardPercentageGain := new(big.Int)
				blockRewardPercentageGain.Mul(TotalValidatorReward, Multiplier)
				blockRewardPercentageGain.Div(blockRewardPercentageGain, totalStaked)

				// gas fee will be distributed evenly for how much staker's has staked
				gasFee := new(big.Int)
				blockReward := new(big.Int)
				for _, proof := range message.Proof {
					address := crypto.PubkeyToAddress(*proof.PublicKey(crypto.S256()))
					staker := committee.GetStakerData(address, state)

					gasFee.Mul(gasFeePercentageGain, staker.StakedValue)
					gasFee.Div(gasFee, Multiplier)

					blockReward.Mul(blockRewardPercentageGain, staker.StakedValue)
					blockReward.Div(blockReward, Multiplier)

					// each validator claim it's gas share, and reset balance in account: GasFeeAddress
					state.AddBalance(address, gasFee)
					state.SubBalance(GasFeeAddress, gasFee)

					// each validator claim it's block reward share
					state.AddBalance(address, blockReward)
				}

				// statistics
				// total gas fee distributed
				totalGas := getTotalGasFees(state)
				totalGas.Add(totalGas, sharedGasFee)
				setTotalGasFees(totalGas, state)

				// total validator rewards distributed
				totalValidatorRewards := getTotalValidatorReward(state)
				totalValidatorRewards.Add(totalValidatorRewards, TotalValidatorReward)
				setTotalValidatorReward(totalValidatorRewards, state)
			}
		}
	}

	// refund all expired staking tokens at current state
	stakers := committee.GetAllStakers(state)
	for k := range stakers {
		staker := committee.GetStakerData(stakers[k], state)
		if header.Number.Uint64() > staker.StakingTo { // expired, refund automatically after stakingTo
			log.Debug("STAKING EXPIRED:", "account", staker.Address, "value", staker.StakedValue)
			state.AddBalance(staker.Address, staker.StakedValue)
			state.SubBalance(committee.StakingAddress, staker.StakedValue)

			// make sure to remove from list
			committee.RemoveStakerFromList(stakers[k], state)
		}
	}
}
