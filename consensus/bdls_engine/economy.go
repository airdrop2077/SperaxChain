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
	"runtime"

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
	// Account to deposit gas fee
	GasFeeAddress = common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
	Multiplier    = big.NewInt(1e18)
)

const (
	// statistics stored in account storage trie of GasFeeAddress
	// global
	KeyTotalGasFeeRewards    = "/v1/stats/totalGasFeeRewards"
	KeyTotalValidatorRewards = "/v1/stats/totalValidatorRewards"
	KeyTotalProposerRewards  = "/v1/stats/totalProposerRewards"

	// account
	KeyAccountGasFeeRewards    = "/v1/stats/%s/totalGasFeeRewards"
	KeyAccountValidatorRewards = "/v1/stats/%s/totalValidatorRewards"
	KeyAccountProposerRewards  = "/v1/stats/%s/totalProposerRewards"
)

// getMapValue retrieves the value with key from account: StakingAddress
func getMapValue(addr common.Address, key string, state vm.StateDB) common.Hash {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr.String())))
	return state.GetCommittedState(committee.StakingAddress, keyHash)
}

// setMapValue sets the value with key to account: StakingAddress
func setMapValue(addr common.Address, key string, value common.Hash, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr.String())))
	state.SetState(committee.StakingAddress, keyHash, value)
}

// getTotalGasFees retrieves total gas fee reward from account storage trie
func getTotalGasFees(state vm.StateDB) *big.Int {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalGasFeeRewards))
	return state.GetState(committee.StakingAddress, keyHash).Big()
}

// setTotalGasFees sets the total gas fee reward to account storage trie
func setTotalGasFees(number *big.Int, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalGasFeeRewards))
	state.SetState(committee.StakingAddress, keyHash, common.BigToHash(number))
}

// getTotalValidatorRewards retrieves total validators reward from account storage trie
func getTotalValidatorRewards(state vm.StateDB) *big.Int {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalValidatorRewards))
	return state.GetState(committee.StakingAddress, keyHash).Big()
}

// setTotalValidatorRewards sets the total validators reward to account storage trie
func setTotalValidatorRewards(number *big.Int, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalValidatorRewards))
	state.SetState(committee.StakingAddress, keyHash, common.BigToHash(number))
}

// getTotalProposerRewards retrieves total gas fee from account storage trie
func getTotalProposerRewards(state vm.StateDB) *big.Int {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalProposerRewards))
	return state.GetState(committee.StakingAddress, keyHash).Big()
}

// setTotalProposerRewards sets the total gas fee to account storage trie
func setTotalProposerRewards(number *big.Int, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(KeyTotalProposerRewards))
	state.SetState(committee.StakingAddress, keyHash, common.BigToHash(number))
}

func PrintPanicStack() {
	i := 0
	funcName, file, line, ok := runtime.Caller(i)
	for ok {
		fmt.Printf("frame %v:[func:%v,file:%v,line:%v]\n", i, runtime.FuncForPC(funcName).Name(), file, line)
		i++
		funcName, file, line, ok = runtime.Caller(i)
	}
}

// mining reward computation
func (e *BDLSEngine) accumulateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header) {
	if !committee.IsBaseQuorum(header.Coinbase) {
		// Reward Block Proposer if it's not base quorum
		state.AddBalance(header.Coinbase, ProposerReward)

		// statistics for  total proposer rewards distributed
		totalProposerRewards := getTotalProposerRewards(state)
		totalProposerRewards.Add(totalProposerRewards, ProposerReward)
		setTotalProposerRewards(totalProposerRewards, state)

		// per account proposer rewards statistics
		accountProposerRewards := getMapValue(header.Coinbase, KeyAccountProposerRewards, state).Big()
		accountProposerRewards.Add(accountProposerRewards, ProposerReward)
		setMapValue(header.Coinbase, KeyAccountProposerRewards, common.BigToHash(accountProposerRewards), state)
	}

	// Ensure the parent is not nil
	parentHeader := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parentHeader == nil {
		return
	}

	// reward validators from previous block
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
			validatorsStaked := new(big.Int)

			// retrieve unique validators
			stakers := make(map[common.Address]bool)
			for k := range message.Proof {
				account := crypto.PubkeyToAddress(*message.Proof[k].PublicKey(crypto.S256()))
				stakers[account] = true
			}

			// sum total stakes from unique validators
			for account := range stakers {
				// NOTE: a validator at height N is immutable
				staker := committee.GetStakerData(account, state)
				if staker.StakedValue.Cmp(common.Big0) > 0 {
					validatorsStaked.Add(validatorsStaked, staker.StakedValue)
				} else {
					stakers[account] = false
				}
			}

			// no value staked
			if validatorsStaked.Cmp(common.Big0) > 0 {
				// retrieve the gas fee account at current height
				// the current balance of GasFeeAddress is the result of transactions at current height
				// and will be distributed at next block
				sharedGasFee := state.GetBalance(GasFeeAddress)

				// gasFeePercentageGain = sharedGasFee * 1e18 / totalStaked
				// we multiplied by 1e18 here to avoid underflow
				gasFeePercentageGain := new(big.Int)
				gasFeePercentageGain.Mul(sharedGasFee, Multiplier)
				gasFeePercentageGain.Div(gasFeePercentageGain, validatorsStaked)

				// blockRewardPercentageGain = (totalvalidator reward) * 1e18 / totalStaked
				// we multiplied by 1e18 here to avoid underflow
				blockRewardPercentageGain := new(big.Int)
				blockRewardPercentageGain.Mul(TotalValidatorReward, Multiplier)
				blockRewardPercentageGain.Div(blockRewardPercentageGain, validatorsStaked)

				// gas fee will be distributed evenly for how much staker's has staked
				gasFee := new(big.Int)
				blockReward := new(big.Int)
				for _, proof := range message.Proof {
					address := crypto.PubkeyToAddress(*proof.PublicKey(crypto.S256()))
					if stakers[address] {
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

						// per account gas fee statistics
						accountGasFeeRewards := getMapValue(address, KeyAccountGasFeeRewards, state).Big()
						accountGasFeeRewards.Add(accountGasFeeRewards, gasFee)
						setMapValue(address, KeyAccountGasFeeRewards, common.BigToHash(accountGasFeeRewards), state)

						// per account block rewards statistics
						accountBlockRewards := getMapValue(address, KeyAccountValidatorRewards, state).Big()
						accountBlockRewards.Add(accountBlockRewards, blockReward)
						setMapValue(address, KeyAccountValidatorRewards, common.BigToHash(accountBlockRewards), state)

						// mark we've processed with this staker
						stakers[address] = false
					}
				}

				// statistics
				// total gas fee distributed
				totalGas := getTotalGasFees(state)
				totalGas.Add(totalGas, sharedGasFee)
				setTotalGasFees(totalGas, state)

				// total validator rewards distributed
				totalValidatorRewards := getTotalValidatorRewards(state)
				totalValidatorRewards.Add(totalValidatorRewards, TotalValidatorReward)
				setTotalValidatorRewards(totalValidatorRewards, state)

				// NOTE:
				//
				// The stats data above needs to be kept in statedb for ACCOUNTABILITY, i.e.
				// stakers cannot deny their rewards.
				//
				// The stats data below will be kept in snapshot for REWARDING ALGORITHM
				// like:
				// 	Reward Moving Average(MA)
				// 	Windowed Inflow + MA
				// 	Windowed Outflow + MA
				// 	...
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
