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
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/rpc"
	"github.com/Sperax/bdls"
)

// API is a user facing RPC API to dump BDLS state
type API struct {
	chain  consensus.ChainReader
	engine *BDLSEngine
}

func (api *API) Version() string {
	return "1.0"
}

// GetValidators returns the validator addresses at specific block height
func (api *API) GetValidators(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}

	// Ensure we have an actually valid block and return the validators from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}

	return api.decodeValidators(header.Decision)
}

// GetValidatorsAtHash returns the validator addresses at specific block hash
func (api *API) GetValidatorsAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)

	// Ensure we have an actually valid block and return the validators from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}

	return api.decodeValidators(header.Decision)
}

// GetTotalStake returns the total staked value
func (api *API) GetTotalStaked() (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return committee.TotalStaked(state), nil
}

// GetTotalStakingOperations returns the total staking operations performed
func (api *API) GetTotalStakingOperations() (count uint64, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return 0, err
	}

	return state.GetNonce(committee.StakingAddress), nil
}

// GetStakers returns a map for all stakers and it's value
func (api *API) GetStakers() (stakers []*committee.Staker, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	stakerAccounts := committee.GetAllStakers(state)
	for _, account := range stakerAccounts {
		stakers = append(stakers, committee.GetStakerData(account, state))
	}

	return stakers, nil
}

// GetStaker returns a staker's information
func (api *API) GetStaker(account common.Address) (stakers *committee.Staker, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return committee.GetStakerData(account, state), nil
}

// GetTotalGasFeeRewards returns the total staked value
func (api *API) GetTotalGasFeeRewards() (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return getTotalGasFees(state), nil
}

// GetTotalValidatorRewards returns the total staked value
func (api *API) GetTotalValidatorRewards() (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return getTotalValidatorRewards(state), nil
}

// GetTotalProposerRewards returns the total staked value
func (api *API) GetTotalProposerRewards() (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return getTotalProposerRewards(state), nil
}

// GetAccountGasFeeRewards returns the total staked value
func (api *API) GetAccountGasFeeRewards(account common.Address) (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return getMapValue(account, KeyAccountGasFeeRewards, state).Big(), nil
}

// GetAccountProposerRewards returns the total staked value
func (api *API) GetAccountProposerRewards(account common.Address) (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	return getMapValue(account, KeyAccountProposerRewards, state).Big(), nil
}

// GetAccountValidatorRewards returns the total staked value
func (api *API) GetAccountValidatorRewards(account common.Address) (total *big.Int, err error) {
	header := api.chain.CurrentHeader()
	state, err := api.engine.stateAt(header.Hash())
	if err != nil {
		return nil, err
	}

	fmt.Println("height:", header.Number)

	return getMapValue(account, KeyAccountValidatorRewards, state).Big(), nil
}

func (api *API) decodeValidators(decision []byte) ([]common.Address, error) {
	var validators []common.Address
	if decision != nil {
		sp, err := bdls.DecodeSignedMessage(decision)
		if err != nil {
			return nil, err
		}

		m, err := bdls.DecodeMessage(sp.Message)
		if err != nil {
			return nil, err
		}

		for _, proof := range m.Proof {
			addr := crypto.PubkeyToAddress(*proof.PublicKey(crypto.S256()))
			validators = append(validators, addr)
		}
	}

	return validators, nil
}
