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
	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus"
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
