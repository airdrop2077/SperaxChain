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
	"encoding/binary"
	"errors"
	"math/big"
	"sort"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/common/hexutil"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/bdls"
	"golang.org/x/crypto/sha3"
)

var (
	CommonCoin = []byte("Sperax")
	// block 0 common random number
	W0 = crypto.Keccak256Hash(hexutil.MustDecode("0x3243F6A8885A308D313198A2E037073"))
	// potential propser expectation
	E1 = big.NewInt(5)
	// BFT committee expectationA
	E2 = big.NewInt(50)
	// unit of staking SPA
	Alpha = new(big.Int).Mul(big.NewInt(100000), big.NewInt(params.Ether))

	MaxUint256 = big.NewFloat(0).SetInt(big.NewInt(0).SetBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))

	// transfering tokens to this address will be specially treated
	StakingAddress = common.Address{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE}
)

var (
	ErrStakingRequest       = errors.New("already staked")
	ErrStakingMinimumTokens = errors.New("staking has less than minimum tokens")
	ErrRedeemRequest        = errors.New("not staked")
)

// types of staking related operation
type StakingOp byte

// Staking Operations
const (
	Staking = StakingOp(0x00)
	Redeem  = StakingOp(0xFF)
)

// StakingRequest will be sent along in transaction.payload
type StakingRequest struct {
	// Staking or Redeem operation
	StakingOp StakingOp

	// The begining height to participate in consensus
	StakingFrom uint64

	// The ending  height to participate in consensus
	StakingTo uint64

	// The staker's hash at the height - StakingFrom
	StakingHash common.Hash
}

// Staker & StakingObject are the structures stored in
// StakingAddress's Account.Code for staking related information
// A single Staker
type Staker struct {
	// the Staker's address
	Address common.Address
	// the 1st block expected to participant in validator and proposer
	StakingFrom uint64
	// the last block to participant in validator and proposer, the tokens will be refunded
	// to participants' addresses after this block has mined
	StakingTo uint64
	// StakingHash is the last hash in hashchain,  random nubmers(R) in futureBlock
	// will be hashed for (futureBlock - stakingFrom) times to match with StakingHash.
	StakingHash common.Hash
	// records the number of tokens staked
	StakedValue *big.Int
}

// The object to be stored in StakingAddress's Account.Code
type StakingObject struct {
	Stakers     []Staker // staker's, expired stakers will automatically be removed
	TotalStaked *big.Int
}

// GetStakingObject returns the stakingObject at some state
func (e *BDLSEngine) GetStakingObject(state *state.StateDB) (*StakingObject, error) {
	var stakingObject StakingObject
	// retrieve committe data structure from code
	code := state.GetCode(StakingAddress)
	if code != nil {
		err := rlp.DecodeBytes(code, &stakingObject)
		if err != nil {
			return nil, err
		}
	}
	return &stakingObject, nil
}

// GetW calculates random number W based on block information
// W0 = H(U0)
// Wj = H(Pj-1,Wj-1) for 0<j<=r,
func (e *BDLSEngine) deriveW(header *types.Header) common.Hash {
	if header.Number.Uint64() == 0 {
		return W0
	}

	hasher := sha3.NewLegacyKeccak256()

	// derive Wj from previous header Pj-1 & Wj-1
	hasher.Write(header.Coinbase.Bytes())
	hasher.Write(header.W.Bytes()) // write Wj-1
	return common.BytesToHash(hasher.Sum(nil))
}

// H(r;0;Ri,r,0;Wr) > max{0;1 i-aip}
func (e *BDLSEngine) IsProposer(header *types.Header, stakingObject *StakingObject) bool {
	var numStaked *big.Int
	var totalStaked *big.Int

	// lookup the staker's information
	for k := range stakingObject.Stakers {
		staker := stakingObject.Stakers[k]
		if staker.Address == header.Coinbase {
			if header.Number.Uint64() <= staker.StakingFrom {
				log.Debug("height is not larger than the height which the proposer has announced(stakingFrom)")
				return false
			} else if common.BytesToHash(e.hashChain(staker.StakingHash.Bytes(), header.Number.Uint64()-staker.StakingFrom)) != header.R {
				log.Debug("hashchain verification failed for header.R")
				return false
			} else {
				numStaked = staker.StakedValue
				totalStaked = stakingObject.TotalStaked
				break
			}
		}
	}

	// compute p
	p := big.NewFloat(0).SetInt(E1)
	p.Mul(p, big.NewFloat(0).SetInt(Alpha))
	p.Quo(p, big.NewFloat(0).SetInt(totalStaked))

	// max{0, 1 - ai*p}
	max := p.Sub(big.NewFloat(1), p.Mul(big.NewFloat(0).SetInt(numStaked), p))
	if max.Cmp(big.NewFloat(0)) != 1 {
		max = big.NewFloat(0)
	}

	// compute proposer hash
	proposerHash := e.proposerHash(header.Number.Uint64(), header.R, header.W)

	// calculate H/MaxUint256
	h := big.NewFloat(0).SetInt(big.NewInt(0).SetBytes(proposerHash.Bytes()))
	h.Quo(h, MaxUint256)

	// prob compare
	if h.Cmp(max) == 1 {
		return true
	}
	return false
}

// ValidatorVotes counts the number of votes for a validator
func (e *BDLSEngine) ValidatorVotes(header *types.Header, staker *Staker, stakingObject *StakingObject) uint64 {
	totalStaked := stakingObject.TotalStaked
	numStaked := staker.StakedValue
	validatorR := staker.StakingHash

	// compute p'
	// p' = E2* numStaked /totalStaked
	p := big.NewFloat(0).SetInt(E2)
	p.Mul(p, big.NewFloat(0).SetInt(Alpha))
	p.Quo(p, big.NewFloat(0).SetInt(totalStaked))

	maxVotes := numStaked.Uint64() / Alpha.Uint64()

	// compute validator's hash
	validatorHash := e.validatorHash(header.Number.Uint64(), validatorR, header.W)

	// calculate H/MaxUint256
	h := big.NewFloat(0).SetInt(big.NewInt(0).SetBytes(validatorHash.Bytes()))
	h.Quo(h, MaxUint256)

	// find the minium possible votes
	var votes uint64
	binominal := big.NewInt(0)
	for i := uint64(0); i <= maxVotes; i++ {
		// computes binomial
		sum := big.NewFloat(0)
		for j := uint64(0); j <= i; j++ {
			coefficient := big.NewFloat(float64(binominal.Binomial(int64(maxVotes), int64(j)).Uint64()))
			a := Pow(p, j)
			b := Pow(big.NewFloat(0).Sub(big.NewFloat(1), p), maxVotes-j)
			r := big.NewFloat(0).Mul(a, b)
			r.Mul(r, coefficient)
			sum.Add(sum, r)
		}

		// effective vote
		if sum.Cmp(h) == 1 {
			votes = i
		}
	}

	return votes
}

type orderedValidator struct {
	identity bdls.Identity
	hash     common.Hash
}

type SortableValidators []orderedValidator

func (s SortableValidators) Len() int { return len(s) }
func (s SortableValidators) Less(i, j int) bool {
	return bytes.Compare(s[i].hash.Bytes(), s[j].hash.Bytes()) == -1
}
func (s SortableValidators) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// validatorHash computes a hash for validator's random number
func (ov SortableValidators) Hash(height uint64, R common.Hash, W common.Hash) common.Hash {
	hasher := sha3.New256()
	binary.Write(hasher, binary.LittleEndian, height)
	binary.Write(hasher, binary.LittleEndian, 1)
	hasher.Write(R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// CreateValidators creates an ordered list for all qualified validators with weights
func (e *BDLSEngine) CreateValidators(header *types.Header, stakingObject *StakingObject) []bdls.Identity {
	var orderedValidators []orderedValidator

	for k := range stakingObject.Stakers {
		staker := stakingObject.Stakers[k]
		if header.Number.Uint64() <= staker.StakingFrom || header.Number.Uint64() > staker.StakingTo {
			continue
		} else {
			n := e.ValidatorVotes(header, &staker, stakingObject)
			for i := uint64(0); i < n; i++ { // add n votes
				var validator orderedValidator
				copy(validator.identity[:], staker.Address.Bytes())
				validator.hash = e.validatorSortingHash(staker.Address, staker.StakingHash, header.W, i)
				orderedValidators = append(orderedValidators, validator)
			}
		}
	}

	// sort by the hash
	sort.Sort(SortableValidators(orderedValidators))
	var sortedValidators []bdls.Identity
	for i := 0; i < len(orderedValidators); i++ {
		sortedValidators = append(sortedValidators, orderedValidators[i].identity)
	}
	return sortedValidators
}

// Pow calculates a^e
func Pow(a *big.Float, e uint64) *big.Float {
	result := big.NewFloat(0.0).Copy(a)
	for i := uint64(0); i < e-1; i++ {
		result = big.NewFloat(0.0).Mul(result, a)
	}
	return result
}

// proposerHash computes a hash for proposer's random number
func (e *BDLSEngine) proposerHash(height uint64, R common.Hash, W common.Hash) common.Hash {
	hasher := sha3.New256()
	binary.Write(hasher, binary.LittleEndian, height)
	binary.Write(hasher, binary.LittleEndian, 0)
	hasher.Write(R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// validatorHash computes a hash for validator's random number
func (e *BDLSEngine) validatorHash(height uint64, R common.Hash, W common.Hash) common.Hash {
	hasher := sha3.New256()
	binary.Write(hasher, binary.LittleEndian, height)
	binary.Write(hasher, binary.LittleEndian, 1)
	hasher.Write(R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// validatorSortHash computes a hash for validator's sorting hashing
func (e *BDLSEngine) validatorSortingHash(address common.Address, R common.Hash, W common.Hash, votes uint64) common.Hash {
	hasher := sha3.New256()
	hasher.Write(address.Bytes())
	binary.Write(hasher, binary.LittleEndian, votes)
	hasher.Write(R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// deriveStakingSeed deterministically derives the random number for height, based on the staking from height and private key
// lastHash  = H(H(privatekey + stakingFrom) *G)
func (e *BDLSEngine) deriveStakingSeed(priv *ecdsa.PrivateKey, stakingFrom uint64) []byte {
	// H(privatekey + stakingFrom)
	hasher := sha3.New256()
	hasher.Write(priv.D.Bytes())
	binary.Write(hasher, binary.LittleEndian, stakingFrom)

	// H(privatekey + lastHeight) *G
	x, y := crypto.S256().ScalarBaseMult(hasher.Sum(nil))

	// H(H(privatekey + lastHeight) *G)
	hasher = sha3.New256()
	hasher.Write(x.Bytes())
	hasher.Write(y.Bytes())
	return hasher.Sum(nil)
}

// compute hash recursively for n(n>=0) times
func (e *BDLSEngine) hashChain(hash []byte, n uint64) []byte {
	if n == 0 {
		return hash
	}

	hasher := sha3.New256()
	hasher.Write(hash)
	for i := uint64(1); i < n; i++ {
		hasher.Write(hasher.Sum(nil))
	}
	return hasher.Sum(nil)
}
