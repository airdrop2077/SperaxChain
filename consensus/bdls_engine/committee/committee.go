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

package committee

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	fmt "fmt"
	"math/big"
	"sort"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/common/hexutil"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/core/vm"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/bdls"
	"golang.org/x/crypto/sha3"
)

var (
	// Base Quorum is the quorum to make sure blockchain can generate new blocks
	// while no other validators are running.
	BaseQuorum = []common.Address{
		common.HexToAddress("f2580391fe8a83366ed550de4e45af1714d74b8d"),
		common.HexToAddress("066aaff9e575302365b7862dcebd4a5a65f75f5f"),
		common.HexToAddress("3f80e8718d8e17a1768b467f193a6fbeaa6236e3"),
		common.HexToAddress("29d3fbe3e7983a41d0e6d984c480ceedb3c251fd"),
	}
)

var (
	CommonCoin = []byte("Sperax")
	// block 0 common random number
	W0 = crypto.Keccak256Hash(hexutil.MustDecode("0x03243F6A8885A308D313198A2E037073"))
	// potential propser expectation
	E1 = big.NewInt(5)
	// BFT committee expectationA
	E2 = big.NewInt(50)
	// unit of staking SPA
	StakingUnit = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	// transfering tokens to this address will be specially treated
	StakingAddress = common.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	// max unsigned 256-bit integer
	MaxUint256 = big.NewFloat(0).SetInt(big.NewInt(0).SetBytes(common.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))
)

var (
	ErrStakingRequest       = errors.New("already staked")
	ErrStakingMinimumTokens = errors.New("staking has less than minimum tokens")
	ErrStakingInvalidPeriod = errors.New("invalid staking period")
	ErrRedeemRequest        = errors.New("not staked")
)

const (
	// example:
	// key: hash("/v1/29d3fbe3e7983a41d0e6d984c480ceedb3c251fd/from")

	// the 1st block expected to participant in validator and proposer
	StakingKeyFrom = "/v1/%v/from"

	// the last block to participant in validator and proposer, the tokens will be refunded
	// to participants' addresses after this block has mined
	StakingKeyTo = "/v1/%v/to"

	// StakingHash is the last hash in hashchain,  random nubmers(R) in futureBlock
	// will be hashed for (futureBlock - stakingFrom) times to match with StakingHash.
	StakingKeyHash = "/v1/%v/hash"

	// records the number of tokens staked
	StakingKeyValue = "/v1/%v/value"

	// record the total number of staked users
	StakingUsersCount = "/v1/count"

	// staking users index , index -> address
	StakingUserIndex = "/v1/address/%v"
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

// Staker represents a staker's information retrieved from account storage trie
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

// getStakingValue retrieves the value with key from account: StakingAddress
func getStakingValue(addr common.Address, key string, state vm.StateDB) common.Hash {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr)))
	return state.GetState(StakingAddress, keyHash)
}

// setStakingValue sets the value with key to account: StakingAddress
func setStakingValue(addr common.Address, key string, value common.Hash, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr)))
	state.SetState(StakingAddress, keyHash, value)
}

// GetAllStakers retrieve all staker's addresses from account storage trie
func GetAllStakers(state vm.StateDB) []common.Address {
	count := GetStakersCount(state)
	var stakers []common.Address
	for i := int64(0); i < count; i++ {
		userIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, i)))
		stakers = append(stakers, common.BytesToAddress(state.GetState(StakingAddress, userIndex).Bytes()))
	}

	return stakers
}

// GetStakersCount retrieves the total staker's count from account storage trie
func GetStakersCount(state vm.StateDB) int64 {
	counterKeyHash := crypto.Keccak256Hash([]byte(StakingUsersCount))
	return state.GetState(StakingAddress, counterKeyHash).Big().Int64()
}

// SetStakersCount sets the total staker's count from account storage trie
func SetStakersCount(count int64, state vm.StateDB) {
	counterKeyHash := crypto.Keccak256Hash([]byte(StakingUsersCount))
	state.SetState(StakingAddress, counterKeyHash, common.BigToHash(big.NewInt(int64(count))))
}

// AddStakerToList adds a new staker's address to the staker's list in account storage trie
func AddStakerToList(addr common.Address, state vm.StateDB) {
	count := GetStakersCount(state)

	// set index
	userIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, count)))
	state.SetState(StakingAddress, userIndex, addr.Hash())

	// increase counter
	SetStakersCount(count+1, state)
}

// RemoveStakerFromList remove a staker's address from staker's list account storage trie
func RemoveStakerFromList(addr common.Address, state vm.StateDB) {
	count := GetStakersCount(state)
	for i := int64(0); i < count; i++ {
		userIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, i)))
		// found this stakers
		if addr == common.BytesToAddress(state.GetState(StakingAddress, userIndex).Bytes()) {
			lastIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, count-1)))
			lastAddress := state.GetState(StakingAddress, lastIndex)

			// swap with the last stakers
			state.SetState(StakingAddress, userIndex, lastAddress)

			// decrease counter
			SetStakersCount(count-1, state)
			return
		}
	}
}

// GetStaker retrieves staking information from storage account trie
func GetStaker(addr common.Address, state vm.StateDB) *Staker {
	staker := new(Staker)
	staker.Address = addr
	staker.StakingFrom = uint64(getStakingValue(addr, StakingKeyFrom, state).Big().Int64())
	staker.StakingTo = uint64(getStakingValue(addr, StakingKeyTo, state).Big().Int64())
	staker.StakingHash = getStakingValue(addr, StakingKeyHash, state)
	staker.StakedValue = getStakingValue(addr, StakingKeyValue, state).Big()
	return staker
}

// SetStaker sets staking information to storage account trie
func SetStaker(staker *Staker, state vm.StateDB) {
	setStakingValue(staker.Address, StakingKeyFrom, common.BigToHash(big.NewInt(int64(staker.StakingFrom))), state)
	setStakingValue(staker.Address, StakingKeyTo, common.BigToHash(big.NewInt(int64(staker.StakingTo))), state)
	setStakingValue(staker.Address, StakingKeyHash, staker.StakingHash, state)
	setStakingValue(staker.Address, StakingKeyValue, common.BigToHash(staker.StakedValue), state)
}

// GetW calculates random number W based on block information
// W0 = H(U0)
// Wj = H(Pj-1,Wj-1) for 0<j<=r,
func DeriveW(header *types.Header) common.Hash {
	if header.Number.Uint64() == 0 {
		return W0
	}

	hasher := sha3.NewLegacyKeccak256()

	// derive Wj from Pj-1 & Wj-1
	hasher.Write(header.Coinbase.Bytes())
	hasher.Write(header.W.Bytes())
	return common.BytesToHash(hasher.Sum(nil))
}

// IsBaseQuorum check whether a address is from base quorum
func IsBaseQuorum(address common.Address) bool {
	for k := range BaseQuorum {
		if address == BaseQuorum[k] {
			return true
		}
	}
	return false
}

// H(r;0;Ri,r,0;Wr) > max{0;1 i-aip}
func IsProposer(header *types.Header, state vm.StateDB) bool {
	// addresses in base quorum are permanent proposers
	if IsBaseQuorum(header.Coinbase) {
		return true
	}

	// non-empty blocks
	numStaked := big.NewFloat(0)
	totalStaked := big.NewFloat(0) // effective stakings

	// lookup the staker's information
	stakers := GetAllStakers(state)
	for k := range stakers {
		staker := GetStaker(stakers[k], state)
		// count effective stakings
		if header.Number.Uint64() > staker.StakingFrom || header.Number.Uint64() <= staker.StakingTo {
			totalStaked.Add(totalStaked, big.NewFloat(0).SetInt(staker.StakedValue))
		}

		// found proposer's staking address
		if staker.Address == header.Coinbase {
			if header.Number.Uint64() <= staker.StakingFrom || header.Number.Uint64() > staker.StakingTo {
				log.Debug("invalid staking period")
				return false
			}

			R := common.BytesToHash(HashChain(header.R.Bytes(), staker.StakingFrom, header.Number.Uint64()))
			if R != staker.StakingHash {
				log.Error("hashchain verification failed for header.R", "header.R", header.R, "computed R", R, "staked hash:", staker.StakingHash)
				return false
			}
			numStaked = big.NewFloat(0).SetInt(staker.StakedValue)
		}
	}

	return isProposerInternal(ProposerHash(header), numStaked, totalStaked)
}

// isProposerInternal is the pure algorithm implementation for testing whether
// an block coinbase account is the proposer
func isProposerInternal(proposerHash common.Hash, numStaked *big.Float, totalStaked *big.Float) bool {
	// if there's staking
	if totalStaked.Sign() == 1 {
		// compute p
		p := big.NewFloat(0).SetInt(E1)
		p.Mul(p, big.NewFloat(0).SetInt(StakingUnit))
		p.Quo(p, totalStaked)

		// max{0, 1 - ai*p}
		max := p.Sub(big.NewFloat(1), p.Mul(numStaked, p))
		if max.Cmp(big.NewFloat(0)) != 1 {
			max = big.NewFloat(0)
		}

		// calculate H/MaxUint256
		h := big.NewFloat(0).SetInt(big.NewInt(0).SetBytes(proposerHash.Bytes()))
		h.Quo(h, MaxUint256)

		// prob compare
		if h.Cmp(max) == 1 {
			return true
		}
	}

	return false
}

// ValidatorVotes counts the number of votes for a validator
func ValidatorVotes(header *types.Header, staker *Staker, totalStaked *big.Int) uint64 {
	numStaked := staker.StakedValue
	validatorR := staker.StakingHash

	// compute p'
	// p' = E2* numStaked /totalStaked
	p := big.NewFloat(0).SetInt(E2)
	p.Mul(p, big.NewFloat(0).SetInt(StakingUnit))
	p.Quo(p, big.NewFloat(0).SetInt(totalStaked))

	maxVotes := numStaked.Uint64() / StakingUnit.Uint64()

	// compute validator's hash
	validatorHash := validatorHash(header.Coinbase, header.Number.Uint64(), validatorR, header.W)

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
func CreateValidators(header *types.Header, state vm.StateDB) []bdls.Identity {
	var orderedValidators []orderedValidator

	// count effective stakings
	totalStaked := big.NewInt(0)
	stakers := GetAllStakers(state)
	for k := range stakers {
		staker := GetStaker(stakers[k], state)
		// count effective stakings
		if header.Number.Uint64() > staker.StakingFrom || header.Number.Uint64() <= staker.StakingTo {
			totalStaked.Add(totalStaked, staker.StakedValue)
		}
	}

	// setup validators
	for k := range stakers {
		staker := GetStaker(stakers[k], state)
		if header.Number.Uint64() <= staker.StakingFrom || header.Number.Uint64() > staker.StakingTo {
			continue
		} else {
			n := ValidatorVotes(header, staker, totalStaked)
			for i := uint64(0); i < n; i++ { // a validator has N slots to be a leader
				var validator orderedValidator
				copy(validator.identity[:], staker.Address.Bytes())
				validator.hash = validatorSortingHash(staker.Address, staker.StakingHash, header.W, i)
				orderedValidators = append(orderedValidators, validator)
			}
		}
	}

	// sort by the validators based on the sorting hash
	sort.Stable(SortableValidators(orderedValidators))
	var sortedValidators []bdls.Identity
	for i := 0; i < len(orderedValidators); i++ {
		sortedValidators = append(sortedValidators, orderedValidators[i].identity)
	}

	// always append based quorum to then end of the validators
	for k := range BaseQuorum {
		var id bdls.Identity
		copy(id[:], BaseQuorum[k][:])
		sortedValidators = append(sortedValidators, id)
	}

	return sortedValidators
}

// Pow calculates a^e
func Pow(a *big.Float, e uint64) *big.Float {
	if e == 0 {
		return big.NewFloat(1)
	}

	result := big.NewFloat(0.0).Copy(a)
	for i := uint64(1); i < e; i++ {
		result.Mul(result, a)
	}
	return result
}

// ProposerHash computes a hash for proposer's random number
func ProposerHash(header *types.Header) common.Hash {
	hasher := sha3.New256()
	hasher.Write(header.Coinbase.Bytes())
	binary.Write(hasher, binary.LittleEndian, header.Number.Uint64())
	binary.Write(hasher, binary.LittleEndian, 0)
	hasher.Write(header.R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(header.W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// validatorHash computes a hash for validator's random number
func validatorHash(coinbase common.Address, height uint64, R common.Hash, W common.Hash) common.Hash {
	hasher := sha3.New256()
	hasher.Write(coinbase.Bytes())
	binary.Write(hasher, binary.LittleEndian, height)
	binary.Write(hasher, binary.LittleEndian, 1)
	hasher.Write(R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// validatorSortHash computes a hash for validator's sorting hashing
func validatorSortingHash(address common.Address, R common.Hash, W common.Hash, votes uint64) common.Hash {
	hasher := sha3.New256()
	hasher.Write(address.Bytes())
	binary.Write(hasher, binary.LittleEndian, votes)
	hasher.Write(R.Bytes())
	hasher.Write(CommonCoin)
	hasher.Write(W.Bytes())

	return common.BytesToHash(hasher.Sum(nil))
}

// DeriveStakingSeed deterministically derives the pseudo-random number with height and private key
// seed := H(H(privatekey,stakingFrom) *G)
func DeriveStakingSeed(priv *ecdsa.PrivateKey, stakingFrom uint64) []byte {
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

// compute hash recursively for to - from times
func HashChain(hash []byte, from, to uint64) []byte {
	n := to - from
	lastHash := hash
	for i := uint64(0); i < n; i++ {
		lastHash = crypto.Keccak256(lastHash)
	}
	return lastHash
}
