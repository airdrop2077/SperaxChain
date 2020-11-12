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
	MaxUint256 = big.NewInt(0).SetBytes(common.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
)

var (
	ErrStakingRequest        = errors.New("STAKING: already staked")
	ErrStakingMinimumTokens  = errors.New("STAKING: less than minimum values")
	ErrStakingZeroValue      = errors.New("STAKING: cannot stake 0 value")
	ErrStakingInvalidPeriod  = errors.New("STAKING: invalid staking period, make sure from < to")
	ErrStakingAlreadyExpired = errors.New("STAKING: staking period already expired")
	ErrRedeemRequest         = errors.New("REDEEM: not staked")
	ErrRedeemValidNonZero    = errors.New("REDEEM: the redeem transaction has none 0 value")
)

const (
	// example:
	// key: hash("/v1/29d3fbe3e7983a41d0e6d984c480ceedb3c251fd/from")
	StakingInList = "/v1/%v/inlist"

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

// getMapValue retrieves the value with key from account: StakingAddress
func getMapValue(addr common.Address, key string, state vm.StateDB) common.Hash {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr.String())))
	return state.GetState(StakingAddress, keyHash)
}

// setMapValue sets the value with key to account: StakingAddress
func setMapValue(addr common.Address, key string, value common.Hash, state vm.StateDB) {
	keyHash := crypto.Keccak256Hash([]byte(fmt.Sprintf(key, addr.String())))
	state.SetState(StakingAddress, keyHash, value)
}

// getStakersCount retrieves the total staker's count from account storage trie
func getStakersCount(state vm.StateDB) int64 {
	counterKeyHash := crypto.Keccak256Hash([]byte(StakingUsersCount))
	return state.GetState(StakingAddress, counterKeyHash).Big().Int64()
}

// setStakersCount sets the total staker's count from account storage trie
func setStakersCount(count int64, state vm.StateDB) {
	counterKeyHash := crypto.Keccak256Hash([]byte(StakingUsersCount))
	state.SetState(StakingAddress, counterKeyHash, common.BigToHash(big.NewInt(int64(count))))
}

// HasStaked is a O(1) way to test whether an account has staked
func HasStaked(addr common.Address, state vm.StateDB) bool {
	if getMapValue(addr, StakingInList, state) == addr.Hash() {
		return true
	}
	return false
}

// GetAllStakers retrieve all staker's addresses from account storage trie
func GetAllStakers(state vm.StateDB) []common.Address {
	count := getStakersCount(state)
	var stakers []common.Address
	for i := int64(0); i < count; i++ {
		userIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, i)))
		stakers = append(stakers, common.BytesToAddress(state.GetState(StakingAddress, userIndex).Bytes()))
	}

	return stakers
}

// AddStakerToList adds a new staker's address to the staker's list in account storage trie
func AddStakerToList(addr common.Address, state vm.StateDB) {
	count := getStakersCount(state)

	// set index
	userIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, count)))
	state.SetState(StakingAddress, userIndex, addr.Hash())

	// mark the account in list
	setMapValue(addr, StakingInList, addr.Hash(), state)

	// increase counter
	setStakersCount(count+1, state)
}

// RemoveStakerFromList remove a staker's address from staker's list account storage trie
func RemoveStakerFromList(addr common.Address, state vm.StateDB) {
	count := getStakersCount(state)
	for i := int64(0); i < count; i++ {
		userIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, i)))
		// found this stakers
		if addr == common.BytesToAddress(state.GetState(StakingAddress, userIndex).Bytes()) {
			lastIndex := crypto.Keccak256Hash([]byte(fmt.Sprintf(StakingUserIndex, count-1)))
			lastAddress := state.GetState(StakingAddress, lastIndex)

			// swap with the last stakers
			state.SetState(StakingAddress, userIndex, lastAddress)

			// unmark the account in list
			setMapValue(addr, StakingInList, common.Hash{}, state)

			// decrease counter
			setStakersCount(count-1, state)
			return
		}
	}
}

// GetStakerData retrieves staking information from storage account trie
func GetStakerData(addr common.Address, state vm.StateDB) *Staker {
	staker := new(Staker)
	staker.Address = addr
	staker.StakingFrom = uint64(getMapValue(addr, StakingKeyFrom, state).Big().Int64())
	staker.StakingTo = uint64(getMapValue(addr, StakingKeyTo, state).Big().Int64())
	staker.StakingHash = getMapValue(addr, StakingKeyHash, state)
	staker.StakedValue = getMapValue(addr, StakingKeyValue, state).Big()
	return staker
}

// SetStakerData sets staking information to storage account trie
func SetStakerData(staker *Staker, state vm.StateDB) {
	setMapValue(staker.Address, StakingKeyFrom, common.BigToHash(big.NewInt(int64(staker.StakingFrom))), state)
	setMapValue(staker.Address, StakingKeyTo, common.BigToHash(big.NewInt(int64(staker.StakingTo))), state)
	setMapValue(staker.Address, StakingKeyHash, staker.StakingHash, state)
	setMapValue(staker.Address, StakingKeyValue, common.BigToHash(staker.StakedValue), state)
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
func IsProposer(header *types.Header, parentState vm.StateDB) bool {
	// addresses in base quorum are permanent proposers
	if IsBaseQuorum(header.Coinbase) {
		return true
	}

	// get total staked value
	totalStaked := TotalStaked(parentState)

	// lookup the staker's information
	staker := GetStakerData(header.Coinbase, parentState)
	if header.Number.Uint64() <= staker.StakingFrom || header.Number.Uint64() > staker.StakingTo {
		log.Debug("invalid staking period")
		return false
	}

	// to mitigate hashchain hashing attack by computing probability aforehead
	if !isProposerInternal(ProposerHash(header), staker.StakedValue, totalStaked) {
		log.Debug("hash of the proposer has failed the threshold")
		return false
	}

	// hashchain verification is the last step, expensive for long term staking
	R := common.BytesToHash(HashChain(header.R.Bytes(), staker.StakingFrom, header.Number.Uint64()))
	if R != staker.StakingHash {
		log.Error("hashchain verification failed for header.R", "header.R", header.R, "computed R", R, "staked hash:", staker.StakingHash)
		return false
	}
	return true
}

// isProposerInternal is the pure algorithm implementation for testing whether
// an block coinbase account is the proposer
func isProposerInternal(proposerHash common.Hash, numStaked *big.Int, totalStaked *big.Int) bool {
	// if there's staking
	if totalStaked.Cmp(common.Big0) > 0 {
		ai := new(big.Int).Div(numStaked, StakingUnit)
		if ai.Cmp(common.Big0) > 0 {
			// compute E1 * StakingUnit * MaxUint256 * ai / totalStaked
			threshold := new(big.Int).Mul(E1, StakingUnit)
			threshold.Mul(threshold, MaxUint256)
			threshold.Mul(threshold, ai)
			threshold.Div(threshold, totalStaked)

			// 1- ai*p < 0, then set threshold to 0
			if MaxUint256.Cmp(threshold) < 0 {
				threshold = common.Big0
			}

			if proposerHash.Big().Cmp(threshold) > 0 {
				return true
			}
		}
	}

	return false
}

// countValidatorVotes counts the number of votes for a validator
func countValidatorVotes(coinbase common.Address, blockNumber uint64, W common.Hash, stakingHash common.Hash, numStaked *big.Int, totalStaked *big.Int) uint64 {
	// assume total staked is not 0
	if totalStaked.Cmp(common.Big0) == 0 {
		log.Error("total staked value is 0")
		return 0
	}

	// compute
	// E2* numStakedUnit /totalStaked * MaxUint256
	threshold := new(big.Int).Mul(E2, StakingUnit)
	threshold.Mul(threshold, MaxUint256)
	threshold.Div(threshold, totalStaked)

	// the count of staking units is the maxVotes
	maxVotes := big.NewInt(0).Div(numStaked, StakingUnit)
	votes := uint64(0)
	for j := big.NewInt(0); j.Cmp(maxVotes) <= 0; j = j.Add(j, common.Big1) {
		validatorHash := validatorHash(coinbase, blockNumber, j, stakingHash, W).Big()
		if validatorHash.Cmp(threshold) < 0 {
			votes++
		}
	}

	return votes
}

type weightedValidator struct {
	identity bdls.Identity
	votes    uint64
	hash     common.Hash
}

// TotalStaked retrieves value staked in staking account
func TotalStaked(state vm.StateDB) *big.Int {
	return state.GetBalance(StakingAddress)
}

// CreateValidators creates an ordered list for all qualified validators with weights
func CreateValidators(header *types.Header, state vm.StateDB) []bdls.Identity {
	var validators []weightedValidator

	// count effective stakings
	totalStaked := TotalStaked(state)

	// setup validators
	stakers := GetAllStakers(state)
	for k := range stakers {
		staker := GetStakerData(stakers[k], state)
		if header.Number.Uint64() <= staker.StakingFrom || header.Number.Uint64() > staker.StakingTo {
			continue
		} else {
			// compute validator's hash
			n := countValidatorVotes(header.Coinbase, header.Number.Uint64(), header.W, staker.StakingHash, staker.StakedValue, totalStaked)
			if n > 0 {
				var validator weightedValidator
				copy(validator.identity[:], staker.Address.Bytes())
				validator.votes = n
				validator.hash = validatorSortingHash(staker.Address, staker.StakingHash, header.W, n)
				validators = append(validators, validator)
			}
		}
	}

	// validators are prioritized by it's weight & hash
	// weight first then hash
	sort.SliceStable(validators, func(i, j int) bool {
		if validators[i].votes == validators[j].votes {
			return bytes.Compare(validators[i].hash.Bytes(), validators[j].hash.Bytes()) == -1
		}
		return validators[i].votes > validators[j].votes
	})

	var sortedValidators []bdls.Identity
	for i := 0; i < len(validators); i++ {
		sortedValidators = append(sortedValidators, validators[i].identity)
	}

	// always append based quorum to then end of the validators
	for k := range BaseQuorum {
		var id bdls.Identity
		copy(id[:], BaseQuorum[k][:])
		sortedValidators = append(sortedValidators, id)
	}

	return sortedValidators
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
func validatorHash(coinbase common.Address, height uint64, j *big.Int, R common.Hash, W common.Hash) common.Hash {
	hasher := sha3.New256()
	hasher.Write(coinbase.Bytes())
	hasher.Write(j.Bytes())
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
