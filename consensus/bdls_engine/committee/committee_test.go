package committee

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/core/rawdb"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/ethdb"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/stretchr/testify/assert"
)

type stateTest struct {
	db    ethdb.Database
	state *state.StateDB
}

func newStateTest() *stateTest {
	db := rawdb.NewMemoryDatabase()
	sdb, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	return &stateTest{db: db, state: sdb}
}

func TestEncodingStaking(t *testing.T) {
	privateKey := "0xb38b95b464052c55e12a3044d4e1f5699ef1dce9f28d9a16313be3e5c031ec11"
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	priv.D = big.NewInt(0).SetBytes(common.FromHex(privateKey))
	priv.PublicKey.X, priv.PublicKey.Y = crypto.S256().ScalarBaseMult(priv.D.Bytes())
	seed := DeriveStakingSeed(priv, 1)
	req := StakingRequest{
		StakingOp:   Staking,
		StakingFrom: 1,
		StakingTo:   40,
		StakingHash: common.BytesToHash(HashChain(seed, 1, 40)),
	}
	bts, err := rlp.EncodeToBytes(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("staking rlp:", common.Bytes2Hex(bts))
	t.Log("seed:", common.BytesToHash(seed).String())
	t.Log("R:", req.StakingHash.String())

	block20 := HashChain(seed, 20, req.StakingTo)
	t.Log("block20#R", common.BytesToHash(block20).String())
	block1 := HashChain(block20, req.StakingFrom, 20)
	t.Log("block1#R", common.BytesToHash(block1).String())
	assert.Equal(t, block1, req.StakingHash.Bytes())

	req = StakingRequest{
		StakingOp: Redeem,
	}

	bts, err = rlp.EncodeToBytes(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("redeem rlp:", common.Bytes2Hex(bts))
}

func TestIsPropoersInternal(t *testing.T) {
	numStaked := big.NewInt(100)
	totalStaked := big.NewInt(100)
	numStaked.Mul(numStaked, StakingUnit)
	totalStaked.Mul(totalStaked, StakingUnit)

	var hash common.Hash
	assert.False(t, isProposerInternal(hash, numStaked, totalStaked))

	hash[common.HashLength-1] = 1
	assert.True(t, isProposerInternal(hash, numStaked, totalStaked))

	hash = crypto.Keccak256Hash([]byte{})
	assert.True(t, isProposerInternal(hash, numStaked, totalStaked))

	numStaked = big.NewInt(10)
	totalStaked = big.NewInt(100)
	numStaked.Mul(numStaked, StakingUnit)
	totalStaked.Mul(totalStaked, StakingUnit)

	totalProposer := 0
	for i := 0; i < 100000; i++ {
		hash = crypto.Keccak256Hash(hash.Bytes())
		if isProposerInternal(hash, numStaked, totalStaked) {
			totalProposer++
		}
	}

	t.Log("totalProposer for 10000, 10% staked", totalProposer)
}

func TestStakersList(t *testing.T) {
	s := newStateTest()
	stakers := GetAllStakers(s.state)
	// nil test
	assert.Nil(t, stakers)

	// pushed 10 stakers
	for i := 0; i < 10; i++ {
		var account common.Address
		account.SetBytes(crypto.Keccak256([]byte{byte(i)})[:common.AddressLength])
		AddStakerToList(account, s.state)
		assert.True(t, HasStaked(account, s.state))
	}

	stakers = GetAllStakers(s.state)
	assert.Equal(t, 10, len(stakers))

	// remove 10 stakers
	for i := 0; i < 10; i++ {
		var account common.Address
		account.SetBytes(crypto.Keccak256([]byte{byte(i)})[:common.AddressLength])
		RemoveStakerFromList(account, s.state)
		assert.False(t, HasStaked(account, s.state))
	}
	stakers = GetAllStakers(s.state)
	assert.Nil(t, stakers)
}

func TestStakerData(t *testing.T) {
	s := newStateTest()
	staker := new(Staker)

	staker.Address.SetBytes(crypto.Keccak256([]byte{0})[:common.AddressLength])
	staker.StakedValue = big.NewInt(1234)
	staker.StakingFrom = 2345
	staker.StakingTo = 3456
	staker.StakingHash = crypto.Keccak256Hash([]byte{1})
	staker.StakedValue = big.NewInt(1000000)

	SetStakerData(staker, s.state)

	stakerDumped := GetStakerData(staker.Address, s.state)
	assert.Equal(t, staker, stakerDumped)
}

func TestCountValidatorVotes(t *testing.T) {
	numStaked := big.NewInt(100)
	totalStaked := big.NewInt(1000)
	numStaked.Mul(numStaked, StakingUnit)
	totalStaked.Mul(totalStaked, StakingUnit)

	W := crypto.Keccak256Hash([]byte{})
	stakingHash := crypto.Keccak256Hash([]byte{1})
	address := common.Address{}

	var totalVotes uint64
	for i := 0; i < 10000; i++ {
		totalVotes += countValidatorVotes(address, uint64(i), W, stakingHash, numStaked, totalStaked)
	}

	t.Log("totalVotes for 10000, 10% staked", totalVotes)
}
