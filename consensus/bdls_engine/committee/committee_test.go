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
	numStaked := big.NewFloat(100)
	totalStaked := big.NewFloat(100)

	var proposerHash common.Hash
	assert.False(t, isProposerInternal(proposerHash, numStaked, totalStaked))

	proposerHash[common.HashLength-1] = 1
	assert.True(t, isProposerInternal(proposerHash, numStaked, totalStaked))

	proposerHash = crypto.Keccak256Hash([]byte{})
	assert.True(t, isProposerInternal(proposerHash, numStaked, totalStaked))
}

func TestGetAllStakers(t *testing.T) {
	s := newStateTest()
	stakers := GetAllStakers(s.state)
	// nil test
	assert.Nil(t, stakers)

	// pushed 10 stakers
	for i := 0; i < 10; i++ {
		var account common.Address
		account.SetBytes(crypto.Keccak256([]byte{byte(i)})[:common.AddressLength])
		AddNewStaker(account, s.state)
	}

	stakers = GetAllStakers(s.state)
	assert.Equal(t, 10, len(stakers))

	// remove 10 stakers
	for i := 0; i < 10; i++ {
		var account common.Address
		account.SetBytes(crypto.Keccak256([]byte{byte(i)})[:common.AddressLength])
		RemoveStaker(account, s.state)
	}
	stakers = GetAllStakers(s.state)
	assert.Nil(t, stakers)
}
