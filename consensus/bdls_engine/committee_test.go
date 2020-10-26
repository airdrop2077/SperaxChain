package bdls_engine

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/stretchr/testify/assert"
)

func TestEncodingStaking(t *testing.T) {
	privateKey := "0xb38b95b464052c55e12a3044d4e1f5699ef1dce9f28d9a16313be3e5c031ec11"
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	priv.D = big.NewInt(0).SetBytes(common.FromHex(privateKey))
	priv.PublicKey.X, priv.PublicKey.Y = crypto.S256().ScalarBaseMult(priv.D.Bytes())
	seed := deriveStakingSeed(priv, 1)
	req := StakingRequest{
		StakingOp:   Staking,
		StakingFrom: 1,
		StakingTo:   120,
		StakingHash: common.BytesToHash(hashChain(seed, 1, 120)),
	}
	bts, err := rlp.EncodeToBytes(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("rlp:", common.Bytes2Hex(bts))
	t.Log("seed:", common.BytesToHash(seed).String())
	t.Log("R:", req.StakingHash.String())

	block100 := hashChain(seed, 100, req.StakingTo)
	t.Log("block100#R", common.BytesToHash(block100).String())
	block1 := hashChain(block100, req.StakingFrom, 100)
	t.Log("block1#R", common.BytesToHash(block1).String())
	assert.Equal(t, block1, req.StakingHash.Bytes())
}
