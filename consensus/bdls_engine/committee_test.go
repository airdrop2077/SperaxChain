package bdls_engine

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/crypto"
	"github.com/Sperax/SperaxChain/rlp"
)

func TestEncodingStaking(t *testing.T) {
	privateKey := "0x81210624861938308113657583733558992734038979034106497541943231397378403724305"
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	priv.D = big.NewInt(0).SetBytes(common.Hex2Bytes(privateKey))
	priv.PublicKey.X, priv.PublicKey.Y = crypto.S256().ScalarBaseMult(priv.D.Bytes())
	req := StakingRequest{
		StakingOp:   Staking,
		StakingFrom: 1,
		StakingTo:   10000,
		StakingHash: common.BytesToHash(deriveStakingSeed(priv, 1)),
	}
	bts, err := rlp.EncodeToBytes(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("rlp:", common.Bytes2Hex(bts))
}
