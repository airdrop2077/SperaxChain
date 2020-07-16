package bdls_engine

import "github.com/Sperax/SperaxChain/crypto"

const (
	stakingFromKey = "Sperax/StakingFrom/v1"
	stakingToKey   = "Sperax/StakingTo/v1"
	stakingHashKey = "Sperax/StakingHash/v1"
)

// keys used to retrieve staking related informatio
var (
	StakingFromKey = crypto.Keccak256Hash([]byte(stakingFromKey))
	StakingToKey   = crypto.Keccak256Hash([]byte(stakingToKey))
	StakingHashKey = crypto.Keccak256Hash([]byte(stakingHashKey))
)
