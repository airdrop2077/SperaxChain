package bdls_engine

import "github.com/Sperax/SperaxChain/consensus"

// API is a user facing RPC API to dump BDLS state
type API struct {
	chain  consensus.ChainReader
	engine *BDLSEngine
}
