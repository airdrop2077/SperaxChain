package node

import (
	"time"

	"github.com/Sperax/SperaxChain/core"
)

type Config struct {
	Genesis         *core.Genesis `toml:",omitempty"`
	DatabaseDir     string
	DatabaseHandles int `toml:"-"`
	DatabaseCache   int

	// cache
	TrieCleanCache int
	TrieDirtyCache int
	TrieTimeout    time.Duration
	SnapshotCache  int
	NoPruning      bool   // Whether to disable pruning and flush everything to disk
	NoPrefetch     bool   // Whether to disable prefetching and only load state on demand
	TxLookupLimit  uint64 `toml:",omitempty"` // The maximum number of blocks from head whose tx indices are reserved.

	// vm
	// Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// Type of the EWASM interpreter ("" for default)
	EWASMInterpreter string

	// Type of the EVM interpreter ("" for default)
	EVMInterpreter string
}
