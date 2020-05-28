package node

import "github.com/Sperax/bdls"

// Node represents a Sperax node on it's network
type Node struct {
	consensus *bdls.Consensus
}
