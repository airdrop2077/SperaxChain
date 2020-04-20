package main

import (
	"log"

	"github.com/Sperax/SperaxChain/p2p"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	nodekey, _ := crypto.GenerateKey()
	config := p2p.Config{
		Name:        "test",
		MaxPeers:    10,
		ListenAddr:  "127.0.0.1:0",
		NoDiscovery: true,
		PrivateKey:  nodekey,
	}
	server := &p2p.Server{
		Config: config,
	}
	if err := server.Start(); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
