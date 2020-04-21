package main

import (
	"sync"

	"github.com/libp2p/go-libp2p-core/crypto"

	"context"
	"time"

	"github.com/Sperax/bdls"
	"github.com/libp2p/go-libp2p-core/network"

	"github.com/libp2p/go-libp2p"
	autonat "github.com/libp2p/go-libp2p-autonat-svc"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	"github.com/libp2p/go-libp2p-core/host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	routing "github.com/libp2p/go-libp2p-routing"
	secio "github.com/libp2p/go-libp2p-secio"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
)

// CreateNode initialize a p2p node with given multiaddr, consensus and ledger
// eg addr: "/ip4/0.0.0.0/tcp/9000"
func CreateNode(addr string, priv crypto.PrivKey, consensus *bdls.Consensus) *Node {
	// The context governs the lifetime of the libp2p node.
	// Cancelling it will stop the the host.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host, err := libp2p.New(ctx,
		// Use the keypair we generated
		libp2p.Identity(priv),
		// Multiple listen addresses
		libp2p.ListenAddrStrings(
			addr, // regular tcp connections
		),
		// support any other default transports (TCP)
		libp2p.DefaultTransports,
		// Let's prevent our peer from having too many
		// connections by attaching a connection manager.
		libp2p.ConnectionManager(connmgr.NewConnManager(
			100,         // Lowwater
			400,         // HighWater,
			time.Minute, // GracePeriod
		)),
		// Attempt to open ports using uPNP for NATed hosts.
		libp2p.NATPortMap(),
		// Let this host use the DHT to find other hosts
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			idht, err := dht.New(ctx, h)
			return idht, err
		}),
		// Let this host use relays and advertise itself on relays if
		// it finds it is behind NAT. Use libp2p.Relay(options...) to
		// enable active relays and more.
		libp2p.EnableAutoRelay(),
	)
	if err != nil {
		panic(err)
	}

	// If you want to help other peers to figure out if they are behind
	// NATs, you can launch the server-side of AutoNAT too (AutoRelay
	// already runs the client)
	_, err = autonat.NewAutoNATService(ctx, host,
		// Support same non default security and transport options as
		// original host.
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(secio.ID, secio.New),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.DefaultTransports,
	)

	// The last step to get fully up and running would be to connect to
	// bootstrap peers (or any other peers). We leave this commented as
	// this is an example and the peer will die as soon as it finishes, so
	// it is unnecessary to put strain on the network.
	/*
		// This connects to public bootstrappers
		for _, addr := range dht.DefaultBootstrapPeers {
			pi, _ := peer.AddrInfoFromP2pAddr(addr)
			// We ignore errors as some bootstrap peers may be down
			// and that is fine.
			h2.Connect(ctx, *pi)
		}
	*/

	node := NewNode(host)
	return node
}

// ETH protocol
const ethProtocol = "/sperax/eth/0.0.1"

// BDLS consensus protocol
const bdlsProtocol = "/sperax/bdls/0.0.1"

type EthHandler struct {
}

func (handler *EthHandler) handleMessage(s network.Stream) {
}

type ConsensusHandler struct {
}

func (handler *ConsensusHandler) handleMessage(s network.Stream) {
}

type Node struct {
	host.Host        // the lib-p2p host
	ethHandler       *EthHandler
	consensusHandler *ConsensusHandler
	die              chan struct{}
	dieOnce          sync.Once
}

// Create a new node with its implemented protocols
func NewNode(host host.Host) *Node {
	node := &Node{Host: host}
	node.die = make(chan struct{})
	node.initETHProtocol()
	node.initBDLSProtocol()
	return node
}

func (node *Node) initETHProtocol() {
	node.ethHandler = new(EthHandler)
	node.SetStreamHandler(ethProtocol, node.ethHandler.handleMessage)
}

func (node *Node) initBDLSProtocol() {
	node.consensusHandler = new(ConsensusHandler)
	node.SetStreamHandler(bdlsProtocol, node.consensusHandler.handleMessage)
}
