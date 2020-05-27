package p2p

import (
	"context"
	"crypto/ecdsa"
	"net"

	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// ConsensusTopic defines consensus messaging topic
const ConsensusTopic = "/sperax/consensus/1.0.0"

// consensus address, to uniquely identifies a node
type consensusAddress string

func (consensusAddress) Network() string     { return "p2p" }
func (addr consensusAddress) String() string { return string(addr) }

// ConsensusPeerAdapter defines a peer to work with consensus algorithm and libp2p
type ConsensusPeerAdapter struct {
	h     *Host
	topic *libp2p_pubsub.Topic
}

// NewConsensusPeerAdapter creates a peer adapter for consensus algorithm, and works on libp2p.
func NewConsensusPeerAdapter(h *Host) (*ConsensusPeerAdapter, error) {
	p := new(ConsensusPeerAdapter)
	p.h = h
	topic, err := h.GetOrJoin(ConsensusTopic)
	if err != nil {
		return nil, err
	}

	p.topic = topic
	return p, nil
}

// Topic returns the topic for consensus messaging
func (p *ConsensusPeerAdapter) Topic() *libp2p_pubsub.Topic { return p.topic }

// We adapt BROADCASTING scheme for consensus algorithm, so we need only ONE consensus peer for
// message routing.
//
// Below are the interfaces adapter for consensus, will treat this p2p host as a peer for
// broadcasting entry.
//
// To work with UNICASTING scheme for consensus, this can be adjusted to peer's public key,
// and should be cautious with directly unreachable peers.
func (p *ConsensusPeerAdapter) GetPublicKey() *ecdsa.PublicKey { return &p.h.priKey.PublicKey }

// RemoteAddr returns remote addr for consensus algorithm to uniquely identifies a peer.
func (p *ConsensusPeerAdapter) RemoteAddr() net.Addr { return consensusAddress(p.h.host.ID()) }

// Send is callback for consensus message exchanging.
func (p *ConsensusPeerAdapter) Send(msg []byte) error {
	go func() {
		ctx := context.Background()
		p.topic.Publish(ctx, msg)
	}()
	return nil
}
