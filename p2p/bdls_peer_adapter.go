package p2p

import (
	"context"
	"crypto/ecdsa"
	"net"

	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// BDLSTopic defines consensus messaging topic
const BDLSTopic = "/sperax/bdls/1.0.0"

// consensus address, to uniquely identifies a node
type bdlsPeerAddress string

func (bdlsPeerAddress) Network() string     { return "p2p" }
func (addr bdlsPeerAddress) String() string { return string(addr) }

// BDLSPeerAdapter defines a peer to work with consensus algorithm and libp2p
type BDLSPeerAdapter struct {
	h     *Host
	topic *libp2p_pubsub.Topic
}

// NewBDLSPeerAdapter creates a peer adapter for consensus algorithm, and works on libp2p.
func NewBDLSPeerAdapter(h *Host) (*BDLSPeerAdapter, error) {
	p := new(BDLSPeerAdapter)
	p.h = h
	topic, err := h.GetOrJoin(BDLSTopic)
	if err != nil {
		return nil, err
	}

	p.topic = topic
	return p, nil
}

// Topic returns the topic for consensus messaging
func (p *BDLSPeerAdapter) Topic() *libp2p_pubsub.Topic { return p.topic }

// We adapt BROADCASTING scheme for consensus algorithm, so we need only ONE consensus peer for
// message routing.
//
// Below are the interfaces adapter for consensus, will treat this p2p host as a peer for
// broadcasting entry.
//
// To work with UNICASTING scheme for consensus, this can be adjusted to peer's public key,
// and should be cautious with directly unreachable peers.
func (p *BDLSPeerAdapter) GetPublicKey() *ecdsa.PublicKey { return &p.h.priKey.PublicKey }

// RemoteAddr returns remote addr for consensus algorithm to uniquely identifies a peer.
func (p *BDLSPeerAdapter) RemoteAddr() net.Addr { return bdlsPeerAddress(p.h.host.ID()) }

// Send is callback for consensus message exchanging.
func (p *BDLSPeerAdapter) Send(msg []byte) error {
	go func() {
		ctx := context.Background()
		p.topic.Publish(ctx, msg)
	}()
	return nil
}
