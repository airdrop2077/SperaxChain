package p2p

import (
	"context"
	"crypto/ecdsa"
	"net"

	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
)

type p2pAddress string

func (p2pAddress) Network() string     { return "p2p" }
func (addr p2pAddress) String() string { return string(addr) }

type Peer struct {
	h     *Host
	topic *libp2p_pubsub.Topic
}

func NewPeer(h *Host) (*Peer, error) {
	p := new(Peer)
	p.h = h
	topic, err := h.Join(ConsensusTopic)
	if err != nil {
		return nil, err
	}

	p.topic = topic
	return p, nil
}

// We adapt broadcasting scheme for consensus algorithm, so we need only ONE consensus peer for
// message routing.
// below are the interfaces adapter for consensus, will treat this p2p host as a peer for
// broadcasting entry.
func (p *Peer) GetPublicKey() *ecdsa.PublicKey { return &p.h.priKey.PublicKey }

// RemoteAddr returns remote addr
func (p *Peer) RemoteAddr() net.Addr { return p2pAddress(p.h.host.ID()) }

// Send a msg to this peer
func (p *Peer) Send(msg []byte) error {
	go func() {
		ctx := context.Background()
		p.topic.Publish(ctx, msg)
	}()
	return nil
}
