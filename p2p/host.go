package p2p

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"

	"context"

	"github.com/libp2p/go-libp2p"
	libp2p_crypto "github.com/libp2p/go-libp2p-core/crypto"
	libp2p_host "github.com/libp2p/go-libp2p-core/host"
	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
	ma "github.com/multiformats/go-multiaddr"
)

type Host struct {
	h      libp2p_host.Host
	pubsub *libp2p_pubsub.PubSub
	priKey libp2p_crypto.PrivKey
	lock   sync.Mutex
}

// NewHost initialize a p2p node with given multiaddr
// eg addr: "/ip4/0.0.0.0/tcp/9000"
func NewHost(port string, priv libp2p_crypto.PrivKey) (*Host, error) {
	// address creation
	listenAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port))
	if err != nil {
		return nil, errors.Wrapf(err,
			"cannot create listen multiaddr from port %#v", port)
	}
	ctx := context.Background()

	// init peer
	p2pHost, err := libp2p.New(ctx,
		libp2p.ListenAddrs(listenAddr), libp2p.Identity(priv),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot initialize libp2p host")
	}

	// init pubsub
	const MaxSize = 1048576
	options := []libp2p_pubsub.Option{
		libp2p_pubsub.WithPeerOutboundQueueSize(64),
		libp2p_pubsub.WithMaxMessageSize(MaxSize),
	}

	pubsub, err := libp2p_pubsub.NewGossipSub(ctx, p2pHost, options...)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot initialize libp2p pubsub")
	}

	// host object
	h := &Host{
		h:      p2pHost,
		pubsub: pubsub,
		priKey: priv,
	}
	return h, nil
}
