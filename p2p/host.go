package p2p

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"sync"

	"github.com/pkg/errors"

	"context"

	"github.com/libp2p/go-libp2p"
	libp2p_crypto "github.com/libp2p/go-libp2p-core/crypto"
	libp2p_host "github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
	ma "github.com/multiformats/go-multiaddr"
)

type Host struct {
	host   libp2p_host.Host
	pubsub *libp2p_pubsub.PubSub
	priKey *ecdsa.PrivateKey
	topics map[string]*libp2p_pubsub.Topic // joined topic
	sync.Mutex
}

// NewHost initialize a p2p node with given multiaddr
// eg addr: "/ip4/0.0.0.0/tcp/9000"
func NewHost(port string, priv *ecdsa.PrivateKey) (*Host, error) {
	// address creation
	listenAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port))
	if err != nil {
		return nil, errors.Wrapf(err,
			"cannot create listen multiaddr from port %#v", port)
	}
	ctx := context.Background()

	// conver to p2p private key
	p2p_priv, err := libp2p_crypto.UnmarshalSecp256k1PrivateKey(priv.D.Bytes())
	if err != nil {
		panic(err)
	}

	// init peer
	p2pHost, err := libp2p.New(ctx,
		libp2p.ListenAddrs(listenAddr), libp2p.Identity(p2p_priv),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot initialize libp2p host")
	}
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", p2pHost.ID().Pretty()))

	log.Println(p2pHost.Addrs()[0].Encapsulate(hostAddr))

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
		host:   p2pHost,
		pubsub: pubsub,
		priKey: priv,
		topics: make(map[string]*libp2p_pubsub.Topic),
	}
	return h, nil
}

// Join or Get a given topic
func (h *Host) Join(topic string) (*libp2p_pubsub.Topic, error) {
	h.Lock()
	defer h.Unlock()

	t, ok := h.topics[topic]
	if ok {
		return t, nil
	}

	t, err := h.pubsub.Join(topic)
	if err != nil {
		return nil, err
	}

	h.topics[topic] = t
	return t, nil
}

func (h *Host) Connect(addr ma.Multiaddr) error {
	targetInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		panic(err)
	}
	log.Println(targetInfo)
	ctx := context.Background()
	return h.host.Connect(ctx, *targetInfo)
}
