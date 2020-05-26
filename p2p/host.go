package p2p

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"sync"

	badger "github.com/ipfs/go-ds-badger"
	"github.com/pkg/errors"

	"context"

	"github.com/libp2p/go-libp2p"
	libp2p_crypto "github.com/libp2p/go-libp2p-core/crypto"
	libp2p_host "github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	libp2p_disc "github.com/libp2p/go-libp2p-discovery"
	libp2p_dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
	ma "github.com/multiformats/go-multiaddr"
)

const Rendezvous = "/sperax/1.0.0"

// Host defines a host to participant in p2p network
type Host struct {
	host   libp2p_host.Host
	pubsub *libp2p_pubsub.PubSub
	priKey *ecdsa.PrivateKey
	topics map[string]*libp2p_pubsub.Topic
	dht    *libp2p_dht.IpfsDHT
	sync.Mutex
}

// NewHost initialize a p2p node with given multiaddr
func NewHost(port string, priv *ecdsa.PrivateKey) (*Host, error) {
	// address creation
	listenAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port))
	if err != nil {
		return nil, errors.Wrapf(err,
			"cannot create listen multiaddr from port %#v", port)
	}
	ctx := context.Background()

	// convert secp256k1 ecdsa privatekey to p2p private key
	p2p_priv, err := libp2p_crypto.UnmarshalSecp256k1PrivateKey(priv.D.Bytes())
	if err != nil {
		panic(err)
	}

	// init p2p host
	host, err := libp2p.New(ctx,
		libp2p.ListenAddrs(listenAddr), libp2p.Identity(p2p_priv),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot initialize libp2p host")
	}

	// init DHT module
	dataStorePath := fmt.Sprintf(".dht-%s", host.ID().Pretty())
	dataStore, err := badger.NewDatastore(dataStorePath, nil)
	if err != nil {
		log.Println(err, "cannot initialize DHT cache at %s", dataStorePath)
	}
	dht, err := libp2p_dht.New(ctx, host, libp2p_dht.Datastore(dataStore), libp2p_dht.Mode(libp2p_dht.ModeServer))
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create DHT")
	}

	err = dht.Bootstrap(ctx)
	if err != nil {
		panic(err)
	}

	// init peer discovery module
	routingDiscovery := libp2p_disc.NewRoutingDiscovery(dht)
	libp2p_disc.Advertise(ctx, routingDiscovery, Rendezvous)
	peerChan, err := routingDiscovery.FindPeers(ctx, Rendezvous)
	if err != nil {
		panic(err)
	}

	// init pubsub module
	const MaxSize = 1048576
	options := []libp2p_pubsub.Option{
		libp2p_pubsub.WithPeerOutboundQueueSize(64),
		libp2p_pubsub.WithMaxMessageSize(MaxSize),
	}

	pubsub, err := libp2p_pubsub.NewGossipSub(ctx, host, options...)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot initialize libp2p pubsub")
	}

	// host object
	h := &Host{
		dht:    dht,
		host:   host,
		pubsub: pubsub,
		priKey: priv,
		topics: make(map[string]*libp2p_pubsub.Topic),
	}

	go h.peerRefresh(peerChan)
	return h, nil
}

// Address returns host's multiaddr
func (h *Host) Address() ma.Multiaddr {
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", h.host.ID().Pretty()))
	return h.host.Addrs()[0].Encapsulate(hostAddr)
}

// GetOrJoin or Get a given topic
func (h *Host) GetOrJoin(topic string) (*libp2p_pubsub.Topic, error) {
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

// Connect initiate an active connection to a given peer
func (h *Host) Connect(addr ma.Multiaddr) error {
	targetInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		panic(err)
	}
	log.Println(targetInfo)
	ctx := context.Background()
	return h.host.Connect(ctx, *targetInfo)
}

// peerRefresh monitors and connect to new peer
func (h *Host) peerRefresh(peerChan <-chan peer.AddrInfo) {
	for peer := range peerChan {
		if peer.ID == h.host.ID() {
			continue
		}
		ctx := context.Background()
		err := h.host.Connect(ctx, peer)
		if err != nil {
			log.Println("Connection failed:", err)
			continue
		}
		log.Println("Connected to:", peer)
	}
}
