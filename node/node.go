package node

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/core"
	"github.com/Sperax/SperaxChain/core/rawdb"
	"github.com/Sperax/SperaxChain/core/vm"
	"github.com/Sperax/SperaxChain/p2p"
	"github.com/Sperax/bdls"
	"github.com/ethereum/go-ethereum/params"

	"github.com/Sperax/bdls/timer"
)

// Node represents a Sperax node on it's network
type Node struct {
	host *p2p.Host // the p2p host

	// consensus related
	consensus     *bdls.Consensus // the core consensus algorithm
	consensusLock sync.Mutex      // consensus lock

	// transactions pool
	txPool *core.TxPool

	// blockchain related
	blockchain *core.BlockChain

	die     chan struct{} // closing signal
	dieOnce sync.Once

	ctx    context.Context    // context based goroutines
	cancel context.CancelFunc // cancel function
}

// New creates a new node.
func New(
	host *p2p.Host,
	consensus *bdls.Consensus,
) (*Node, error) {

	node := new(Node)
	node.host = host
	node.consensus = consensus
	node.die = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	node.ctx = ctx
	node.cancel = cancel

	// init chaindb
	config := Config{}
	chainDb, err := rawdb.NewLevelDBDatabaseWithFreezer(".", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "sperax/db/chaindata/")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Println("Initialised chain configuration", "config", chainConfig, genesisHash)

	// cache config
	cacheConfig := &core.CacheConfig{
		TrieCleanLimit:      config.TrieCleanCache,
		TrieCleanNoPrefetch: config.NoPrefetch,
		TrieDirtyLimit:      config.TrieDirtyCache,
		TrieDirtyDisabled:   config.NoPruning,
		TrieTimeLimit:       config.TrieTimeout,
		SnapshotLimit:       config.SnapshotCache,
	}

	// vm config
	vmConfig := vm.Config{
		EnablePreimageRecording: config.EnablePreimageRecording,
		EWASMInterpreter:        config.EWASMInterpreter,
		EVMInterpreter:          config.EVMInterpreter,
	}
	// init blockchain
	node.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, nil, vmConfig, nil, &config.TxLookupLimit)
	if err != nil {
		return nil, err
	}
	// init txpool
	txPoolConfig := core.DefaultTxPoolConfig
	node.txPool = core.NewTxPool(txPoolConfig, chainConfig, node.blockchain)

	// trigger the consensus updater
	node.consensusUpdate()
	// start consensus messaging loop
	go node.consensusMessenger(node.ctx)
	return node, nil
}

// Close this node
func (node *Node) Close() {
	node.dieOnce.Do(func() {
		close(node.die)
		node.cancel()
	})
}

// consensusMessenger is a goroutine to receive all messages required for consensus & transactions
func (node *Node) consensusMessenger(ctx context.Context) {
	// consensus peer adapter
	peer, err := p2p.NewBDLSPeerAdapter(node.host)
	if err != nil {
		panic(err)
	}
	node.consensus.Join(peer)

	// subscribe & handle messages
	sub, err := peer.Topic().Subscribe()
	for {
		msg, err := sub.Next(ctx)
		if err != nil { // cancelFunc trigger error
			select {
			case <-node.die: //  signal messenger exit
				return
			default:
				continue
			}
		}

		// handle consensus messages
		node.consensusLock.Lock()
		node.consensus.ReceiveMessage(msg.Data, time.Now())
		node.consensusLock.Unlock()
	}
}

// consensusUpdate is a self-sustaining function to call consensus.Update periodically
// with the help of bdls.timer
func (node *Node) consensusUpdate() {
	node.consensusLock.Lock()
	node.consensus.Update(time.Now())
	node.consensusLock.Unlock()
	timer.SystemTimedSched.Put(node.consensusUpdate, time.Now().Add(20*time.Millisecond))
}

/*
// proposer
					var currentHeight uint64
				PROPOSE:
					for {
						data := make([]byte, 1024)
						io.ReadFull(rand.Reader, data)

						bdlsConsensusLock.Lock()
						bdlsConsensus.Propose(data)
						bdlsConsensusLock.Unlock()

						for {
							newHeight, newRound, newState := bdlsConsensus.CurrentState()
							if newHeight > currentHeight {
								h := blake2b.Sum256(newState)
								log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))
								currentHeight = newHeight
								continue PROPOSE
							}
							// wait
							<-time.After(20 * time.Millisecond)
						}
					}
*/
