package node

import (
	"context"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/consensus/bdls_engine"
	"github.com/Sperax/SperaxChain/core"
	"github.com/Sperax/SperaxChain/core/rawdb"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/core/vm"
	"github.com/Sperax/SperaxChain/p2p"
	"github.com/Sperax/SperaxChain/worker"
	"github.com/Sperax/bdls"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/minio/blake2b-simd"

	"github.com/Sperax/bdls/timer"
)

const (
	freezerDir = "/freezer"
	chainDBDir = "/chaindb"
	namespace  = "sperax/db/chaindata/"
)

const ()

// Node represents a Sperax node on it's network
type Node struct {
	host *p2p.Host // the p2p host

	// consensus related
	consensus       *bdls.Consensus // the core consensus algorithm
	consensusLock   sync.Mutex      // consensus lock
	consensusEngine consensus.Engine

	// worker
	worker *worker.Worker

	// transactions pool
	txPool *core.TxPool

	// blockchain related
	blockchain *core.BlockChain

	// closing
	die     chan struct{} // closing signal
	dieOnce sync.Once

	ctx    context.Context    // context based goroutines
	cancel context.CancelFunc // cancel function
}

// New creates a new node.
func New(host *p2p.Host, consensus *bdls.Consensus, config *Config) (*Node, error) {
	node := new(Node)
	node.host = host
	node.consensus = consensus
	node.die = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	node.ctx = ctx
	node.cancel = cancel

	// init chaindb
	chainDb, err := rawdb.NewLevelDBDatabaseWithFreezer(config.DatabaseDir+chainDBDir, config.DatabaseCache, config.DatabaseHandles, config.DatabaseDir+freezerDir, namespace)
	if err != nil {
		log.Println("new leveldb:", chainDb, err)
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

	// init consensus engine
	engine := bdls_engine.NewBDLSEngine()
	engine.SetConsensus(consensus)
	node.consensusEngine = engine

	// init blockchain
	node.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, engine, vmConfig, nil, &config.TxLookupLimit)
	if err != nil {
		log.Println("new blockchain:", err)
		return nil, err
	}
	// init txpool
	txPoolConfig := core.DefaultTxPoolConfig
	node.txPool = core.NewTxPool(txPoolConfig, chainConfig, node.blockchain)

	// init worker
	node.worker = worker.New(config.Genesis.Config, node.blockchain, engine)

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

	newBlock, err := node.proposeNewBlock()
	if err != nil {
		log.Println(err)
		panic(err)
	}

	log.Println("newBlock:", newBlock)
	sealHash := node.consensusEngine.SealHash(newBlock.Header()).Bytes()
	node.consensusLock.Lock()
	node.consensus.Propose(sealHash)
	node.consensusLock.Unlock()

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

		node.consensusLock.Lock()
		currentHeight, _, _ := node.consensus.CurrentState()
		// handle consensus messages
		node.consensus.ReceiveMessage(msg.Data, time.Now())
		newHeight, newRound, newState := node.consensus.CurrentState()
		node.consensusLock.Unlock()

		// should propose new block as participants if consensus
		// has confirmed a new height
		if newHeight > currentHeight {
			h := blake2b.Sum256(newState)
			log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))

			newBlock, err := node.proposeNewBlock()
			if err != nil {
				panic(err)
			}

			// TODO:
			// step 1. broadcast block data

			//  step2. consensus propose
			sealHash := node.consensusEngine.SealHash(newBlock.Header()).Bytes()
			node.consensusLock.Lock()
			node.consensus.Propose(sealHash)
			node.consensusLock.Unlock()
		}
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

// proposeNewBlock collects transactions from txpool and seal a new block to propose to
// consensus algorithm
func (node *Node) proposeNewBlock() (*types.Block, error) {
	pending, err := node.txPool.Pending()
	if err != nil {
		return nil, errors.New("Failed to fetch pending transactions")
	}

	coinbase := common.Address{}
	if err := node.worker.CommitTransactions(pending, coinbase); err != nil {
		return nil, err
	}

	log.Println("proposed")
	return node.worker.FinalizeNewBlock()
}

// Add a remote transactions
func (node *Node) AddRemoteTransaction(tx *types.Transaction) error {
	err := node.txPool.AddRemote(tx)
	if err != nil {
		return err
	}
	pendingCount, queueCount := node.txPool.Stats()
	log.Println("addtx:", pendingCount, queueCount)
	return nil
}
