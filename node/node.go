package node

import (
	"context"
	"encoding/hex"
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
	"github.com/Sperax/bdls"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/minio/blake2b-simd"

	"github.com/Sperax/bdls/timer"
)

const freezerDir = "/freezer"
const chainDBDir = "/chaindb"
const namespace = "sperax/db/chaindata/"

// Node represents a Sperax node on it's network
type Node struct {
	host *p2p.Host // the p2p host

	// consensus related
	consensus       *bdls.Consensus // the core consensus algorithm
	consensusLock   sync.Mutex      // consensus lock
	consensusEngine consensus.Engine

	// transactions pool
	txPool *core.TxPool

	// blockchain related
	blockchain *core.BlockChain

	// TODO: worker

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

	// init blockchain
	node.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, engine, vmConfig, nil, &config.TxLookupLimit)
	if err != nil {
		log.Println("new blockchain:", err)
		return nil, err
	}
	// init txpool
	txPoolConfig := core.DefaultTxPoolConfig
	node.txPool = core.NewTxPool(txPoolConfig, chainConfig, node.blockchain)

	// trigger the consensus updater
	node.consensusUpdate()
	// start consensus messaging loop
	go node.consensusMessenger(node.ctx)
	//  the main clock for generating blocks
	go node.consensusClock()
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

// consensusClock is the main block generation clock for blockchain
func (node *Node) consensusClock() {
	node.consensusLock.Lock()
	node.proposeNewBlock()
	currentHeight, _, _ := node.consensus.CurrentState()
	node.consensusLock.Unlock()

	for {
		node.consensusLock.Lock()
		newHeight, newRound, newState := node.consensus.CurrentState()
		node.consensusLock.Unlock()

		if newHeight > currentHeight {
			h := blake2b.Sum256(newState)
			log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))
			currentHeight = newHeight

			// CLOCK
			node.consensusLock.Lock()
			node.proposeNewBlock()
			node.consensusLock.Unlock()
		}
		// check periodically for new height
		<-time.After(1 * time.Second)
	}
}

// proposeNewBlock collects transactions from txpool and seal a new block to propose to
// consensus algorithm
func (node *Node) proposeNewBlock() {
	pending, err := node.txPool.Pending()
	if err != nil {
		log.Println("Failed to fetch pending transactions")
		return
	}
	parent := node.blockchain.CurrentBlock()
	timestamp := time.Now().Unix()
	num := parent.Number()
	if parent.Time() >= uint64(timestamp) {
		timestamp = int64(parent.Time() + 1)
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		Time:       uint64(timestamp),
	}

	// simply include all transactions
	var txs []*types.Transaction
	for _, list := range pending {
		for _, tx := range list {
			txs = append(txs, tx)
		}
	}

	newblock := types.NewBlock(header, txs, nil)
	encodedBlockHeader, err := rlp.EncodeToBytes(newblock.Header())
	if err != nil {
		log.Println(err)
	}
	node.consensus.Propose(encodedBlockHeader)
	log.Println("proposed")
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
