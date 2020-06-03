package worker

import (
	"log"

	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/core/vm"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/pkg/errors"
)

// environment is the worker's current environment and holds all of the current state information.
type environment struct {
	signer   types.Signer
	state    *state.StateDB
	gasPool  *core.GasPool
	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
}

type Worker struct {
	config   *params.ChainConfig
	chain    *core.BlockChain
	current  *environment // An environment for current running cycle.
	engine   consensus.Engine
	gasFloor uint64
	gasCeil  uint64
}

// New create a new worker object.
func New(config *params.ChainConfig, chain *core.BlockChain, engine consensus.Engine) *Worker {
	worker := &Worker{
		config: config,
		chain:  chain,
		engine: engine,
	}
	worker.gasFloor = 80000000
	worker.gasCeil = 120000000

	parent := worker.chain.CurrentBlock()
	header := &types.Header{
		ParentHash: parent.Hash(),
	}
	worker.makeCurrent(parent, header)

	return worker
}

// makeCurrent creates a new environment for the current cycle.
func (w *Worker) makeCurrent(parent *types.Block, header *types.Header) error {
	state, err := w.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}
	env := &environment{
		state:  state,
		header: header,
	}

	w.current = env
	return nil
}

func (w *Worker) commitTransaction(tx *types.Transaction, coinbase common.Address) ([]*types.Log, error) {
	snap := w.current.state.Snapshot()
	receipt, err := core.ApplyTransaction(
		w.config,
		w.chain,
		&coinbase,
		w.current.gasPool,
		w.current.state,
		w.current.header,
		tx,
		&w.current.header.GasUsed,
		vm.Config{},
	)
	if err != nil {
		w.current.state.RevertToSnapshot(snap)
		log.Println("Transaction failed commitment", err)
		return nil, err
	}
	if receipt == nil {
		log.Println("Receipt is Nil!")
		return nil, errors.New("receipt is nil")
	}
	w.current.txs = append(w.current.txs, tx)
	w.current.receipts = append(w.current.receipts, receipt)
	return receipt.Logs, nil
}

// CommitTransactions commits transactions for new block.
func (w *Worker) CommitTransactions(pending map[common.Address]types.Transactions, coinbase common.Address) error {
	if w.current.gasPool == nil {
		w.current.gasPool = new(core.GasPool).AddGas(w.current.header.GasLimit)
	}

	txs := types.NewTransactionsByPriceAndNonce(w.current.signer, pending)
	for {
		// If we don't have enough gas for any further transactions then we're done
		if w.current.gasPool.Gas() < params.TxGas {
			log.Println("Not enough gas for further transactions", w.current.gasPool.Gas(), params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}

		from, _ := types.Sender(w.current.signer, tx)
		// Start executing the transaction
		w.current.state.Prepare(tx.Hash(), common.Hash{}, len(w.current.txs))

		_, err := w.commitTransaction(tx, coinbase)
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Println("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case core.ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			log.Println("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case core.ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Println("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Println("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}

	}

	log.Println("newTxns", len(w.current.txs))
	log.Println("blockGasLimit", w.current.header.GasLimit)
	log.Println("blockGasUsed", w.current.header.GasUsed)
	return nil
}

// FinalizeNewBlock generate a new block for the next consensus round.
func (w *Worker) FinalizeNewBlock() (*types.Block, error) {
	state := w.current.state.Copy()
	copyHeader := types.CopyHeader(w.current.header)
	block, err := w.engine.FinalizeAndAssemble(w.chain, copyHeader, state, w.current.txs, nil, w.current.receipts)
	if err != nil {
		return nil, errors.Wrap(err, "cannot finalize block")
	}

	return block, nil
}
