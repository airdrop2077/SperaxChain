package bdls_engine

import (
	"errors"
	"math/big"

	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/bdls"
	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/log"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/SperaxChain/rpc"
)

type BDLSEngine struct {
	consensusConfig *bdls.Config
}

func NewBDLSEngine(consensusConfig *bdls.Config) *BDLSEngine {
	engine := new(BDLSEngine)
	engine.consensusConfig = consensusConfig
	return engine
}

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *BDLSEngine) Author(header *types.Header) (common.Address, error) {
	return common.Address{}, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *BDLSEngine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	parentHeader := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parentHeader == nil {
		return errors.New("unknown ancestor")
	}
	if seal {
		if err := e.VerifySeal(chain, header); err != nil {
			return err
		}
	}
	return nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (e *BDLSEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := e.VerifyHeader(chain, header, seals[i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()

	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of a given engine.
func (e *BDLSEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (e *BDLSEngine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// step 1. Get the SealHash(without Decision field) of this header
	sealHash := e.SealHash(header).Bytes()

	// step 2. create a consensus object to validate this message at the correct height
	config := *e.consensusConfig
	config.CurrentHeight = header.Number.Uint64()

	consensus, err := bdls.NewConsensus(e.consensusConfig)
	if err != nil {
		log.Error("new consensus:", err)
		return err
	}

	// step 3. validate decide message integrity
	err = consensus.ValidateDecideMessage(header.Decision, sealHash)
	if err != nil {
		log.Debug("VerifySeal", "ValidateDecideMessage", err)
		return err
	}

	return nil
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *BDLSEngine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *BDLSEngine) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	accumulateRewards(chain.Config(), state, header)
	header.Root = state.IntermediateRoot(true)
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *BDLSEngine) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	accumulateRewards(chain.Config(), state, header)
	header.Root = state.IntermediateRoot(true)
	return types.NewBlock(header, txs, receipts), nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (e *BDLSEngine) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (e *BDLSEngine) SealHash(header *types.Header) (hash common.Hash) {
	copied := types.CopyHeader(header)
	copied.Decision = nil
	return copied.Hash()
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (e *BDLSEngine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return common.Big1
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *BDLSEngine) APIs(chain consensus.ChainReader) []rpc.API {
	// TODO
	return nil
}

// Close terminates any background threads maintained by the consensus engine.
func (e *BDLSEngine) Close() error {
	// TODO
	return nil
}

// mining reward computation
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header) {
	state.AddBalance(common.Address{}, big.NewInt(100))
}
