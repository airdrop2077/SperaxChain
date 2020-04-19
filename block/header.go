package block

import (
	"io"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/rs/zerolog"

	"github.com/Sperax/SperaxChain/crypto/hash"
)

type Header struct {
	fields headerFields
}

// EncodeRLP encodes the header fields into RLP format.
func (h *Header) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &h.fields)
}

// DecodeRLP decodes the given RLP decode stream into the header fields.
func (h *Header) DecodeRLP(s *rlp.Stream) error {
	return s.Decode(&h.fields)
}

// NewHeader creates a new header object.
func NewHeader() *Header {
	return &Header{headerFields{
		Number: new(big.Int),
		Time:   new(big.Int),
	}}
}

type headerFields struct {
	ParentHash          common.Hash    `json:"parentHash"       gencodec:"required"`
	Coinbase            common.Address `json:"miner"            gencodec:"required"`
	Root                common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash              common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash         common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	OutgoingReceiptHash common.Hash    `json:"outgoingReceiptsRoot"     gencodec:"required"`
	IncomingReceiptHash common.Hash    `json:"incomingReceiptsRoot" gencodec:"required"`
	Bloom               ethtypes.Bloom `json:"logsBloom"        gencodec:"required"`
	Number              *big.Int       `json:"number"           gencodec:"required"`
	GasLimit            uint64         `json:"gasLimit"         gencodec:"required"`
	GasUsed             uint64         `json:"gasUsed"          gencodec:"required"`
	Time                *big.Int       `json:"timestamp"        gencodec:"required"`
	Extra               []byte         `json:"extraData"        gencodec:"required"`
	MixDigest           common.Hash    `json:"mixHash"          gencodec:"required"`
	// Additional Fields
	BDLSDecide []byte `json:"signature" gencodec:"required"` // the related <decide> message to this block
}

// ParentHash is the header hash of the parent block.  For the genesis block
// which has no parent by definition, this field is zeroed out.
func (h *Header) ParentHash() common.Hash {
	return h.fields.ParentHash
}

// SetParentHash sets the parent hash field.
func (h *Header) SetParentHash(newParentHash common.Hash) {
	h.fields.ParentHash = newParentHash
}

// Coinbase is the address of the node that proposed this block and all
// transactions in it.
func (h *Header) Coinbase() common.Address {
	return h.fields.Coinbase
}

// SetCoinbase sets the coinbase address field.
func (h *Header) SetCoinbase(newCoinbase common.Address) {
	h.fields.Coinbase = newCoinbase
}

// Root is the state (account) trie root hash.
func (h *Header) Root() common.Hash {
	return h.fields.Root
}

// SetRoot sets the state trie root hash field.
func (h *Header) SetRoot(newRoot common.Hash) {
	h.fields.Root = newRoot
}

// TxHash is the transaction trie root hash.
func (h *Header) TxHash() common.Hash {
	return h.fields.TxHash
}

// SetTxHash sets the transaction trie root hash field.
func (h *Header) SetTxHash(newTxHash common.Hash) {
	h.fields.TxHash = newTxHash
}

// ReceiptHash is the same-shard transaction receipt trie hash.
func (h *Header) ReceiptHash() common.Hash {
	return h.fields.ReceiptHash
}

// SetReceiptHash sets the same-shard transaction receipt trie hash.
func (h *Header) SetReceiptHash(newReceiptHash common.Hash) {
	h.fields.ReceiptHash = newReceiptHash
}

// OutgoingReceiptHash is the egress transaction receipt trie hash.
func (h *Header) OutgoingReceiptHash() common.Hash {
	return h.fields.OutgoingReceiptHash
}

// SetOutgoingReceiptHash sets the egress transaction receipt trie hash.
func (h *Header) SetOutgoingReceiptHash(newOutgoingReceiptHash common.Hash) {
	h.fields.OutgoingReceiptHash = newOutgoingReceiptHash
}

// IncomingReceiptHash is the ingress transaction receipt trie hash.
func (h *Header) IncomingReceiptHash() common.Hash {
	return h.fields.IncomingReceiptHash
}

// SetIncomingReceiptHash sets the ingress transaction receipt trie hash.
func (h *Header) SetIncomingReceiptHash(newIncomingReceiptHash common.Hash) {
	h.fields.IncomingReceiptHash = newIncomingReceiptHash
}

// Bloom is the Bloom filter that indexes accounts and topics logged by smart
// contract transactions (executions) in this block.
func (h *Header) Bloom() ethtypes.Bloom {
	return h.fields.Bloom
}

// SetBloom sets the smart contract log Bloom filter for this block.
func (h *Header) SetBloom(newBloom ethtypes.Bloom) {
	h.fields.Bloom = newBloom
}

// Number is the block number.
//
// The returned instance is a copy; the caller may do anything with it.
func (h *Header) Number() *big.Int {
	return new(big.Int).Set(h.fields.Number)
}

// SetNumber sets the block number.
//
// It stores a copy; the caller may freely modify the original.
func (h *Header) SetNumber(newNumber *big.Int) {
	h.fields.Number = new(big.Int).Set(newNumber)
}

// GasLimit is the gas limit for transactions in this block.
func (h *Header) GasLimit() uint64 {
	return h.fields.GasLimit
}

// SetGasLimit sets the gas limit for transactions in this block.
func (h *Header) SetGasLimit(newGasLimit uint64) {
	h.fields.GasLimit = newGasLimit
}

// GasUsed is the amount of gas used by transactions in this block.
func (h *Header) GasUsed() uint64 {
	return h.fields.GasUsed
}

// SetGasUsed sets the amount of gas used by transactions in this block.
func (h *Header) SetGasUsed(newGasUsed uint64) {
	h.fields.GasUsed = newGasUsed
}

// Time is the UNIX timestamp of this block.
//
// The returned instance is a copy; the caller may do anything with it.
func (h *Header) Time() *big.Int {
	return new(big.Int).Set(h.fields.Time)
}

// SetTime sets the UNIX timestamp of this block.
//
// It stores a copy; the caller may freely modify the original.
func (h *Header) SetTime(newTime *big.Int) {
	h.fields.Time = new(big.Int).Set(newTime)
}

// Extra is the extra data field of this block.
//
// The returned slice is a copy; the caller may do anything with it.
func (h *Header) Extra() []byte {
	return append(h.fields.Extra[:0:0], h.fields.Extra...)
}

// SetExtra sets the extra data field of this block.
//
// It stores a copy; the caller may freely modify the original.
func (h *Header) SetExtra(newExtra []byte) {
	h.fields.Extra = append(newExtra[:0:0], newExtra...)
}

// MixDigest is the mixhash.
//
// This field is a remnant from Ethereum, and Harmony does not use it and always
// zeroes it out.
func (h *Header) MixDigest() common.Hash {
	return h.fields.MixDigest
}

// SetMixDigest sets the mixhash of this block.
func (h *Header) SetMixDigest(newMixDigest common.Hash) {
	h.fields.MixDigest = newMixDigest
}

// BDLSDecide is the BDLS commit group signature for the last block.
func (h *Header) BDLSDecide() []byte {
	return h.fields.BDLSDecide
}

// SetBDLSDecide sets the BDLS commit group signature for the last
// block.
func (h *Header) SetBDLSDecide(decide []byte) {
	h.fields.BDLSDecide = decide
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	return hash.FromRLP(h)
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	// TODO: update with new fields
	return common.StorageSize(unsafe.Sizeof(*h)) +
		common.StorageSize(len(h.Extra())+(h.Number().BitLen()+
			h.Time().BitLen())/8,
		)
}

// Logger returns a sub-logger with block contexts added.
func (h *Header) Logger(logger *zerolog.Logger) *zerolog.Logger {
	nlogger := logger.
		With().
		Str("blockHash", h.Hash().Hex()).
		Uint64("blockNumber", h.Number().Uint64()).
		Logger()
	return &nlogger
}
