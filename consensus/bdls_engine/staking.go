// BSD 3-Clause License
//
// Copyright (c) 2020, Sperax
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package bdls_engine

import (
	"encoding/binary"
	"math/big"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/common/hexutil"
	"github.com/Sperax/SperaxChain/consensus"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	W0    = crypto.Keccak256(hexutil.MustDecode("0x3243F6A8885A308D313198A2E037073"))
	E1    = big.NewInt(5)      // potential propser expectation
	E2    = big.NewInt(50)     // BFT committee expectationA
	Alpha = big.NewInt(100000) // unit of staking SPA
)

// Rand calcuates W
// W0 = H(U0)
// Wj = H(Pj-1,Wj-1) for 0<j<=r,
func (e *BDLSEngine) RandAtBlock(chain consensus.ChainReader, block *types.Block) []byte {
	if block.NumberU64() == 0 {
		return W0
	}

	// call RandAtABlock recursivly
	hasher := sha3.NewLegacyKeccak256()
	prevBlock := chain.GetBlock(block.ParentHash(), block.NumberU64()-1)
	coinbase := prevBlock.Coinbase()
	hasher.Write(coinbase[:])
	// TODO: if W has written in block header, then we can stop recursion.
	hasher.Write(e.RandAtBlock(chain, prevBlock))
	return hasher.Sum(nil)
}

// H(r;0;Ri,r,0;Wr) > max{0;1 i-aip}
func (e *BDLSEngine) IsProposer(chain consensus.ChainReader, block *types.Block, R common.Hash, numStaked *big.Int, totalStaked *big.Int) bool {
	// compute p
	p := big.NewFloat(0).SetInt(E1)
	p.Mul(p, big.NewFloat(0).SetInt(Alpha))
	p.Quo(p, big.NewFloat(0).SetInt(totalStaked))

	// max{0, 1 - ai*p}
	max := p.Sub(big.NewFloat(1), p.Mul(big.NewFloat(0).SetInt(numStaked), p))
	if max.Cmp(big.NewFloat(0)) != 1 {
		max = big.NewFloat(0)
	}

	// compute H
	hasher := sha3.NewLegacyKeccak256()
	binary.Write(hasher, binary.LittleEndian, block.NumberU64())
	binary.Write(hasher, binary.LittleEndian, 0)
	hasher.Write(R[:])
	hasher.Write(e.RandAtBlock(chain, block))

	h := big.NewFloat(0)
	x := big.NewFloat(0).SetInt(big.NewInt(0).SetBytes(hasher.Sum(nil)))
	y := big.NewFloat(0).SetInt(big.NewInt(0).SetBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
	h.Quo(x, y)

	if h.Cmp(max) == 1 {
		return true
	}
	return false
}
