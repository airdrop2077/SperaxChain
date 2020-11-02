// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/Sperax/SperaxChain/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// test network.
var TestnetBootnodes = []string{
	"enode://fa1c6b5c763775f40d5d7f83d73dbd36c7fb8d2782041bf531c49e9204e195af4feaaa406c063e373b1937ec5f4a38dd793048b607eeea4f3f850355042bc950@18.183.64.226:30303",
	"enode://9277ce1ffb56c48c8577b34ca54343d365a6f0a0bfc5365d2c4b1948f20e17ed6f3273be95aac460afb0f79e99a6505e429872913792b547436078ff53156a02@54.168.60.62:30303",
	"enode://61ac01c4ad8a9b63f284b54437681f32f38922d9f3499118aa6e1217fdfa98768cb449a2618b231c0e2e903b56ef2590fb40247d4acd0eb988cc82dc0ea4e0f7@54.249.196.162:30303",
	"enode://163e06d54807c5327dff80cad281eaa24061e5d819e02353620a63ea9698d98932591c3041a010d9c54885f0986bf7fa793887ae067d838c327da63894e375bf@18.181.86.225:30303",
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// These DNS names provide bootstrap connectivity for public testnets and the mainnet.
// See https://github.com/ethereum/discv4-dns-lists for more information.
var KnownDNSNetworks = map[common.Hash]string{
	// TODO(xtaci): setup dns
	MainnetGenesisHash: dnsPrefix + "mainnet.sperax.io",
	TestnetGenesisHash: dnsPrefix + "test01.sperax.io",
}
