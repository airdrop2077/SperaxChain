// Copyright 2017 The go-ethereum Authors
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

package core

// Constants containing the genesis allocation of built-in genesis blocks.
// Their content is an RLP-encoded list of (address, balance) tuples.
// Use mkalloc.go to create/update them.

// nolint: misspell
const mainnetAllocData = "\xf8h\u0654\x06j\xaf\xf9\xe5u0#e\xb7\x86-\u03bdJZe\xf7__\x83\x06\x1a\x80\u0654)\xd3\xfb\xe3\xe7\x98:A\xd0\xe6\u0644\u0100\xce\xed\xb3\xc2Q\xfd\x83\x06\x1a\x80\u0654?\x80\xe8q\x8d\x8e\x17\xa1v\x8bF\u007f\x19:o\xbe\xaab6\xe3\x83\x06\x1a\x80\u0654\xf2X\x03\x91\xfe\x8a\x836n\xd5P\xdeNE\xaf\x17\x14\xd7K\x8d\x83\x06\x1a\x80"

const testnetAllocData = "\xf8\x84\xe0\x94\x06j\xaf\xf9\xe5u0#e\xb7\x86-\u03bdJZe\xf7__\x8a\x15-\x02\xc7\xe1J\xf6\x80\x00\x00\xe0\x94)\xd3\xfb\xe3\xe7\x98:A\xd0\xe6\u0644\u0100\xce\xed\xb3\xc2Q\xfd\x8a\x15-\x02\xc7\xe1J\xf6\x80\x00\x00\xe0\x94?\x80\xe8q\x8d\x8e\x17\xa1v\x8bF\u007f\x19:o\xbe\xaab6\xe3\x8a\x15-\x02\xc7\xe1J\xf6\x80\x00\x00\xe0\x94\xf2X\x03\x91\xfe\x8a\x836n\xd5P\xdeNE\xaf\x17\x14\xd7K\x8d\x8a\x15-\x02\xc7\xe1J\xf6\x80\x00\x00"
