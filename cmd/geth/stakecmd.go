// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Sperax/SperaxChain/accounts/keystore"
	"github.com/Sperax/SperaxChain/cmd/utils"
	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/consensus/bdls_engine/committee"
	"github.com/Sperax/SperaxChain/rlp"
	"gopkg.in/urfave/cli.v1"
)

var (
	stakeCommand = cli.Command{
		Name:      "stake",
		Usage:     "staking payload generation",
		ArgsUsage: "",
		Category:  "STAKE COMMANDS",
		Description: `
		Generate staking payload to send with transaction to delegate or redeem.`,
		Subcommands: []cli.Command{
			{
				Name:   "delegate",
				Usage:  "generate data to delegate SPA",
				Action: utils.MigrateFlags(delegate),
				Flags: []cli.Flag{
					utils.SperaxStakeFromFlag,
					utils.SperaxStakeToFlag,
					utils.SperaxStakeAccountFlag,
				},
				Description: `
Generate data.payload to delegate SPA via eth.sendTransaction()`,
			},
			{
				Name:   "redeem",
				Usage:  "generate data to redeem SPA",
				Action: utils.MigrateFlags(redeem),
				Flags: []cli.Flag{
					utils.SperaxStakeFromFlag,
					utils.SperaxStakeToFlag,
					utils.SperaxStakeAccountFlag,
				},
				Description: `
Generate data.payload to redeem SPA via eth.sendTransaction()`,
			},
		},
	}
)

func delegate(ctx *cli.Context) error {
	fmt.Println("STAKEING PARAMETERS GENERATION")
	req, err := stake(ctx, committee.Staking)
	if err != nil {
		utils.Fatalf("delgated failed. err: %v", err)
	}

	fmt.Println("FROM:", req.StakingFrom)
	fmt.Println("TO:", req.StakingTo)

	bts, err := rlp.EncodeToBytes(req)
	if err != nil {
		utils.Fatalf("internal error:%v ", err)
	}
	fmt.Printf("STAKING PAYLOAD, use with eth.sendTransaction() by setting data.payload=0x%v\n", common.Bytes2Hex(bts))
	return nil
}

func redeem(ctx *cli.Context) error {
	fmt.Println("REDEEM PARAMETERS GENERATION")
	req, err := stake(ctx, committee.Redeem)
	if err != nil {
		utils.Fatalf("redeem failed. err: %v", err)
	}

	bts, err := rlp.EncodeToBytes(req)
	if err != nil {
		utils.Fatalf("internal error:%v ", err)
	}

	fmt.Printf("REDEEM PAYLOAD, use with eth.sendTransaction() by setting data.payload=0x%v\n", common.Bytes2Hex(bts))
	return nil
}

func stake(ctx *cli.Context, op committee.StakingOp) (req *committee.StakingRequest, err error) {
	node := makeFullNode(ctx)
	defer node.Close()

	ks := node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	passwords := utils.MakePasswordList(ctx)
	accountStr := strings.TrimSpace(ctx.GlobalString(utils.SperaxStakeAccountFlag.Name))

	account, err := utils.MakeAddress(ks, accountStr)
	if err != nil {
		utils.Fatalf("account address invalid:%v err:%v ", account, err)
	}

	unlockAccount(ks, accountStr, 0, passwords)

	for _, wallet := range ks.Wallets() {
		priv, err := wallet.GetPrivateKey(account)
		if err != nil {
			continue
		}

		// derive random seed from private key
		req := committee.StakingRequest{
			StakingOp:   op,
			StakingFrom: uint64(ctx.GlobalInt(utils.SperaxStakeFromFlag.Name)),
			StakingTo:   uint64(ctx.GlobalInt(utils.SperaxStakeToFlag.Name)),
		}

		seed := committee.DeriveStakingSeed(priv, req.StakingFrom)
		req.StakingHash = common.BytesToHash(committee.HashChain(seed, req.StakingFrom, req.StakingTo))
		return &req, nil
	}

	return nil, errors.New("Failed to unlock private key")
}
