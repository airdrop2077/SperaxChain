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
	"math/big"
	"strings"

	"github.com/Sperax/SperaxChain/accounts/keystore"
	"github.com/Sperax/SperaxChain/cmd/utils"
	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/common/hexutil"
	"github.com/Sperax/SperaxChain/consensus/bdls_engine/committee"
	"github.com/Sperax/SperaxChain/console"
	"github.com/Sperax/SperaxChain/core"
	"github.com/Sperax/SperaxChain/core/types"
	"github.com/Sperax/SperaxChain/params"
	"github.com/Sperax/SperaxChain/rlp"
	"github.com/Sperax/SperaxChain/rpc"
	"gopkg.in/urfave/cli.v1"
)

const (
	MainnetRPC        = "http://api.sperax.io:8545"
	MainnetTxExplorer = "http://explorer.sperax.io/tx/"

	TestnetRPC        = "http://api.testnet.sperax.io:8545"
	TestnetTxExplorer = "http://explorer.testnet.sperax.io/tx/"
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
					utils.SperaxStakeAmountFlag,
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
					utils.SperaxStakeAccountFlag,
				},
				Description: `
Generate data.payload to redeem SPA via eth.sendTransaction()`,
			},
		},
	}
)

func delegate(ctx *cli.Context) error {
	node := makeFullNode(ctx)
	defer node.Close()

	ks := node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	passwords := utils.MakePasswordList(ctx)
	accountStr := strings.TrimSpace(ctx.GlobalString(utils.SperaxStakeAccountFlag.Name))

	account, err := utils.MakeAddress(ks, accountStr)
	if err != nil {
		utils.Fatalf("account address invalid:%v err:%v ", account, err)
	}

	account, password := unlockAccount(ks, accountStr, 0, passwords)

	for _, wallet := range ks.Wallets() {
		priv, err := wallet.GetPrivateKey(account)
		if err != nil {
			continue
		}

		// derive random seed from private key
		req := committee.StakingRequest{
			StakingOp:   committee.Staking,
			StakingFrom: uint64(ctx.GlobalInt(utils.SperaxStakeFromFlag.Name)),
			StakingTo:   uint64(ctx.GlobalInt(utils.SperaxStakeToFlag.Name)),
		}

		seed := committee.DeriveStakingSeed(priv, req.StakingFrom)
		req.StakingHash = common.BytesToHash(committee.HashChain(seed, req.StakingFrom, req.StakingTo))

		bts, err := rlp.EncodeToBytes(req)
		if err != nil {
			utils.Fatalf("internal error:%v ", err)
		}

		// api route
		// currently we have testnet & mainnet
		apiURL := MainnetRPC
		txURL := MainnetTxExplorer
		switch {
		case ctx.GlobalBool(utils.TestnetFlag.Name):
			apiURL = TestnetRPC
			txURL = TestnetTxExplorer
		default:
		}

		// connect to official RPC server
		client, err := rpc.Dial(apiURL)
		if err != nil {
			return err
		}
		defer client.Close()

		// get nonce from RPC
		var result string
		err = client.Call(&result, "eth_getTransactionCount", account.Address, "latest")
		if err != nil {
			return err
		}

		count, ok := big.NewInt(0).SetString(result, 0)
		if !ok {
			return errors.New("illegal result for eth_getTransactionCount")
		}

		// get gasPrice form RPC
		err = client.Call(&result, "eth_gasPrice")
		if err != nil {
			return err
		}
		gasPrice, ok := big.NewInt(0).SetString(result, 0)

		amount := big.NewInt(ctx.GlobalInt64(utils.SperaxStakeAmountFlag.Name))
		amount.Mul(amount, big.NewInt(params.Ether))

		// get gas limit
		gasLimit, err := core.IntrinsicGas(bts, false, true, false)

		// create transaction
		tx := types.NewTransaction(
			count.Uint64(),
			committee.StakingAddress, // staking address
			amount,
			gasLimit,
			gasPrice,
			bts,
		)

		// sign transaction
		tx, err = ks.SignTxWithPassphrase(account, password, tx, params.TestnetChainConfig.ChainID)
		if err != nil {
			return err
		}

		// encode to raw
		enc, err := rlp.EncodeToBytes(tx)
		if err != nil {
			return err
		}
		rawTx := hexutil.Encode(enc)

		fmt.Println("FROM BLOCK#:", req.StakingFrom)
		fmt.Println("TO BLOCK#:", req.StakingTo)
		fmt.Println("NONCE:", tx.Nonce())
		fmt.Println("AMOUNT:", amount)
		fmt.Println("GAS LIMIT:", gasLimit)
		fmt.Println("GAS PRICE:", gasPrice)
		fmt.Println("DATA:", common.Bytes2Hex(bts))
		ok, err = console.Stdin.PromptConfirm("SEND DELEGATE REQUEST WITH THESE PARAMETERS?")
		if ok {
			err = client.Call(&result, "eth_sendRawTransaction", rawTx)
			if err != nil {
				return err
			}

			fmt.Printf("Check transaction: %v%s\n", txURL, result)
		}

		return nil
	}

	return errors.New("Failed to unlock private key")
}

func redeem(ctx *cli.Context) error {
	fmt.Println("REDEEM PARAMETERS GENERATION")

	req := committee.StakingRequest{
		StakingOp: committee.Redeem,
	}

	bts, err := rlp.EncodeToBytes(req)
	if err != nil {
		utils.Fatalf("internal error:%v ", err)
	}

	node := makeFullNode(ctx)
	defer node.Close()

	ks := node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	passwords := utils.MakePasswordList(ctx)
	accountStr := strings.TrimSpace(ctx.GlobalString(utils.SperaxStakeAccountFlag.Name))

	account, err := utils.MakeAddress(ks, accountStr)
	if err != nil {
		utils.Fatalf("account address invalid:%v err:%v ", account, err)
	}

	account, password := unlockAccount(ks, accountStr, 0, passwords)

	// api route
	// currently we have testnet & mainnet
	apiURL := MainnetRPC
	txURL := MainnetTxExplorer
	switch {
	case ctx.GlobalBool(utils.TestnetFlag.Name):
		apiURL = TestnetRPC
		txURL = TestnetTxExplorer
	default:
	}

	// connect to official RPC server
	client, err := rpc.Dial(apiURL)
	if err != nil {
		return err
	}
	defer client.Close()

	// get nonce from RPC
	var result string
	err = client.Call(&result, "eth_getTransactionCount", account.Address, "latest")
	if err != nil {
		return err
	}

	count, ok := big.NewInt(0).SetString(result, 0)
	if !ok {
		return errors.New("illegal result for eth_getTransactionCount")
	}

	// get gasPrice form RPC
	err = client.Call(&result, "eth_gasPrice")
	if err != nil {
		return err
	}
	gasPrice, ok := big.NewInt(0).SetString(result, 0)

	// get gas limit
	gasLimit, err := core.IntrinsicGas(bts, false, true, false)

	// create transaction
	tx := types.NewTransaction(
		count.Uint64(),
		committee.StakingAddress, // staking address
		common.Big0,
		gasLimit,
		gasPrice,
		bts,
	)

	// sign transaction
	tx, err = ks.SignTxWithPassphrase(account, password, tx, params.TestnetChainConfig.ChainID)
	if err != nil {
		return err
	}

	// encode to raw
	enc, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	rawTx := hexutil.Encode(enc)

	fmt.Println("NONCE:", tx.Nonce())
	fmt.Println("GAS LIMIT:", gasLimit)
	fmt.Println("GAS PRICE:", gasPrice)
	fmt.Println("DATA:", common.Bytes2Hex(bts))

	ok, err = console.Stdin.PromptConfirm("SEND REDEEM REQUEST WITH THESE PARAMETERS?")
	if ok {
		err = client.Call(&result, "eth_sendRawTransaction", rawTx)
		if err != nil {
			return err
		}

		fmt.Printf("Check transaction: %v%s\n", txURL, result)
	}
	return nil
}
