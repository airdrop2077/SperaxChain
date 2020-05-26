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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/Sperax/SperaxChain/p2p"
	"github.com/Sperax/bdls"
	libp2p_pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/minio/blake2b-simd"
	"github.com/urfave/cli/v2"
)

// A quorum set for consenus
type Quorum struct {
	Keys []*big.Int `json:"keys"` // pem formatted keys
}

func main() {
	app := &cli.App{
		Name:                 "Sperax",
		Usage:                "Sperax bootstrap",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "genkeys",
				Usage: "generate quorum to participant in consensus",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "count",
						Value: 4,
						Usage: "number of participant in quorum",
					},
					&cli.StringFlag{
						Name:  "config",
						Value: "./quorum.json",
						Usage: "output quorum file",
					},
				},
				Action: func(c *cli.Context) error {
					count := c.Int("count")
					quorum := &Quorum{}
					// generate private keys
					for i := 0; i < count; i++ {
						privateKey, err := ecdsa.GenerateKey(bdls.DefaultCurve, rand.Reader)
						if err != nil {
							return err
						}

						quorum.Keys = append(quorum.Keys, privateKey.D)
					}

					file, err := os.Create(c.String("config"))
					if err != nil {
						return err
					}
					enc := json.NewEncoder(file)
					enc.SetIndent("", "\t")
					err = enc.Encode(quorum)
					if err != nil {
						return err
					}
					file.Close()

					log.Println("generate", c.Int("count"), "keys")
					return nil
				},
			},
			{
				Name:  "run",
				Usage: "start a consensus agent",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "listen",
						Value: ":4680",
						Usage: "the client's listening port",
					},
					&cli.IntFlag{
						Name:  "id",
						Value: 0,
						Usage: "the node id, will use the n-th private key in quorum.json",
					},
					&cli.StringFlag{
						Name:  "config",
						Value: "./quorum.json",
						Usage: "the shared quorum config file",
					},
					&cli.StringFlag{
						Name:  "bootstrap",
						Value: "",
						Usage: "bootstrap node",
					},
				},
				Action: func(c *cli.Context) error {
					// open quorum config
					file, err := os.Open(c.String("config"))
					if err != nil {
						return err
					}
					defer file.Close()

					quorum := new(Quorum)
					err = json.NewDecoder(file).Decode(quorum)
					if err != nil {
						return err
					}

					id := c.Int("id")
					if id >= len(quorum.Keys) {
						return errors.New(fmt.Sprint("cannot locate private key for id:", id))
					}
					log.Println("identity:", id)

					// create configuration
					config := new(bdls.Config)
					config.Epoch = time.Now()
					config.CurrentState = make([]byte, 1024) // fake state
					config.CurrentHeight = 0
					config.StateCompare = func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) }
					config.StateValidate = func(bdls.State) bool { return true }

					for k := range quorum.Keys {
						priv := new(ecdsa.PrivateKey)
						priv.PublicKey.Curve = bdls.DefaultCurve
						priv.D = quorum.Keys[k]
						priv.PublicKey.X, priv.PublicKey.Y = bdls.DefaultCurve.ScalarBaseMult(priv.D.Bytes())
						// myself
						if id == k {
							config.PrivateKey = priv
						}

						// set validator sequence
						config.Participants = append(config.Participants, &priv.PublicKey)
					}
					// init consensus
					consensus, err := bdls.NewConsensus(config)
					if err != nil {
						panic(err)
					}
					consensus.SetLatency(200 * time.Millisecond)
					var consensusLock sync.Mutex

					h, err := p2p.NewHost(fmt.Sprint(3000+id), config.PrivateKey)
					if err != nil {
						panic(err)
					}

					/*
						if id != 0 {
							bootstrap, err := multiaddr.NewMultiaddr(c.String("bootstrap"))
							if err != nil {
								panic(err)
							}

							err = h.Connect(bootstrap)
							if err != nil {
								panic(err)
							}
						}
					*/

					// consensus peer adapter
					peer, err := p2p.NewPeer(h)
					if err != nil {
						panic(err)
					}
					consensus.Join(peer)

					// receiver
					sub, err := peer.Topic().Subscribe()
					go func(sub *libp2p_pubsub.Subscription) {
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						for {
							msg, err := sub.Next(ctx)
							if err != nil {
								log.Println(err)
								continue
							}
							consensusLock.Lock()
							consensus.ReceiveMessage(msg.Data, time.Now())
							consensusLock.Unlock()
						}
					}(sub)

					// updater
					go func() {
						for {
							consensusLock.Lock()
							consensus.Update(time.Now())
							consensusLock.Unlock()
							<-time.After(20 * time.Millisecond)
						}
					}()

					// proposer
					var currentHeight uint64
				PROPOSE:
					for {
						data := make([]byte, 1024)
						io.ReadFull(rand.Reader, data)

						consensusLock.Lock()
						consensus.Propose(data)
						consensusLock.Unlock()

						for {
							newHeight, newRound, newState := consensus.CurrentState()
							if newHeight > currentHeight {
								h := blake2b.Sum256(newState)
								log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))
								currentHeight = newHeight
								continue PROPOSE
							}
							// wait
							<-time.After(20 * time.Millisecond)
						}
					}

					return nil
				},
			},
		},

		Action: func(c *cli.Context) error {
			cli.ShowAppHelp(c)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
