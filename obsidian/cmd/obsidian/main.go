// Copyright 2024 The Obsidian Authors
// This file is part of Obsidian.

// obsidian is the official command-line client for Obsidian.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/ethereum/go-ethereum/core"
	"github.com/urfave/cli/v2"

	obsparams "github.com/obsidian-chain/obsidian/params"
	"github.com/obsidian-chain/obsidian/stealth"
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	gitDate   = ""
)

func main() {
	app := &cli.App{
		Name:                 "obsidian",
		Usage:                "the Obsidian command line interface",
		Version:              obsparams.VersionWithMeta,
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			initCommand,
			versionCommand,
			stealthCommand,
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// initCommand initializes a new genesis block
var initCommand = &cli.Command{
	Name:      "init",
	Usage:     "Bootstrap and initialize a new genesis block",
	ArgsUsage: "<genesisPath>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "datadir",
			Usage: "Data directory for the databases",
			Value: "./obsidian-data",
		},
	},
	Action: func(ctx *cli.Context) error {
		genesisPath := ctx.Args().First()
		if genesisPath == "" {
			return fmt.Errorf("must supply path to genesis JSON file")
		}

		file, err := os.Open(genesisPath)
		if err != nil {
			return fmt.Errorf("failed to read genesis file: %v", err)
		}
		defer file.Close()

		genesis := new(core.Genesis)
		if err := json.NewDecoder(file).Decode(genesis); err != nil {
			return fmt.Errorf("invalid genesis file: %v", err)
		}

		fmt.Println("Genesis configuration loaded successfully")
		fmt.Printf("Chain ID: %d\n", genesis.Config.ChainID)
		fmt.Printf("Gas Limit: %d\n", genesis.GasLimit)
		fmt.Printf("Difficulty: %s\n", genesis.Difficulty.String())

		return nil
	},
}

// versionCommand prints version information
var versionCommand = &cli.Command{
	Name:  "version",
	Usage: "Print version numbers",
	Action: func(ctx *cli.Context) error {
		fmt.Println("Obsidian")
		fmt.Println("Version:", obsparams.VersionWithMeta)
		if gitCommit != "" {
			fmt.Println("Git Commit:", gitCommit)
		}
		if gitDate != "" {
			fmt.Println("Git Commit Date:", gitDate)
		}
		fmt.Println("Architecture:", runtime.GOARCH)
		fmt.Println("Go Version:", runtime.Version())
		fmt.Println("Operating System:", runtime.GOOS)
		return nil
	},
}

// stealthCommand manages stealth addresses
var stealthCommand = &cli.Command{
	Name:  "stealth",
	Usage: "Manage stealth addresses",
	Subcommands: []*cli.Command{
		{
			Name:   "generate",
			Usage:  "Generate a new stealth key pair",
			Action: stealthGenerate,
		},
		{
			Name:      "address",
			Usage:     "Generate a stealth address for a recipient",
			ArgsUsage: "<meta-address>",
			Action:    stealthAddress,
		},
	},
}

// stealthGenerate generates a new stealth key pair
func stealthGenerate(ctx *cli.Context) error {
	keyPair, err := stealth.GenerateStealthKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate stealth key pair: %v", err)
	}

	metaAddr := keyPair.MetaAddress()

	fmt.Println("=== Stealth Key Pair Generated ===")
	fmt.Println()
	fmt.Println("KEEP THESE PRIVATE KEYS SECURE!")
	fmt.Println()
	fmt.Printf("Spend Private Key: %s\n", hex.EncodeToString(keyPair.SpendPrivateKey.D.Bytes()))
	fmt.Printf("View Private Key:  %s\n", hex.EncodeToString(keyPair.ViewPrivateKey.D.Bytes()))
	fmt.Println()
	fmt.Println("=== Public Meta-Address (share this) ===")
	fmt.Println()
	fmt.Printf("Meta-Address: %s\n", metaAddr.String())
	fmt.Println()
	fmt.Printf("Spend Public Key: %s\n", hex.EncodeToString(metaAddr.SpendPubKey))
	fmt.Printf("View Public Key:  %s\n", hex.EncodeToString(metaAddr.ViewPubKey))

	return nil
}

// stealthAddress generates a one-time stealth address
func stealthAddress(ctx *cli.Context) error {
	metaAddrStr := ctx.Args().First()
	if metaAddrStr == "" {
		return fmt.Errorf("must provide a meta-address")
	}

	metaAddr, err := stealth.ParseMetaAddress(metaAddrStr)
	if err != nil {
		return fmt.Errorf("invalid meta-address: %v", err)
	}

	stealthAddr, err := stealth.GenerateStealthAddress(metaAddr)
	if err != nil {
		return fmt.Errorf("failed to generate stealth address: %v", err)
	}

	fmt.Println("=== Stealth Address Generated ===")
	fmt.Println()
	fmt.Printf("Stealth Address:    %s\n", stealthAddr.Address.Hex())
	fmt.Printf("Ephemeral Pub Key:  %s\n", hex.EncodeToString(stealthAddr.EphemeralPubKey))
	fmt.Printf("View Tag:           0x%02x\n", stealthAddr.ViewTag)
	fmt.Println()
	fmt.Println("Send funds to the Stealth Address.")
	fmt.Println("Include the Ephemeral Pub Key in the transaction data.")

	return nil
}
