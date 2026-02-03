// Copyright 2024 The Obsidian Authors
// This file is part of Obsidian.

// obsidian is the official command-line client for Obsidian.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	ethrpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/urfave/cli/v2"

	"github.com/obsidian-chain/obsidian/eth/backend"
	"github.com/obsidian-chain/obsidian/node"
	obsp2p "github.com/obsidian-chain/obsidian/p2p"
	obsparams "github.com/obsidian-chain/obsidian/params"
	obsrpc "github.com/obsidian-chain/obsidian/rpc"
	"github.com/obsidian-chain/obsidian/stealth"
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	gitDate   = ""
)

// Flags
var (
	dataDirFlag = &cli.StringFlag{
		Name:    "datadir",
		Usage:   "Data directory for the databases and keystore",
		Value:   node.DefaultDataDir(),
		EnvVars: []string{"OBSIDIAN_DATADIR"},
	}
	httpEnabledFlag = &cli.BoolFlag{
		Name:  "http",
		Usage: "Enable the HTTP-RPC server",
		Value: true,
	}
	httpHostFlag = &cli.StringFlag{
		Name:  "http.addr",
		Usage: "HTTP-RPC server listening interface",
		Value: "localhost",
	}
	httpPortFlag = &cli.IntFlag{
		Name:  "http.port",
		Usage: "HTTP-RPC server listening port",
		Value: 8545,
	}
	httpCorsFlag = &cli.StringFlag{
		Name:  "http.corsdomain",
		Usage: "Comma separated list of domains from which to accept cross origin requests",
		Value: "*",
	}
	httpApiFlag = &cli.StringFlag{
		Name:  "http.api",
		Usage: "APIs offered over the HTTP-RPC interface",
		Value: "eth,net,web3,obs,miner",
	}
	wsEnabledFlag = &cli.BoolFlag{
		Name:  "ws",
		Usage: "Enable the WS-RPC server",
		Value: false,
	}
	wsHostFlag = &cli.StringFlag{
		Name:  "ws.addr",
		Usage: "WS-RPC server listening interface",
		Value: "localhost",
	}
	wsPortFlag = &cli.IntFlag{
		Name:  "ws.port",
		Usage: "WS-RPC server listening port",
		Value: 8546,
	}
	minerEnabledFlag = &cli.BoolFlag{
		Name:  "mine",
		Usage: "Enable mining",
		Value: false,
	}
	minerCoinbaseFlag = &cli.StringFlag{
		Name:  "miner.etherbase",
		Usage: "Public address for block mining rewards",
	}
	p2pPortFlag = &cli.IntFlag{
		Name:  "port",
		Usage: "Network listening port",
		Value: 8333,
	}
	maxPeersFlag = &cli.IntFlag{
		Name:  "maxpeers",
		Usage: "Maximum number of network peers",
		Value: 50,
	}
	networkIdFlag = &cli.Uint64Flag{
		Name:  "networkid",
		Usage: "Network identifier",
		Value: obsparams.ObsidianMainnetNetworkID,
	}
	logLevelFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail",
		Value: 3,
	}
	bootnodesFlag = &cli.StringFlag{
		Name:  "bootnodes",
		Usage: "Comma separated enode URLs for P2P discovery bootstrap",
		Value: "140.238.7.194:8333,217.142.151.122:8333,157.151.219.199:8333,129.154.52.54:8333,152.69.229.203:8333",
	}
	noDiscoverFlag = &cli.BoolFlag{
		Name:  "nodiscover",
		Usage: "Disables the peer discovery mechanism",
		Value: false,
	}
)

func main() {
	app := &cli.App{
		Name:                 "obsidian",
		Usage:                "the Obsidian command line interface",
		Version:              obsparams.VersionWithMeta,
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			runCommand,
			initCommand,
			versionCommand,
			stealthCommand,
			accountCommand,
			consoleCommand,
			healthCommand,
			metricsCommand,
			backupCommand,
			nodeCommand,
		},
		Flags: []cli.Flag{
			dataDirFlag,
			logLevelFlag,
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runCommand starts the Obsidian node
var runCommand = &cli.Command{
	Name:  "run",
	Usage: "Start the Obsidian node",
	Flags: []cli.Flag{
		dataDirFlag,
		httpEnabledFlag,
		httpHostFlag,
		httpPortFlag,
		httpCorsFlag,
		httpApiFlag,
		wsEnabledFlag,
		wsHostFlag,
		wsPortFlag,
		minerEnabledFlag,
		minerCoinbaseFlag,
		p2pPortFlag,
		maxPeersFlag,
		networkIdFlag,
		logLevelFlag,
		bootnodesFlag,
		noDiscoverFlag,
	},
	Action: runNode,
}

func runNode(ctx *cli.Context) error {
	// Setup logging
	logLevel := log.FromLegacyLevel(ctx.Int(logLevelFlag.Name))
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, logLevel, true)))

	log.Info("Starting Obsidian node",
		"version", obsparams.VersionWithMeta,
		"chainId", obsparams.ObsidianMainnetNetworkID,
	)

	// Parse seed nodes
	seedNodes := strings.Split(ctx.String(bootnodesFlag.Name), ",")
	for i := range seedNodes {
		seedNodes[i] = strings.TrimSpace(seedNodes[i])
	}
	log.Info("Seed nodes configured", "nodes", seedNodes)

	// Create node config
	nodeConfig := node.DefaultConfig()
	nodeConfig.DataDir = ctx.String(dataDirFlag.Name)
	nodeConfig.HTTPHost = ctx.String(httpHostFlag.Name)
	nodeConfig.HTTPPort = ctx.Int(httpPortFlag.Name)
	nodeConfig.HTTPModules = []string{"eth", "net", "web3", "obs", "miner"}
	nodeConfig.WSHost = ctx.String(wsHostFlag.Name)
	nodeConfig.WSPort = ctx.Int(wsPortFlag.Name)
	nodeConfig.P2P.MaxPeers = ctx.Int(maxPeersFlag.Name)
	nodeConfig.P2P.ListenAddr = fmt.Sprintf(":%d", ctx.Int(p2pPortFlag.Name))
	nodeConfig.P2P.NoDiscovery = ctx.Bool(noDiscoverFlag.Name)

	// Create node
	n, err := node.New(&nodeConfig)
	if err != nil {
		return fmt.Errorf("failed to create node: %v", err)
	}

	// Create backend
	backendConfig := backend.DefaultConfig()
	b, err := backend.New(backendConfig)
	if err != nil {
		return fmt.Errorf("failed to create backend: %v", err)
	}

	// Create P2P handler for block broadcasting
	p2pHandler := obsp2p.NewHandler(
		obsparams.ObsidianMainnetNetworkID,
		b, // Pass backend as P2P backend interface
	)

	// Register P2P protocol with node
	nodeConfig.P2P.Protocols = append(nodeConfig.P2P.Protocols, p2pHandler.Protocol())

	// Set P2P handler in backend for broadcasting
	b.SetP2PHandler(p2pHandler)

	// Register RPC APIs
	apis := obsrpc.GetAPIs(b)
	rpcAPIs := make([]ethrpc.API, len(apis))
	for i, api := range apis {
		rpcAPIs[i] = ethrpc.API{
			Namespace: api.Namespace,
			Service:   api.Service,
		}
	}
	n.RegisterAPIs(rpcAPIs)

	// Start node
	if err := n.Start(); err != nil {
		return fmt.Errorf("failed to start node: %v", err)
	}

	// Start mining if enabled
	if ctx.Bool(minerEnabledFlag.Name) {
		log.Info("Starting miner (with delay to ensure P2P connectivity)")
		go func() {
			// Wait for peer discovery and connections
			time.Sleep(5 * time.Second)
			if err := b.StartMining(); err != nil {
				log.Error("Failed to start miner", "error", err)
			}
		}()
	}

	log.Info("Obsidian node started successfully",
		"http", fmt.Sprintf("http://%s:%d", nodeConfig.HTTPHost, nodeConfig.HTTPPort),
		"datadir", nodeConfig.DataDir,
	)

	// Connect to seed nodes in background
	go connectToSeedNodes(seedNodes)

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")
	if err := n.Stop(); err != nil {
		log.Error("Error stopping node", "error", err)
	}

	return nil
}

// initCommand initializes a new genesis block
var initCommand = &cli.Command{
	Name:      "init",
	Usage:     "Bootstrap and initialize a new genesis block",
	ArgsUsage: "<genesisPath>",
	Flags: []cli.Flag{
		dataDirFlag,
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
		fmt.Printf("Chain ID: %d (0x%x)\n", obsparams.ObsidianMainnetNetworkID, obsparams.ObsidianMainnetNetworkID)
		fmt.Printf("Block Time: %s\n", obsparams.BlockTime)
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
		{
			Name:      "scan",
			Usage:     "Scan for payments to your stealth addresses",
			ArgsUsage: "<view-private-key>",
			Action:    stealthScan,
		},
	},
}

// accountCommand manages accounts
var accountCommand = &cli.Command{
	Name:  "account",
	Usage: "Manage accounts",
	Subcommands: []*cli.Command{
		{
			Name:   "new",
			Usage:  "Create a new account",
			Action: accountNew,
		},
		{
			Name:   "list",
			Usage:  "List all accounts",
			Action: accountList,
		},
	},
}

// consoleCommand attaches to a running node
var consoleCommand = &cli.Command{
	Name:  "console",
	Usage: "Start an interactive JavaScript console (attach to running node)",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "attach",
			Usage: "Endpoint to attach to",
			Value: "http://localhost:8545",
		},
	},
	Action: func(ctx *cli.Context) error {
		endpoint := ctx.String("attach")
		fmt.Printf("Connecting to %s...\n", endpoint)

		client, err := ethrpc.Dial(endpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to node: %v", err)
		}
		defer client.Close()

		// Get chain ID to verify connection
		var chainId string
		if err := client.Call(&chainId, "eth_chainId"); err != nil {
			return fmt.Errorf("failed to get chain ID: %v", err)
		}

		fmt.Println("Connected successfully!")
		fmt.Printf("Chain ID: %s\n", chainId)
		fmt.Println("\nAvailable RPC methods:")
		fmt.Println("  eth_* - Ethereum compatible methods")
		fmt.Println("  obs_* - Obsidian specific methods")
		fmt.Println("  net_* - Network methods")
		fmt.Println("  web3_* - Web3 methods")
		fmt.Println("\nExample: curl -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"obs_getNetworkInfo\",\"params\":[],\"id\":1}' " + endpoint)

		return nil
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

// stealthScan scans for stealth payments
func stealthScan(ctx *cli.Context) error {
	viewKey := ctx.Args().First()
	if viewKey == "" {
		return fmt.Errorf("must provide view private key")
	}
	fmt.Println("Scanning for stealth payments...")
	fmt.Println("(This feature requires a running node with indexed transactions)")
	return nil
}

// accountNew creates a new account
func accountNew(ctx *cli.Context) error {
	keyPair, err := stealth.GenerateStealthKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Use spend key as the main account key
	privateKey := keyPair.SpendPrivateKey

	fmt.Println("=== New Account Created ===")
	fmt.Println()
	fmt.Printf("Address: 0x%x\n", privateKey.PublicKey.X.Bytes()[:20])
	fmt.Printf("Private Key: %s\n", hex.EncodeToString(privateKey.D.Bytes()))
	fmt.Println()
	fmt.Println("IMPORTANT: Save your private key securely!")

	return nil
}

// accountList lists all accounts
func accountList(ctx *cli.Context) error {
	dataDir := ctx.String(dataDirFlag.Name)
	fmt.Printf("Keystore directory: %s/keystore\n", dataDir)
	fmt.Println("(Account listing from keystore not yet implemented)")
	return nil
}

// healthCommand performs health checks
var healthCommand = &cli.Command{
	Name:  "health",
	Usage: "Check node health status",
	Flags: []cli.Flag{
		dataDirFlag,
	},
	Action: func(ctx *cli.Context) error {
		cfg := &CLIConfig{
			DataDir: ctx.String(dataDirFlag.Name),
		}
		return HealthCheck(cfg)
	},
}

// metricsCommand displays metrics
var metricsCommand = &cli.Command{
	Name:  "metrics",
	Usage: "Display node metrics",
	Flags: []cli.Flag{
		dataDirFlag,
	},
	Action: func(ctx *cli.Context) error {
		cfg := &CLIConfig{
			DataDir: ctx.String(dataDirFlag.Name),
		}
		return ShowMetrics(cfg)
	},
}

// backupCommand manages backups
var backupCommand = &cli.Command{
	Name:  "backup",
	Usage: "Manage database backups",
	Subcommands: []*cli.Command{
		{
			Name:      "create",
			Usage:     "Create a database backup",
			ArgsUsage: "[backup-name]",
			Flags: []cli.Flag{
				dataDirFlag,
			},
			Action: func(ctx *cli.Context) error {
				backupName := ctx.Args().First()
				if backupName == "" {
					backupName = fmt.Sprintf("backup-%d", time.Now().Unix())
				}
				cfg := &CLIConfig{
					DataDir: ctx.String(dataDirFlag.Name),
				}
				return CreateBackup(cfg, backupName)
			},
		},
		{
			Name:  "list",
			Usage: "List available backups",
			Flags: []cli.Flag{
				dataDirFlag,
			},
			Action: func(ctx *cli.Context) error {
				cfg := &CLIConfig{
					DataDir: ctx.String(dataDirFlag.Name),
				}
				return ListBackups(cfg)
			},
		},
	},
}

// nodeCommand shows node information
var nodeCommand = &cli.Command{
	Name:  "node",
	Usage: "Show node information",
	Flags: []cli.Flag{
		dataDirFlag,
		httpHostFlag,
		httpPortFlag,
		wsHostFlag,
		wsPortFlag,
		minerEnabledFlag,
		logLevelFlag,
	},
	Action: func(ctx *cli.Context) error {
		cfg := &CLIConfig{
			DataDir:  ctx.String(dataDirFlag.Name),
			HTTPAddr: ctx.String(httpHostFlag.Name),
			HTTPPort: ctx.Int(httpPortFlag.Name),
			WSAddr:   ctx.String(wsHostFlag.Name),
			WSPort:   ctx.Int(wsPortFlag.Name),
			Mining:   ctx.Bool(minerEnabledFlag.Name),
			LogLevel: fmt.Sprintf("%d", ctx.Int(logLevelFlag.Name)),
		}
		return ShowNodeInfo(cfg)
	},
}

// connectToSeedNodes attempts to connect to seed nodes
func connectToSeedNodes(seedNodes []string) {
	log.Info("Connecting to seed nodes...", "count", len(seedNodes))

	for _, addr := range seedNodes {
		if addr == "" {
			continue
		}

		go func(nodeAddr string) {
			// Retry connection with backoff
			for i := 0; i < 3; i++ {
				conn, err := net.DialTimeout("tcp", nodeAddr, 10*time.Second)
				if err != nil {
					log.Debug("Failed to connect to seed node", "addr", nodeAddr, "attempt", i+1, "error", err)
					time.Sleep(time.Duration(i+1) * 5 * time.Second)
					continue
				}
				conn.Close()
				log.Info("Successfully connected to seed node", "addr", nodeAddr)
				return
			}
			log.Warn("Could not connect to seed node after retries", "addr", nodeAddr)
		}(addr)
	}
}
