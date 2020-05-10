//go:generate go run assets_generate.go
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	tmflags "github.com/tendermint/tendermint/libs/cli/flags"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	nm "github.com/tendermint/tendermint/node"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/proxy"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

func retrieveDefaultConfig() (interface{}, error) {
	file, err := Resources.Open("default_config.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(bufio.NewReader(file))
	var result interface{}
	err = decoder.Decode(&result)
	return result, err
}

// DefaultConfig represents the default configuration when none is available
var DefaultConfig interface{}

func doInit(config *cfg.Config, logger tmlog.Logger) error {
	// private validator
	privValKeyFile := config.PrivValidatorKeyFile()
	privValStateFile := config.PrivValidatorStateFile()

	if err := tmos.EnsureDir(filepath.Dir(privValKeyFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}
	if err := tmos.EnsureDir(filepath.Dir(privValStateFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}

	var pv *privval.FilePV
	if tmos.FileExists(privValKeyFile) {
		pv = privval.LoadFilePV(privValKeyFile, privValStateFile)
		logger.Info("Found private validator", "keyFile", privValKeyFile, "stateFile", privValStateFile)
	} else {
		pv = privval.GenFilePV(privValKeyFile, privValStateFile)
		pv.Save()
		logger.Info("Generated private validator", "keyFile", privValKeyFile, "stateFile", privValStateFile)
	}

	nodeKeyFile := config.NodeKeyFile()
	if err := tmos.EnsureDir(filepath.Dir(nodeKeyFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}
	if tmos.FileExists(nodeKeyFile) {
		logger.Info("Found node key", "path", nodeKeyFile)
	} else {
		if _, err := p2p.LoadOrGenNodeKey(nodeKeyFile); err != nil {
			return errors.Wrap(err, "failed to generate node key")
		}
		logger.Info("Generated node key", "path", nodeKeyFile)
	}

	// genesis file
	genFile := config.GenesisFile()
	if err := tmos.EnsureDir(filepath.Dir(genFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}
	if tmos.FileExists(genFile) {
		logger.Info("Found genesis file", "path", genFile)
	} else {
		genDoc := types.GenesisDoc{
			ChainID:         fmt.Sprintf("athenamesh-%v", tmrand.Str(6)),
			GenesisTime:     tmtime.Now(),
			ConsensusParams: types.DefaultConsensusParams(),
		}
		key := pv.GetPubKey()
		genDoc.Validators = []types.GenesisValidator{{
			Address: key.Address(),
			PubKey:  key,
			Power:   10,
		}}

		if err := genDoc.SaveAs(genFile); err != nil {
			return errors.Wrap(err, "failed to create genesis file")
		}
		logger.Info("Generated genesis file", "path", genFile)
	}

	configFile := filepath.Join(filepath.Dir(nodeKeyFile), "config.toml")
	if !tmos.FileExists(configFile) {
		cfg.WriteConfigFile(configFile, config)
		logger.Info("Generated config file", "path", configFile)
	}

	log.Print("")
	log.Print("Initial configuration constructed.")
	log.Printf("Examine the configuration files in %s to customize the behavior of the chain", filepath.Dir(nodeKeyFile))
	log.Print("Execute athenamesh in either \"once\" or \"node\" to initialize the new chain")
	return nil
}

func instantiateApp(app abci.Application, config *cfg.Config, configFile string, logger tmlog.Logger) (tmlog.Logger, *nm.Node, error) {
	// read config
	config.RootDir = filepath.Dir(filepath.Dir(configFile))
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		return nil, nil, errors.Wrap(err, "viper failed to read config file")
	}
	if err := viper.Unmarshal(config); err != nil {
		return nil, nil, errors.Wrap(err, "viper failed to unmarshal config")
	}
	if err := config.ValidateBasic(); err != nil {
		return nil, nil, errors.Wrap(err, "config is invalid")
	}

	// create logger
	var err error
	logger, err = tmflags.ParseLogLevel(config.LogLevel, logger, cfg.DefaultLogLevel())
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse log level")
	}

	// read private validator
	pv := privval.LoadFilePV(
		config.PrivValidatorKeyFile(),
		config.PrivValidatorStateFile(),
	)

	// read node key
	nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load node's key")
	}

	// create node
	node, err := nm.NewNode(
		config,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(app),
		nm.DefaultGenesisDocProviderFunc(config),
		nm.DefaultDBProvider,
		nm.DefaultMetricsProvider(config.Instrumentation),
		logger)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create new Tendermint node")
	}

	return logger, node, nil
}

func doNode(config *cfg.Config, logger tmlog.Logger, doOnce bool) error {
	dbPath := filepath.Join(filepath.Dir(config.PrivValidatorStateFile()), "store.db")
	dbopt := badger.DefaultOptions(dbPath)
	badgerLogger := newBadgerLogger(logger)
	dbopt.Logger = badgerLogger
	if strings.HasPrefix(runtime.GOOS, "windows") {
		dbopt = dbopt.WithTruncate(true)
	}
	db, err := badger.Open(dbopt)
	if err != nil {
		return errors.Wrap(err, "failed to open badger db")
	}
	defer db.Close()
	app := NewAthenaStoreApplication(db, logger)

	flag.Parse()

	configFile := filepath.Join(filepath.Dir(config.NodeKeyFile()), "config.toml")
	logger, node, err := instantiateApp(app, config, configFile, logger)
	if err != nil {
		return err
	}

	// the logger returned from instantiateApp has the configured log levels and filters applied to it,
	// apply to everything else that uses a logger object
	app.logger = logger
	badgerLogger.logger = logger

	if doOnce {
		firstCycleComplete = make(chan struct{}, 1)
	}

	node.Start()
	defer func() {
		node.Stop()
		node.Wait()
	}()

	if doOnce {
		<-firstCycleComplete
	} else {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
	}
	return nil
}

func rootErrors(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v", err.Error())
		os.Exit(1)
	}
}

func main() {
	config := cfg.DefaultConfig()
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout))
	//rootErrors(doNode(config, logger))
	//return

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "init":
			rootErrors(doInit(config, logger))
			return
		case "node":
			rootErrors(doNode(config, logger, false))
			return
		case "once":
			rootErrors(doNode(config, logger, true))
			return
		}
	}
	log.Print("athenamesh.exe <command>")
	log.Print("  init - create a new (empty) database.  This will create a new \"universe\"")
	log.Print("  once - operate a node for one cycle only (useful when creating a new \"universe\")")
	log.Print("  node - operate a node")
}
