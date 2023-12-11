package main

import (
	"context"
	"errors"
	"math/big"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	vault "github.com/hashicorp/vault/api"

	"github.com/rarimo/issuer-node/internal/buildinfo"
	"github.com/rarimo/issuer-node/internal/config"
	"github.com/rarimo/issuer-node/internal/core/ports"
	"github.com/rarimo/issuer-node/internal/core/services"
	"github.com/rarimo/issuer-node/internal/db"
	"github.com/rarimo/issuer-node/internal/gateways"
	"github.com/rarimo/issuer-node/internal/kms"
	"github.com/rarimo/issuer-node/internal/loader"
	"github.com/rarimo/issuer-node/internal/log"
	"github.com/rarimo/issuer-node/internal/providers"
	"github.com/rarimo/issuer-node/internal/redis"
	"github.com/rarimo/issuer-node/internal/repositories"
	"github.com/rarimo/issuer-node/pkg/blockchain/eth"
	"github.com/rarimo/issuer-node/pkg/cache"
	"github.com/rarimo/issuer-node/pkg/credentials/revocation_status"
	circuitLoaders "github.com/rarimo/issuer-node/pkg/loaders"
	"github.com/rarimo/issuer-node/pkg/pubsub"
	"github.com/rarimo/issuer-node/pkg/reverse_hash"
)

var build = buildinfo.Revision()

func main() {
	log.Info(context.Background(), "starting issuer node...", "revision", build)

	cfg, err := config.Load("")
	if err != nil {
		log.Error(context.Background(), "cannot load config", "err", err)
		panic(err)
	}

	// Context with log
	ctx, cancel := context.WithCancel(log.NewContext(context.Background(), cfg.Log.Level, cfg.Log.Mode, os.Stdout))
	defer cancel()

	if err := cfg.SanitizeAPIUI(ctx); err != nil {
		log.Error(ctx, "there are errors in the configuration that prevent server to start", "err", err)
		return
	}

	rdb, err := redis.Open(cfg.Cache.RedisUrl)
	if err != nil {
		log.Error(ctx, "cannot connect to redis", "err", err, "host", cfg.Cache.RedisUrl)
		return
	}
	ps := pubsub.NewRedis(rdb)
	ps.WithLogger(log.Error)
	cachex := cache.NewRedisCache(rdb)

	storage, err := db.NewStorage(cfg.Database.URL)
	if err != nil {
		log.Error(ctx, "cannot connect to database", "err", err)
		panic(err)
	}

	defer func(storage *db.Storage) {
		err := storage.Close()
		if err != nil {
			log.Error(ctx, "error closing database connection", "err", err)
		}
	}(storage)

	// TODO: Cache only if cfg.APIUI.SchemaCache == true
	schemaLoader := loader.NewDocumentLoader(cfg.IPFS.GatewayURL)

	var vaultCli *vault.Client
	var vaultErr error
	vaultCfg := providers.Config{
		UserPassAuthEnabled: cfg.VaultUserPassAuthEnabled,
		Address:             cfg.KeyStore.Address,
		Token:               cfg.KeyStore.Token,
		Pass:                cfg.VaultUserPassAuthPassword,
	}

	vaultCli, vaultErr = providers.VaultClient(ctx, vaultCfg)
	if vaultErr != nil {
		log.Error(ctx, "cannot initialize vault client", "err", err)
		return
	}

	if vaultCfg.UserPassAuthEnabled {
		go providers.RenewToken(ctx, vaultCli, vaultCfg)
	}

	bjjKeyProvider, err := kms.NewVaultPluginIden3KeyProvider(vaultCli, cfg.KeyStore.PluginIden3MountPath, kms.KeyTypeBabyJubJub)
	if err != nil {
		log.Error(ctx, "cannot create BabyJubJub key provider", "err", err)
		panic(err)
	}

	ethKeyProvider, err := kms.NewVaultPluginIden3KeyProvider(vaultCli, cfg.KeyStore.PluginIden3MountPath, kms.KeyTypeEthereum)
	if err != nil {
		log.Error(ctx, "cannot create Ethereum key provider", "err", err)
		panic(err)
	}

	keyStore := kms.NewKMS()
	err = keyStore.RegisterKeyProvider(kms.KeyTypeBabyJubJub, bjjKeyProvider)
	if err != nil {
		log.Error(ctx, "cannot register BabyJubJub key provider", "err", err)
		panic(err)
	}

	err = keyStore.RegisterKeyProvider(kms.KeyTypeEthereum, ethKeyProvider)
	if err != nil {
		log.Error(ctx, "cannot register Ethereum key provider", "err", err)
		panic(err)
	}

	err = config.CheckDID(ctx, cfg, vaultCli)
	if err != nil {
		log.Error(ctx, "cannot initialize did", "err", err)
		return
	}

	identityRepo := repositories.NewIdentity()
	claimsRepo := repositories.NewClaims()
	mtRepo := repositories.NewIdentityMerkleTreeRepository()
	merkleTreeRootsRepository := repositories.NewMerkleTreeNodesRepository()
	identityStateRepo := repositories.NewIdentityState()
	revocationRepository := repositories.NewRevocation()
	mtService := services.NewIdentityMerkleTrees(mtRepo, merkleTreeRootsRepository)
	qrService := services.NewQrStoreService(cachex)

	connectionsRepository := repositories.NewConnections()

	commonClient, err := ethclient.Dial(cfg.Ethereum.URL)
	if err != nil {
		panic("Error dialing with ethclient: " + err.Error())
	}

	minGasPrice := big.NewInt(int64(cfg.Ethereum.MinGasPrice))
	maxGasPrice := big.NewInt(int64(cfg.Ethereum.MaxGasPrice))
	if cfg.GasPriceZero {
		minGasPrice = big.NewInt(0)
		maxGasPrice = big.NewInt(0)
	}

	cl := eth.NewClient(commonClient, &eth.ClientConfig{
		DefaultGasLimit:        cfg.Ethereum.DefaultGasLimit,
		ConfirmationTimeout:    cfg.Ethereum.ConfirmationTimeout,
		ConfirmationBlockCount: cfg.Ethereum.ConfirmationBlockCount,
		ReceiptTimeout:         cfg.Ethereum.ReceiptTimeout,
		MinGasPrice:            minGasPrice,
		MaxGasPrice:            maxGasPrice,
		RPCResponseTimeout:     cfg.Ethereum.RPCResponseTimeout,
		WaitReceiptCycleTime:   cfg.Ethereum.WaitReceiptCycleTime,
		WaitBlockCycleTime:     cfg.Ethereum.WaitBlockCycleTime,
	}, keyStore)

	rhsFactory := reverse_hash.NewFactory(cfg.CredentialStatus.RHS.GetURL(), cl, common.HexToAddress(cfg.CredentialStatus.OnchainTreeStore.SupportedTreeStoreContract), reverse_hash.DefaultRHSTimeOut)
	revocationStatusResolver := revocation_status.NewRevocationStatusResolver(cfg.CredentialStatus)

	identityService := services.NewIdentity(keyStore, identityRepo, mtRepo, identityStateRepo, mtService, qrService, claimsRepo, revocationRepository, connectionsRepository, storage, nil, nil, pubsub.NewMock(), cfg.CredentialStatus, rhsFactory, revocationStatusResolver)
	claimsService := services.NewClaim(claimsRepo, identityService, qrService, mtService, identityStateRepo, schemaLoader, storage, cfg.ServerUrl, cfg.APIUI.ServerURL, cfg.SingleIssuer, ps, cfg.IPFS.GatewayURL, revocationStatusResolver)

	circuitsLoaderService := circuitLoaders.NewCircuits(cfg.Circuit.Path)
	proofService := initProofService(ctx, cfg, circuitsLoaderService)

	transactionService, err := gateways.NewTransaction(cl, cfg.Ethereum.ConfirmationBlockCount)
	if err != nil {
		log.Error(ctx, "error creating transaction service", "err", err)
		panic("error creating transaction service")
	}
	publisherGateway, err := gateways.NewPublisherEthGateway(cl, common.HexToAddress(cfg.Ethereum.ContractAddress), keyStore, cfg.PublishingKeyPath)
	if err != nil {
		log.Error(ctx, "error creating publish gateway", "err", err)
		panic("error creating publish gateway")
	}
	publisher := gateways.NewPublisher(storage, identityService, claimsService, mtService, keyStore, transactionService, proofService, publisherGateway, cfg.Ethereum.ConfirmationTimeout, ps)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	wg := new(sync.WaitGroup)
	run(ctx, wg, cfg, publisher, onChainPublisherRunner)
	run(ctx, wg, cfg, publisher, statusCheckerRunner)

	waitGroupChannel := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitGroupChannel)
	}()

	select {
	case <-quit:
	case <-waitGroupChannel:
	}

	<-quit
	log.Info(ctx, "finishing app")
	cancel()
	log.Info(ctx, "Finished")
}

func initProofService(ctx context.Context, config *config.Configuration, circuitLoaderService *circuitLoaders.Circuits) ports.ZKGenerator {
	log.Info(ctx, "native prover enabled", "enabled", config.NativeProofGenerationEnabled)
	if config.NativeProofGenerationEnabled {
		proverConfig := &services.NativeProverConfig{
			CircuitsLoader: circuitLoaderService,
		}
		return services.NewNativeProverService(proverConfig)
	}

	proverConfig := &gateways.ProverConfig{
		ServerURL:       config.Prover.ServerURL,
		ResponseTimeout: config.Prover.ResponseTimeout,
	}
	return gateways.NewProverService(proverConfig)
}

func run(
	ctx context.Context,
	wg *sync.WaitGroup,
	cfg *config.Configuration,
	publisher ports.Publisher,
	runner func(ctx context.Context, cfg *config.Configuration, publisher ports.Publisher),
) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		runner(ctx, cfg, publisher)
	}()
}

func onChainPublisherRunner(ctx context.Context, cfg *config.Configuration, publisher ports.Publisher) {
	ticker := time.NewTicker(cfg.StatesTransitionFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// If the previous state publishing is failed, we try to re-publish it
			republishedState, err := publisher.RetryPublishState(ctx, &cfg.APIUI.IssuerDID) // TODO single
			if err != nil && !errors.Is(err, gateways.ErrNoFailedStatesToProcess) {
				if errors.Is(err, gateways.ErrStateIsBeingProcessed) {
					continue
				}

				log.Error(ctx, "error re-publishing state", "err", err)
				continue
			}
			if republishedState != nil {
				ticker.Reset(cfg.StatesTransitionFrequency)
				log.Info(ctx, "re-published state",
					"tx", republishedState.TxID,
					"state", republishedState.State,
				)
				continue
			}

			publishedState, err := publisher.PublishState(ctx, &cfg.APIUI.IssuerDID) // TODO single
			if err != nil {
				if errors.Is(err, gateways.ErrStateIsBeingProcessed) ||
					errors.Is(err, gateways.ErrNoStatesToProcess) {
					continue
				}

				ticker.Reset(cfg.StatesTransitionFrequency)
				log.Error(ctx, "error publishing state", "err", err)
				continue
			}
			if publishedState == nil {
				log.Error(ctx, "published state is nil")
				continue
			}

			log.Info(ctx, "published state",
				"tx", publishedState.TxID,
				"state", publishedState.State,
			)
		case <-ctx.Done():
			log.Info(ctx, "finishing on chain publishing job")
		}
	}
}

func statusCheckerRunner(ctx context.Context, cfg *config.Configuration, publisher ports.Publisher) {
	ticker := time.NewTicker(cfg.OnChainCheckStatusFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			publisher.CheckTransactionStatus(ctx)
		case <-ctx.Done():
			log.Info(ctx, "finishing check transaction status job")
		}
	}
}
