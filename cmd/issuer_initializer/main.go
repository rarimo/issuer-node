package main

import (
	"context"
	"fmt"
	"os"

	"github.com/rarimo/issuer-node/internal/config"
	"github.com/rarimo/issuer-node/internal/core/services"
	"github.com/rarimo/issuer-node/internal/db"
	"github.com/rarimo/issuer-node/internal/kms"
	"github.com/rarimo/issuer-node/internal/log"
	"github.com/rarimo/issuer-node/internal/providers"
	"github.com/rarimo/issuer-node/internal/repositories"
	"github.com/rarimo/issuer-node/pkg/pubsub"
)

const perm = 777

func main() {
	if _, err := os.Stat(config.K8sDidFile); err == nil {
		log.Info(context.Background(), "identifier already created and stored in file. New identifier not created")
		return
	}

	cfg, err := config.Load("./config.toml")
	if err != nil {
		log.Error(context.Background(), "cannot load config", "err", err)
		return
	}

	ctx, cancel := context.WithCancel(log.NewContext(context.Background(), cfg.Log.Level, cfg.Log.Mode, os.Stdout))
	defer cancel()

	if err := cfg.Sanitize(ctx); err != nil {
		log.Error(ctx, "there are errors in the configuration that prevent server to start", "err", err)
		return
	}

	storage, err := db.NewStorage(cfg.Database.URL)
	if err != nil {
		log.Error(ctx, "cannot connect to database", "err", err)
		return
	}

	vaultCli, err := providers.NewVaultClient(cfg.KeyStore.Address, cfg.KeyStore.Token)
	if err != nil {
		log.Error(ctx, "cannot init vault client: ", "err", err)
		return
	}

	keyStore, err := kms.Open(cfg.KeyStore.PluginIden3MountPath, vaultCli)
	if err != nil {
		log.Error(ctx, "cannot initialize kms", "err", err)
		return
	}

	// repositories initialization
	identityRepository := repositories.NewIdentity()
	claimsRepository := repositories.NewClaims()
	mtRepository := repositories.NewIdentityMerkleTreeRepository()
	identityStateRepository := repositories.NewIdentityState()
	merkleTreeRootsRepository := repositories.NewMerkleTreeNodesRepository()

	// services initialization
	mtService := services.NewIdentityMerkleTrees(mtRepository, merkleTreeRootsRepository)
	identityService := services.NewIdentity(keyStore, identityRepository, mtRepository, identityStateRepository, mtService, claimsRepository, nil, nil, storage, nil, nil, nil, pubsub.NewMock())

	identity, err := identityService.Create(ctx, cfg.APIUI.IdentityMethod, cfg.APIUI.IdentityBlockchain, cfg.APIUI.IdentityNetwork, cfg.ServerUrl)
	if err != nil {
		log.Error(ctx, "error creating identifier", err)
		return
	}

	log.Info(ctx, "identifier crated successfully")

	if err := os.WriteFile(config.K8sDidFile, []byte(identity.Identifier), os.FileMode(perm)); err != nil {
		log.Error(ctx, "error writing identifier to file", "error", err)
	}

	//nolint:all
	fmt.Printf(identity.Identifier)
}
