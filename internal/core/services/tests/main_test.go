package services_tests

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/rarimo/issuer-node/internal/config"
	"github.com/rarimo/issuer-node/internal/db"
	"github.com/rarimo/issuer-node/internal/db/tests"
	"github.com/rarimo/issuer-node/internal/kms"
	"github.com/rarimo/issuer-node/internal/log"
	"github.com/rarimo/issuer-node/internal/providers"
	"github.com/rarimo/issuer-node/pkg/cache"
)

var (
	storage        *db.Storage
	vaultCli       *api.Client
	bjjKeyProvider kms.KeyProvider
	keyStore       *kms.KMS
	cachex         cache.Cache
)

const ipfsGateway = "http://localhost:8080"

func TestMain(m *testing.M) {
	ctx := context.Background()
	conn := lookupPostgresURL()
	if conn == "" {
		conn = "postgres://postgres:postgres@localhost:5435"
	}

	cfgForTesting := config.Configuration{
		Database: config.Database{
			URL: conn,
		},
		KeyStore: config.VaultTest(),
	}
	s, teardown, err := tests.NewTestStorage(&cfgForTesting)
	defer teardown()
	if err != nil {
		log.Error(ctx, "failed to acquire test database", "err", err)
		os.Exit(1)
	}
	storage = s

	vaultCli, err = providers.NewVaultClient(cfgForTesting.KeyStore.Address, cfgForTesting.KeyStore.Token)
	if err != nil {
		log.Error(ctx, "failed to acquire vault client", "err", err)
		os.Exit(1)
	}

	bjjKeyProvider, err = kms.NewVaultPluginIden3KeyProvider(vaultCli, cfgForTesting.KeyStore.PluginIden3MountPath, kms.KeyTypeBabyJubJub)
	if err != nil {
		log.Error(ctx, "failed to create Iden3 Key Provider", "err", err)
		os.Exit(1)
	}

	keyStore = kms.NewKMS()
	err = keyStore.RegisterKeyProvider(kms.KeyTypeBabyJubJub, bjjKeyProvider)
	if err != nil {
		log.Error(ctx, "failed to register Key Provider", "err", err)
		os.Exit(1)
	}
	cachex = cache.NewMemoryCache()

	m.Run()
}

func lookupPostgresURL() string {
	con, ok := os.LookupEnv("POSTGRES_TEST_DATABASE")
	if !ok {
		return ""
	}
	return con
}
