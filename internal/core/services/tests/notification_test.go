package services_tests

import (
	"context"
	"os"
	"testing"

	commonEth "github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rarimo/issuer-node/internal/common"
	"github.com/rarimo/issuer-node/internal/core/domain"
	"github.com/rarimo/issuer-node/internal/core/event"
	"github.com/rarimo/issuer-node/internal/core/ports"
	"github.com/rarimo/issuer-node/internal/core/services"
	"github.com/rarimo/issuer-node/internal/db/tests"
	"github.com/rarimo/issuer-node/internal/gateways"
	"github.com/rarimo/issuer-node/internal/log"
	"github.com/rarimo/issuer-node/internal/repositories"
	"github.com/rarimo/issuer-node/pkg/credentials/revocation_status"
	"github.com/rarimo/issuer-node/pkg/http"
	"github.com/rarimo/issuer-node/pkg/pubsub"
	"github.com/rarimo/issuer-node/pkg/reverse_hash"
)

func TestNotification_SendNotification(t *testing.T) {
	const (
		method     = "polygonid"
		blockchain = "polygon"
		network    = "mumbai"
	)
	ctx := log.NewContext(context.Background(), log.LevelDebug, log.OutputText, os.Stdout)
	identityRepo := repositories.NewIdentity()
	claimsRepo := repositories.NewClaims()
	identityStateRepo := repositories.NewIdentityState()
	mtRepo := repositories.NewIdentityMerkleTreeRepository()
	mtService := services.NewIdentityMerkleTrees(mtRepo)
	revocationRepository := repositories.NewRevocation()
	connectionsRepository := repositories.NewConnections()
	rhsFactory := reverse_hash.NewFactory(cfg.CredentialStatus.RHS.URL, nil, commonEth.HexToAddress(cfg.CredentialStatus.OnchainTreeStore.SupportedTreeStoreContract), reverse_hash.DefaultRHSTimeOut)
	revocationStatusResolver := revocation_status.NewRevocationStatusResolver(cfg.CredentialStatus)
	identityService := services.NewIdentity(keyStore, identityRepo, mtRepo, identityStateRepo, mtService, nil, claimsRepo, revocationRepository, connectionsRepository, storage, nil, nil, pubsub.NewMock(), cfg.CredentialStatus, rhsFactory, revocationStatusResolver)
	credentialsService := services.NewClaim(claimsRepo, identityService, nil, mtService, identityStateRepo, docLoader, storage, cfg.CredentialStatus.DirectStatus.GetURL(), pubsub.NewMock(), ipfsGateway, revocationStatusResolver)
	connectionsService := services.NewConnection(connectionsRepository, storage)
	iden, err := identityService.Create(ctx, "polygon-test", &ports.DIDCreationOptions{Method: method, Blockchain: blockchain, Network: network, KeyType: BJJ})
	require.NoError(t, err)

	did, err := w3c.ParseDID(iden.Identifier)
	require.NoError(t, err)

	userDID, err := w3c.ParseDID("did:polygonid:polygon:mumbai:2qH7XAwYQzCp9VfhpNgeLtK2iCehDDrfMWUCEg5ig5")
	require.NoError(t, err)

	notificationGateway := gateways.NewPushNotificationClient(http.DefaultHTTPClientWithRetry)
	notificationService := services.NewNotification(notificationGateway, connectionsService, credentialsService)

	fixture := tests.NewFixture(storage)
	credID := fixture.CreateClaim(t, &domain.Claim{
		Identifier:      common.ToPointer(did.String()),
		Issuer:          did.String(),
		OtherIdentifier: userDID.String(),
		HIndex:          "20060639968773997271173557722944342103398298534714534718204282267207714246564",
	})

	t.Run("should get an error, non existing credential", func(t *testing.T) {
		ev := event.CreateCredential{CredentialIDs: []string{uuid.NewString()}, IssuerID: did.String()}
		message, err := ev.Marshal()
		require.NoError(t, err)
		assert.Error(t, notificationService.SendCreateCredentialNotification(ctx, message))
	})

	t.Run("should get an error, existing credential but not existing connection", func(t *testing.T) {
		ev := event.CreateCredential{CredentialIDs: []string{credID.String()}, IssuerID: did.String()}
		message, err := ev.Marshal()
		require.NoError(t, err)
		assert.Error(t, notificationService.SendCreateCredentialNotification(ctx, message))
	})

	t.Run("should get an error,wrong credential id", func(t *testing.T) {
		ev := event.CreateCredential{CredentialIDs: []string{"wrong id"}, IssuerID: did.String()}
		message, err := ev.Marshal()
		require.NoError(t, err)
		assert.Error(t, notificationService.SendCreateCredentialNotification(ctx, message))
	})
}
