package ports

import (
	"context"
	"encoding/json"

	"github.com/iden3/go-schema-processor/verifiable"

	"github.com/rarimo/issuer-node/internal/core/domain"
	"github.com/rarimo/issuer-node/pkg/pubsub"
)

// NotificationService represents the notification service interface
type NotificationService interface {
	SendCreateCredentialNotification(ctx context.Context, payload pubsub.Message) error
	SendCreateConnectionNotification(ctx context.Context, payload pubsub.Message) error
}

// NotificationGateway represents the notification interface
type NotificationGateway interface {
	Notify(ctx context.Context, msg json.RawMessage, userDIDDocument verifiable.DIDDocument) (*domain.UserNotificationResult, error)
}
