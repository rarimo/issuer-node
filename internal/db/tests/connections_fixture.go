package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/rarimo/issuer-node/internal/core/domain"
)

// CreateConnection fixture
func (f *Fixture) CreateConnection(t *testing.T, conn *domain.Connection) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id, err := f.connectionsRepository.Save(ctx, f.storage.Pgx, conn)
	assert.NoError(t, err)
	return id
}
