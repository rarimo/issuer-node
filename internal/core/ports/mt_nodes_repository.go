package ports

import (
	"context"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
	"github.com/polygonid/sh-id-platform/internal/db"
)

type MerkleTreeNodesRepository interface {
	GetByKey(ctx context.Context, conn db.Querier, key string) (*domain.MerkleTreeNode, error)
}
