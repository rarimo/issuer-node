package ports

import (
	"context"
	"github.com/rarimo/issuer-node/internal/db"
)

type MerkleTreeNodesRepository interface {
	GetMTIDByKey(ctx context.Context, conn db.Querier, key string) (int64, error)
}
