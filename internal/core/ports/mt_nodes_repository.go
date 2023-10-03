package ports

import (
	"context"
	"github.com/polygonid/sh-id-platform/internal/db"
)

type MerkleTreeNodesRepository interface {
	GetMTIDByKey(ctx context.Context, conn db.Querier, key string) (int64, error)
}
