package repositories

import (
	"context"
	"fmt"
	"github.com/rarimo/issuer-node/internal/core/ports"
	"github.com/rarimo/issuer-node/internal/db"
)

type merkleTreeNodesRepository struct{}

func NewMerkleTreeNodesRepository() ports.MerkleTreeNodesRepository {
	return &merkleTreeNodesRepository{}
}

func (mtr *merkleTreeNodesRepository) GetMTIDByKey(
	ctx context.Context, conn db.Querier, key string,
) (int64, error) {
	var mtID int64
	row := conn.QueryRow(ctx, "SELECT mt_id FROM mt_nodes WHERE \"key\"=$1", "\\x"+key)
	if err := row.Scan(&mtID); err != nil {
		return 0, fmt.Errorf("error getting merkle tree by key %w", err)
	}
	return mtID, nil
}
