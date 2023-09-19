package repositories

import (
	"context"
	"fmt"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
	"github.com/polygonid/sh-id-platform/internal/core/ports"
	"github.com/polygonid/sh-id-platform/internal/db"
)

type merkleTreeNodesRepository struct{}

func NewMerkleTreeNodesRepository() ports.MerkleTreeNodesRepository {
	return &merkleTreeNodesRepository{}
}

func (mtr *merkleTreeNodesRepository) GetByKey(
	ctx context.Context, conn db.Querier, key string,
) (*domain.MerkleTreeNode, error) {
	var res domain.MerkleTreeNode
	row := conn.QueryRow(ctx, "SELECT mt_id, \"key\", type, child_l, child_r FROM mt_nodes WHERE \"key\"=$1", "\\x"+key)
	if err := row.Scan(&res.MTID, &res.Key, &res.Type, &res.ChildL, &res.ChildR); err != nil {
		return nil, fmt.Errorf("error getting merkle tree by key %w", err)
	}
	return &res, nil
}
