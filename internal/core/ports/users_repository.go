package ports

import (
	"context"
	core "github.com/iden3/go-iden3-core"
	"github.com/rarimo/issuer-node/internal/db"
)

type UsersRepository interface {
	Save(ctx context.Context, conn db.Querier, login, password string, did core.DID) error
}
