package repositories

import (
	"context"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
	"github.com/rarimo/issuer-node/internal/core/ports"
	"github.com/rarimo/issuer-node/internal/db"
)

type users struct{}

func NewUsers() ports.UsersRepository {
	return &users{}
}

func (u *users) Save(ctx context.Context, conn db.Querier, login, password string, did core.DID) error {
	statement := `INSERT INTO users (login, password, did) VALUES ($1, $2, $3)`

	_, err := conn.Exec(ctx, statement, login, password, did.String())
	if err != nil {
		return errors.Wrap(err, "failed to exec statement")
	}

	return nil
}
