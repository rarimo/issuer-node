package ports

import (
	"context"
	core "github.com/iden3/go-iden3-core"
)

type UsersService interface {
	AddUser(ctx context.Context, login, password string, did core.DID) error
}
