package services

import (
	"context"
	core "github.com/iden3/go-iden3-core"
	"github.com/polygonid/sh-id-platform/internal/core/ports"
	"github.com/polygonid/sh-id-platform/internal/db"
)

type users struct {
	usersRepo ports.UsersRepository
	storage   *db.Storage
}

// NewUsers creates a new users service
func NewUsers(repo ports.UsersRepository, storage *db.Storage) ports.UsersService {
	return &users{
		usersRepo: repo,
		storage:   storage,
	}
}

func (u *users) AddUser(ctx context.Context, login, password string, did core.DID) error {
	return u.usersRepo.Save(ctx, u.storage.Pgx, login, password, did)
}
