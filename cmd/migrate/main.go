package main

import (
	"context"
	"os"

	"github.com/rarimo/issuer-node/internal/config"
	"github.com/rarimo/issuer-node/internal/db/schema"
	"github.com/rarimo/issuer-node/internal/log"

	_ "github.com/lib/pq"
)

func main() {
	cfg, err := config.Load("./config.toml")
	if err != nil {
		log.Error(context.Background(), "cannot load config", "err", err)
	}
	// Context with log
	ctx := log.NewContext(context.Background(), cfg.Log.Level, cfg.Log.Mode, os.Stdout)
	log.Debug(ctx, "database", "url", cfg.Database.URL)

	if err := schema.Migrate(cfg.Database.URL); err != nil {
		log.Error(ctx, "error migrating database", "err", err)
		return
	}

	log.Info(ctx, "migration done!")
}
