package db

import (
	"github.com/spf13/cobra"

	"github.com/open-policy-agent/opa-control-plane/cmd"
	"github.com/open-policy-agent/opa-control-plane/cmd/internal/flags"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
)

type migrateParams struct {
	dryrun            bool
	mergeConflictFail bool
	configFile        []string
	logging           logging.Config
}

func init() {
	var params migrateParams

	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Run any outstanding database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			lc := params.logging
			log := logging.NewLogger(lc)

			bs, err := config.Merge(params.configFile, params.mergeConflictFail)
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			config, err := config.Parse(bs)
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			migrator := migrations.New().
				WithLogger(log).
				WithConfig(config.Database).
				WithMigrate(!params.dryrun)

			if _, err := migrator.Run(ctx); err != nil {
				log.Fatalf("migrate: %v", err)
			}
		},
	}

	flags.AddConfig(migrate.Flags(), &params.configFile)
	migrate.Flags().BoolVarP(&params.dryrun, "dry-run", "", false, "Only report outstanding migrations, don't apply them")
	migrate.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	logging.VarP(migrate, &params.logging)

	// adding an extra layer to differentiate from `opactl migrate`
	db := &cobra.Command{
		Use:   "db",
		Short: "DB-related commands",
	}
	db.AddCommand(migrate)

	cmd.RootCommand.AddCommand(
		db,
	)
}
