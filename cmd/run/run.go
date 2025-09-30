package cmd

import (
	"bytes"
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/styrainc/opa-control-plane/cmd"
	"github.com/styrainc/opa-control-plane/cmd/internal/flags"
	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/migrations"
	"github.com/styrainc/opa-control-plane/internal/server"
	"github.com/styrainc/opa-control-plane/internal/service"
	"github.com/styrainc/opa-control-plane/internal/util"
	"github.com/styrainc/opa-control-plane/libraries"
)

const defaultLocalAddr = "localhost:8282"

type runParams struct {
	addr              string
	configFile        []string
	persistenceDir    string
	resetPersistence  bool
	mergeConflictFail bool
	migrateDB         bool
	logging           logging.Config
}

func init() {
	var params runParams

	run := &cobra.Command{
		Use:   "run",
		Short: "Run the OPA Control Plane service",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			log := logging.NewLogger(params.logging)

			if params.resetPersistence {
				if err := os.RemoveAll(params.persistenceDir); err != nil {
					log.Fatalf("failed to remove persistence directory: %v", err)
				}
			}
			if err := os.MkdirAll(params.persistenceDir, 0755); err != nil {
				log.Fatalf("failed to create persistence directory: %v", err)
			}

			bs, err := config.Merge(params.configFile, params.mergeConflictFail)
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			config, err := config.Parse(bytes.NewBuffer(bs))
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			config.SetSQLitePersistentByDefault(params.persistenceDir)

			svc := service.New().
				WithPersistenceDir(params.persistenceDir).
				WithConfig(config).
				WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
				WithLogger(log).
				WithMigrateDB(params.migrateDB)

			// NOTE(sr): We run Init() separately here because we're passing svc.Database() to server below
			if err := svc.Init(ctx); err != nil {
				log.Fatalf("initialize service: %v", err)
			}

			go func() {
				if err := server.New().WithDatabase(svc.Database()).WithReadiness(svc.Ready).Init().ListenAndServe(params.addr); err != nil {
					log.Fatalf("failed to start server: %v", err)
				}
			}()

			if err := svc.Run(ctx); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	flags.AddConfig(run.Flags(), &params.configFile)
	run.Flags().StringVarP(&params.addr, "addr", "a", defaultLocalAddr, "Set listening address of the server")
	run.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	run.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")
	run.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	logging.VarP(run, &params.logging)
	migrations.Var(run.Flags(), &params.migrateDB)

	cmd.RootCommand.AddCommand(
		run,
	)
}
