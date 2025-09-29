package cmd

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/styrainc/opa-control-plane/cmd"
	"github.com/styrainc/opa-control-plane/cmd/internal/flags"
	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/migrations"
	"github.com/styrainc/opa-control-plane/internal/progress"
	"github.com/styrainc/opa-control-plane/internal/service"
	"github.com/styrainc/opa-control-plane/internal/util"
	"github.com/styrainc/opa-control-plane/libraries"
)

type buildParams struct {
	noninteractive    bool
	configFile        []string
	persistenceDir    string
	resetPersistence  bool
	mergeConflictFail bool
	migrateDB         bool
	bundleNames       []string
	logging           logging.Config
}

func init() {
	var params buildParams

	build := &cobra.Command{
		Use:   "build",
		Short: "Build and distribute configured bundles",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			lc := params.logging
			if !params.noninteractive {
				// interactive sessions get a nice report, so we suppress error logs
				lc.Level = logging.LevelError
			}
			log := logging.NewLogger(lc)

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

			if len(params.bundleNames) > 0 {
				for name := range config.Bundles {
					if !slices.Contains(params.bundleNames, name) {
						delete(config.Bundles, name)
					}
				}
			}

			// It might be that `opactl build` is connecting to database -- but
			// the common use is that `opactl build` will just use its own in-memory
			// sqlite DB. The logic for running migrations is thus: Do as you're told
			// if you're told; otherwise apply migrations if there is no database
			// config.
			migrate := params.migrateDB || config.Database == nil

			svc := service.New().
				WithPersistenceDir(params.persistenceDir).
				WithConfig(config).
				WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
				WithSingleShot(true).
				WithLogger(log).
				WithNoninteractive(params.noninteractive).
				WithMigrateDB(migrate)
			if err := svc.Init(ctx); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}

			if err := svc.Run(ctx); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}

			buildReport := collectBuildReport(svc.Report())

			if !params.noninteractive {
				printReport(buildReport)
			}

			if !buildReport.allBuildsSuccessful() {
				os.Exit(1)
			}
		},
	}

	flags.AddConfig(build.Flags(), &params.configFile)
	flags.AddBundleName(build.Flags(), &params.bundleNames)
	build.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	build.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")
	build.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	progress.Var(build.Flags(), &params.noninteractive)
	logging.VarP(build, &params.logging)
	migrations.Var(build.Flags(), &params.migrateDB)

	cmd.RootCommand.AddCommand(
		build,
	)
}

type buildError struct {
	bundleName string
	buildState service.BuildState
	message    string
}

type buildReport struct {
	totalBuilds      int
	successfulBuilds int
	buildErrors      []buildError
}

func (b *buildReport) allBuildsSuccessful() bool {
	return b.totalBuilds == b.successfulBuilds
}

func collectBuildReport(r *service.Report) *buildReport {
	sorted := slices.Collect(maps.Keys(r.Bundles))
	sort.Strings(sorted)

	var success int
	var buildErrors []buildError
	for _, name := range sorted {
		if r.Bundles[name].State == service.BuildStateSuccess {
			success++
		} else {
			buildErrors = append(buildErrors, buildError{
				bundleName: name,
				buildState: r.Bundles[name].State,
				message:    r.Bundles[name].Message,
			})
		}
	}

	return &buildReport{
		totalBuilds:      len(r.Bundles),
		successfulBuilds: success,
		buildErrors:      buildErrors,
	}
}

func printReport(r *buildReport) {
	fmt.Fprintf(os.Stderr, "%d/%d bundles built and pushed successfully\n", r.successfulBuilds, r.totalBuilds)
	if !r.allBuildsSuccessful() {
		table := tablewriter.NewWriter(os.Stderr)
		table.SetAutoWrapText(false)
		table.SetHeader([]string{"Bundle", "Status", "Message"})
		for _, buildError := range r.buildErrors {
			table.Append([]string{buildError.bundleName, buildError.buildState.String(), buildError.message})
		}
		table.Render()
	}
}
