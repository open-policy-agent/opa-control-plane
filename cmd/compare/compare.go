package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/akedrou/textdiff"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/spf13/cobra"
	"github.com/styrainc/opa-control-plane/cmd"
	"github.com/styrainc/opa-control-plane/cmd/internal/das"
	"github.com/styrainc/opa-control-plane/cmd/internal/flags"
	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/s3"
)

var log *logging.Logger

type compareReport struct {
	MissingSystems []string                       `json:"missing_systems,omitempty"`
	ExtraSystems   []string                       `json:"extra_systems,omitempty"`
	Systems        map[string]compareSystemReport `json:"systems,omitempty"`
}

type compareSystemReport struct {
	Error  *string              `json:"error,omitempty"`
	Bundle *compareBundleReport `json:"bundle,omitempty"`
}

type compareBundleReport struct {
	Rego *compareRegoReport `json:"rego,omitempty"`
}

func (r *compareBundleReport) init() {
	if r.Rego == nil {
		r.Rego = &compareRegoReport{Diffs: map[string]string{}}
	}
}

func (r *compareBundleReport) AddExtra(path string) {
	r.init()
	r.Rego.Extras = append(r.Rego.Extras, path)
}

func (r *compareBundleReport) AddMissing(path string) {
	r.init()
	r.Rego.Missing = append(r.Rego.Missing, path)
}

func (r *compareBundleReport) AddDiff(path, blob string) {
	r.init()
	r.Rego.Diffs[path] = blob
}

func (r *compareBundleReport) Empty() bool {
	if r.Rego == nil {
		return true
	}
	return len(r.Rego.Missing) == 0 && len(r.Rego.Extras) == 0 && len(r.Rego.Diffs) == 0
}

type compareRegoReport struct {
	Missing []string          `json:"missing,omitempty"`
	Extras  []string          `json:"extras,omitempty"`
	Diffs   map[string]string `json:"diffs,omitempty"`
}

type compareParams struct {
	configFile        []string
	styraURL          string
	headers           []string
	styraToken        string
	mergeConflictFail bool
	logging           logging.Config
}

func init() {

	var params compareParams

	params.styraToken = os.Getenv("STYRA_TOKEN")

	compare := &cobra.Command{
		Use:   "compare",
		Short: "Compare OPA Control Plane configuration and bundles to version from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doCompare(params); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	flags.AddConfig(compare.Flags(), &params.configFile)
	compare.Flags().StringVarP(&params.styraURL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")
	compare.Flags().StringSliceVarP(&params.headers, "header", "", nil, "Set additional HTTP headers for requests to Styra API")
	compare.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	logging.VarP(compare, &params.logging)

	compare.Hidden = true

	cmd.RootCommand.AddCommand(
		compare,
	)
}

func doCompare(params compareParams) error {
	log = logging.NewLogger(params.logging)

	log.Infof("Loading configuration from %v...", params.configFile)

	bs, err := config.Merge(params.configFile, params.mergeConflictFail)
	if err != nil {
		return err
	}

	cfg, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}

	url := cfg.Metadata.ExportedFrom

	if params.styraURL != "" {
		url = params.styraURL
	}

	if url == "" {
		return errors.New("please provide Styra URL with -u/--url")
	}

	sortedBundles := slices.Collect(maps.Values(cfg.Bundles))
	sort.Slice(sortedBundles, func(i, j int) bool {
		return sortedBundles[i].Name < sortedBundles[j].Name
	})

	styra := das.Client{
		URL:     url,
		Headers: params.headers,
		Token:   params.styraToken,
		Client:  http.DefaultClient,
	}
	log.Info("Fetching systems...")
	resp, err := styra.JSON("v1/systems")
	if err != nil {
		return err
	}

	var v1systems []*das.V1System
	if err := resp.Decode(&v1systems); err != nil {
		return err
	}

	v1SystemsByName := map[string]*das.V1System{}
	for _, system := range v1systems {
		v1SystemsByName[system.SanitizedName()] = system
	}

	_ = styra

	result := compareReport{
		Systems: map[string]compareSystemReport{},
	}

	for name := range v1SystemsByName {
		if _, ok := cfg.Bundles[name]; !ok {
			result.MissingSystems = append(result.MissingSystems, name)
		}
	}

	ctx := context.Background()

	for _, b := range sortedBundles {
		v1, ok := v1SystemsByName[b.Name]
		if !ok {
			result.ExtraSystems = append(result.ExtraSystems, b.Name)
			continue
		}
		report, err := compareSystem(ctx, &styra, v1, b)
		if err != nil {
			msg := err.Error()
			report = &compareSystemReport{Error: &msg}
		}
		result.Systems[b.Name] = *report
	}

	bs, err = json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(bs))

	return nil
}

func compareSystem(ctx context.Context, client *das.Client, v1 *das.V1System, system *config.Bundle) (*compareSystemReport, error) {

	log.Infof("Checking system %q...", system.Name)

	s, err := s3.New(ctx, system.ObjectStorage)
	if err != nil {
		return nil, err
	}
	r, err := s.Download(ctx)
	if err != nil {
		return nil, err
	}
	a, err := bundle.NewReader(r).Read()
	if err != nil {
		return nil, err
	}

	// TODO(tsandall): ideally this would be addressed upstream or fixed within the builder
	for i := range a.Modules {
		a.Modules[i].Path = strings.TrimPrefix(a.Modules[i].Path, "/")
	}

	resp, err := client.JSON("v1/systems/" + v1.Id + "/bundles")
	if err != nil {
		return nil, err
	}

	var v1bundles []*das.V1Bundle
	if err := resp.Decode(&v1bundles); err != nil {
		return nil, err
	}

	downloadResp, err := client.Get(strings.TrimPrefix(v1bundles[0].DownloadURL, client.URL))
	if err != nil {
		return nil, err
	}

	defer downloadResp.Body.Close()

	b, err := bundle.NewReader(downloadResp.Body).Read()
	if err != nil {
		return nil, err
	}

	bundleReport, err := compareBundle(a, b)
	result := &compareSystemReport{Bundle: &bundleReport}
	if err != nil {
		msg := err.Error()
		result.Error = &msg
	}
	return result, nil
}

func compareBundle(a, b bundle.Bundle) (compareBundleReport, error) {

	var r compareBundleReport

	aFiles := map[string][]byte{}
	for _, mf := range a.Modules {
		aFiles[mf.Path] = mf.Raw
	}

	bFiles := map[string][]byte{}
	for _, mf := range b.Modules {
		bFiles[mf.Path] = mf.Raw
	}

	for k := range aFiles {
		if _, ok := bFiles[k]; !ok {
			r.AddExtra(k)
		}
	}

	for k := range bFiles {
		if _, ok := aFiles[k]; !ok {
			r.AddMissing(k)
		}
	}

	for k := range aFiles {
		if _, ok := bFiles[k]; ok {
			am, err := ast.ParseModule(k, string(aFiles[k]))
			if err != nil {
				return r, err
			}

			bm, err := ast.ParseModule(k, string(bFiles[k]))
			if err != nil {
				return r, err
			}

			if !am.Equal(bm) {
				r.AddDiff(k, textdiff.Unified("Expected", "Found", string(bFiles[k]), string(aFiles[k])))
			}
		}
	}

	if !reflect.DeepEqual(a.Data, b.Data) {

		aBytes, err := json.MarshalIndent(a.Data, "", "  ")
		if err != nil {
			return r, err
		}

		bBytes, err := json.MarshalIndent(b.Data, "", "  ")
		if err != nil {
			return r, err
		}

		diffText := textdiff.Unified("Expected", "Found", string(bBytes), string(aBytes))
		if len(diffText) > 1024 {
			diffText = diffText[:1024]
		}

		r.AddDiff("data.json", diffText)
	}

	return r, nil
}
