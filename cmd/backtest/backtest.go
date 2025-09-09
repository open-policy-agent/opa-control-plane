package backtest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akedrou/textdiff"
	"github.com/olekukonko/tablewriter"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	v1 "github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/sdk"
	"github.com/spf13/cobra"
	"github.com/styrainc/opa-control-plane/cmd"
	"github.com/styrainc/opa-control-plane/cmd/internal/das"
	"github.com/styrainc/opa-control-plane/cmd/internal/flags"
	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/progress"
	"github.com/styrainc/opa-control-plane/internal/s3"
)

var log *logging.Logger

const (
	OutputFormatJSON   = "json"
	OutputFormatPretty = "pretty"
)

type Options struct {
	ConfigFile           []string
	URL                  string
	Token                string
	Headers              []string
	NumDecisions         int
	PolicyType           string
	MaxEvalTimeInflation int
	MergeConflictFail    bool
	Logging              logging.Config
	Output               io.Writer
	Noninteractive       bool
	Format               string
	BundleNames          []string
}

func init() {
	var opts Options

	opts.Token = os.Getenv("STYRA_TOKEN")

	backtest := &cobra.Command{
		Use:   "backtest",
		Short: "Run backtest on OPA Control Plane bundles against decisions from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			opts.Output = os.Stdout
			if err := Run(opts); err != nil {
				fmt.Fprintln(os.Stderr, "unexpected error:", err)
				os.Exit(1)
			}
		},
	}

	flags.AddConfig(backtest.Flags(), &opts.ConfigFile)
	flags.AddBundleName(backtest.Flags(), &opts.BundleNames)
	backtest.Flags().StringVarP(&opts.URL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")
	backtest.Flags().StringSliceVarP(&opts.Headers, "header", "", nil, "Set additional HTTP headers for requests to Styra API")
	backtest.Flags().IntVarP(&opts.NumDecisions, "decisions", "n", 100, "Number of decisions to backtest")
	backtest.Flags().StringVarP(&opts.PolicyType, "policy-type", "", "", "Specify policy type to backtest against (e.g., validating, mutating, etc.)")
	backtest.Flags().IntVarP(&opts.MaxEvalTimeInflation, "max-eval-time-inflation", "", 100, "Maximum allowed increase in decision evaluation time (in percents, <0 to disable)")
	backtest.Flags().BoolVarP(&opts.MergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	backtest.Flags().StringVarP(&opts.Format, "format", "", OutputFormatPretty, "Set output format (json, pretty)")
	logging.VarP(backtest, &opts.Logging)
	progress.Var(backtest.Flags(), &opts.Noninteractive)

	cmd.RootCommand.AddCommand(
		backtest,
	)

}

type Report struct {
	Bundles map[string]BundleReport `json:"bundles,omitempty"`
}

type ReportStatus int

const (
	ReportStatusUnknown ReportStatus = iota
	ReportStatusError
	ReportStatusResultDiff
	ReportStatusLatencyInflation
	ReportStatusPassed
	ReportStatusSkipped
)

func (s ReportStatus) String() string {
	switch s {
	case ReportStatusError:
		return "ERROR"
	case ReportStatusResultDiff:
		return "RESULT_DIFF"
	case ReportStatusLatencyInflation:
		return "LATENCY_INFLATION"
	case ReportStatusPassed:
		return "PASSED"
	case ReportStatusSkipped:
		return "SKIPPED"
	case ReportStatusUnknown:
		fallthrough
	default:
		return "UNKNOWN"
	}
}

type BundleReport struct {
	Status  ReportStatus   `json:"status"`
	Message string         `json:"message,omitempty"`
	Details []DecisionDiff `json:"details,omitempty"`
}

type DecisionDiff struct {
	Status  ReportStatus `json:"status"`
	Message string       `json:"error"`
	Path    string       `json:"path"`
}

func Run(opts Options) error {
	ctx := context.Background()

	if opts.Noninteractive {
		log = logging.NewLogger(opts.Logging)
	}

	bs, err := config.Merge(opts.ConfigFile, opts.MergeConflictFail)
	if err != nil {
		return err
	}

	cfg, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}

	if len(opts.BundleNames) > 0 {
		for name := range cfg.Bundles {
			if !slices.Contains(opts.BundleNames, name) {
				delete(cfg.Bundles, name)
			}
		}
	}

	url := cfg.Metadata.ExportedFrom

	if opts.URL != "" {
		url = opts.URL
	}

	if url == "" {
		return errors.New("please provide Styra URL with -u/--url")
	}

	styra := &das.Client{
		URL:     url,
		Headers: opts.Headers,
		Token:   opts.Token,
		Client:  http.DefaultClient}

	report := Report{
		Bundles: map[string]BundleReport{},
	}

	func() {
		bar := progress.New(opts.Noninteractive, len(cfg.Bundles), "running backtest")
		defer bar.Finish()
		for _, b := range cfg.Bundles {
			log.Infof("Backtesting bundle %q", b.Name)
			if err := backtestBundle(ctx, opts, styra, b, &report); err != nil {
				report.Bundles[b.Name] = BundleReport{
					Status:  ReportStatusError,
					Message: err.Error(),
				}
			}
			bar.Add(1)
		}
	}()

	switch opts.Format {
	case OutputFormatJSON:
		bs, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}

		fmt.Fprintln(opts.Output, string(bs))

	case OutputFormatPretty:
		printReport(opts.Output, cfg, report)
	}

	return nil
}

func printReport(w io.Writer, root *config.Root, report Report) {

	sorted := slices.Collect(maps.Keys(root.Bundles))
	sort.Slice(sorted, func(i, j int) bool {
		a := report.Bundles[sorted[i]]
		b := report.Bundles[sorted[j]]
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		if a.Message != b.Message {
			return a.Message < b.Message
		}
		return sorted[i] < sorted[j]
	})

	var success int

	for _, name := range sorted {
		if report.Bundles[name].Status == ReportStatusPassed {
			success++
		}
	}

	fmt.Fprintf(w, "%d/%d bundles backtested successfully\n", success, len(root.Bundles))

	table := tablewriter.NewWriter(w)
	table.SetAutoWrapText(false)
	table.SetHeader([]string{"Name", "Status", "Message"})

	for _, name := range sorted {
		sr := report.Bundles[name]
		table.Append([]string{name, sr.Status.String(), sr.Message})
	}

	table.Render()
}

func backtestBundle(ctx context.Context, opts Options, styra *das.Client, b *config.Bundle, report *Report) error {

	systemId, ok := b.Labels["system-id"]
	if !ok {
		report.Bundles[b.Name] = BundleReport{Status: ReportStatusSkipped, Message: "No system id configured"}
		return nil
	}

	if resp, err := styra.Get("v1/systems/"+systemId, das.Params{Query: map[string]string{
		"authz":       "false",
		"compact":     "true",
		"datasources": "false",
		"errors":      "false",
		"metadata":    "false",
		"modules":     "false",
		"policies":    "false",
		"rule_counts": "false",
	}}); err != nil {
		return err
	} else if resp.StatusCode == http.StatusNotFound {
		report.Bundles[b.Name] = BundleReport{Status: ReportStatusSkipped, Message: fmt.Sprintf("System %v does not exist", systemId)}
		return nil
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code for system %v: %v", systemId, resp.StatusCode)
	}

	params := das.Params{
		Query: map[string]string{
			"limit":  strconv.Itoa(opts.NumDecisions),
			"system": b.Labels["system-id"],
		},
	}

	if opts.PolicyType != "" {
		params.Query["policy_type"] = opts.PolicyType
	}

	resp, err := styra.JSON("v1/decisions", params)
	if err != nil {
		return err
	}

	var decisions das.V1Decisions

	if err := resp.Decode(&decisions); err != nil {
		return err
	}

	if len(decisions.Items) == 0 {
		report.Bundles[b.Name] = BundleReport{Status: ReportStatusSkipped, Message: "No decisions found for system"}
		return nil
	}

	s, err := s3.New(ctx, b.ObjectStorage)
	if err != nil {
		return err
	}

	r, err := s.Download(ctx)
	if err != nil {
		return err
	}

	bs, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	a, err := bundle.NewReader(bytes.NewReader(bs)).Read()
	if err != nil {
		return err
	}

	t0 := time.Now()

	var diffs []DecisionDiff

	// Start a HTTP server for bundle.

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		files := map[string][]byte{
			"/bundle.tar.gz": bs,
		}

		content, ok := files[r.URL.Path]
		if !ok {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		if _, err := w.Write(content); err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))

	defer ts.Close()

	// Start OPA SDK

	config := fmt.Sprintf(`{
				"services": {
						"test": {
								"url": %q
						}
				},
				"bundles": {
						"test": {
								"resource": "/bundle.tar.gz"
						}
				}
		}`, ts.URL)

	ready := make(chan struct{})
	sdkopts := sdk.Options{
		Config: strings.NewReader(config),
		Ready:  ready,
	}
	if log != nil {
		sdkopts.Logger = &logger{*log}
	}
	opa, err := sdk.New(ctx, sdkopts)
	if err != nil {
		return err
	}

	defer opa.Stop(ctx)

	select {
	case <-time.After(90 * time.Second):
		return errors.New("OPA SDK did not become ready in time")
	case <-ctx.Done():
		return ctx.Err()
	case <-ready:
		// SDK is ready
	}

	// Re-evaluate decisions

	tempDir, err := os.MkdirTemp("", "opa-control-plane-backtest-"+b.Name)
	if err != nil {
		return err
	}

	bundleFile, err := os.Create(filepath.Join(tempDir, "bundle.tar.gz"))
	if err != nil {
		return err
	}

	defer bundleFile.Close()

	if err := bundle.NewWriter(bundleFile).DisableFormat(true).Write(a); err != nil {
		return err
	}

	for i, d := range decisions.Items {

		options := sdk.DecisionOptions{
			Path: d.Path,
		}
		if d.Input != nil {
			options.Input = *d.Input
		}

		log.Infof("Evaluating decision %q for system %q", d.DecisionId, b.Name)

		var result *interface{}
		var start = time.Now()

		r, err := opa.Decision(ctx, options)
		if err != nil && !sdk.IsUndefinedErr(err) {
			return err
		} else if sdk.IsUndefinedErr(err) {
			result = nil
		} else {
			result = &r.Result
		}

		err = compareResults(&d, result, time.Since(start), opts.MaxEvalTimeInflation)
		if err == nil {
			continue
		}

		path := filepath.Join(tempDir, strconv.Itoa(i))
		if innerErr := os.MkdirAll(path, 0755); innerErr != nil {
			return innerErr
		}

		if innerErr := saveFailure(path, d); innerErr != nil {
			return innerErr
		}

		switch err := err.(type) {
		case *compareErr:
			diffs = append(diffs, DecisionDiff{Status: err.Status, Message: err.Message, Path: path})
		default:
			diffs = append(diffs, DecisionDiff{Status: ReportStatusError, Message: err.Error(), Path: path})
		}

	}

	if len(diffs) == 0 {
		report.Bundles[b.Name] = BundleReport{
			Status:  ReportStatusPassed,
			Message: fmt.Sprintf("%d/%d decisions were identical (took %v)", len(decisions.Items), len(decisions.Items), time.Since(t0)),
		}
		return nil
	}

	var nonErrorDiffs, errorDiffs int
	for _, d := range diffs {
		switch d.Status {
		case ReportStatusLatencyInflation:
			fallthrough
		case ReportStatusResultDiff:
			nonErrorDiffs++
		default:
			errorDiffs++
		}
	}

	if errorDiffs > 0 {
		report.Bundles[b.Name] = BundleReport{
			Status:  ReportStatusError,
			Message: fmt.Sprintf("%d/%d decisions generated errors. Details: %v", errorDiffs, len(decisions.Items), filepath.Dir(diffs[0].Path)),
			Details: diffs,
		}
	} else {
		report.Bundles[b.Name] = BundleReport{
			Status:  diffs[0].Status,
			Message: fmt.Sprintf("%d/%d decisions differed. Details: %v", nonErrorDiffs, len(decisions.Items), filepath.Dir(diffs[0].Path)),
			Details: diffs,
		}
	}

	return nil
}

func saveFailure(dir string, d das.V1Decision) error {

	decisionFile, err := os.Create(filepath.Join(dir, "decision.json"))
	if err != nil {
		return err
	}

	defer decisionFile.Close()

	enc := json.NewEncoder(decisionFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return err
	}

	inputFile, err := os.Create(filepath.Join(dir, "input.json"))
	if err != nil {
		return err
	}

	defer inputFile.Close()

	enc = json.NewEncoder(inputFile)
	enc.SetIndent("", "  ")
	if enc.Encode(d.Input) != nil {
		return err
	}

	return nil
}

type compareErr struct {
	Status  ReportStatus `json:"status"`
	Message string       `json:"message"`
}

func (e *compareErr) Error() string {
	return e.Message
}

func resultDiffErr(msg string) error {
	return &compareErr{Message: msg, Status: ReportStatusResultDiff}
}

func latencyInflationErr(msg string) error {
	return &compareErr{Message: msg, Status: ReportStatusLatencyInflation}
}

func compareResults(d *das.V1Decision, r *interface{}, t time.Duration, maxEvalInflation int) error {

	if d.Result == nil {
		if r != nil {
			return resultDiffErr("logged decision was undefined but bundle decision was not")
		}
		return nil
	}

	if r == nil {
		return resultDiffErr("logged decision was defined but bundle decision was not")
	}

	a, err := ast.InterfaceToValue(*r)
	if err != nil {
		return err
	}

	b, err := ast.InterfaceToValue(*d.Result)
	if err != nil {
		return err
	}

	if a.Compare(b) != 0 {

		aBytes, err := json.MarshalIndent(*r, "", "  ")
		if err != nil {
			return err
		}

		bBytes, err := json.MarshalIndent(*d.Result, "", "  ")
		if err != nil {
			return err
		}

		return resultDiffErr(textdiff.Unified("Expected", "Found", string(bBytes), string(aBytes)))
	}

	if maxEvalInflation >= 0 {
		if o := time.Duration(d.Metrics.TimerRegoQueryEvalNs); o*time.Duration(maxEvalInflation+100)/100 < t {
			return latencyInflationErr(fmt.Sprintf("bundle decision took over %d%% longer than original decision to evaluate", maxEvalInflation))
		}
	}

	return nil
}

// logger adapts logging.Logger to opa/v1/logging.Logger
type logger struct {
	logging.Logger
}

func (l *logger) Debug(fmt string, a ...any) {
	l.Logger.Debugf(fmt, a...)
}

func (l *logger) Info(fmt string, a ...any) {
	l.Logger.Infof(fmt, a...)
}

func (l *logger) Error(fmt string, a ...any) {
	l.Logger.Errorf(fmt, a...)
}

func (l *logger) Warn(fmt string, a ...any) {
	l.Logger.Warnf(fmt, a...)
}

func (*logger) GetLevel() v1.Level {
	return v1.Debug
}

func (*logger) SetLevel(_ v1.Level) {
	// no-op
}

func (l *logger) WithFields(_ map[string]any) v1.Logger {
	return l
}
