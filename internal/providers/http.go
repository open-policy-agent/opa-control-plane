package providers

import (
	"cmp"
	"context"
	"encoding/json"
	"path"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/httpsync"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// dataFile is the file a datasource's data is written to, within Dir.
const dataFile = "data.json"

func httpOpts(fields []string) []httpsync.HTTPSyncOption {
	if len(fields) == 0 {
		return nil
	}
	return []httpsync.HTTPSyncOption{httpsync.WithMetadataFields(fields)}
}

// HTTP provides an http datasource. ProviderParams.Config must be a
// config.Datasource; its data is written to data.json in Dir.
type HTTP struct{}

func (HTTP) Type() string                  { return TypeHTTP }
func (HTTP) ConfigSchema() json.RawMessage { return builtinSchema }

func (HTTP) Parse(json.RawMessage) (any, error) {
	return nil, errParse(TypeHTTP, "datasources")
}

func (HTTP) New(_ context.Context, p pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	ds, ok := p.Config.(config.Datasource)
	if !ok {
		return nil, errConfig(TypeHTTP, p.Config)
	}
	url, _ := ds.Config["url"].(string)
	method, _ := ds.Config["method"].(string)
	method = cmp.Or(method, "GET")
	body, _ := ds.Config["body"].(string)
	headers, _ := ds.Config["headers"].(map[string]any)

	return httpsync.New(path.Join(p.Dir, dataFile), url, method, body, headers, ds.Credentials, httpOpts(p.MetadataFields)...).
		WithSecretProvider(p.SecretProvider), nil
}

// S3 provides an s3 datasource. ProviderParams.Config must be a
// config.Datasource; its data is written to data.json in Dir.
type S3 struct{}

func (S3) Type() string                  { return TypeS3 }
func (S3) ConfigSchema() json.RawMessage { return builtinSchema }

func (S3) Parse(json.RawMessage) (any, error) {
	return nil, errParse(TypeS3, "datasources")
}

func (S3) New(_ context.Context, p pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	ds, ok := p.Config.(config.Datasource)
	if !ok {
		return nil, errConfig(TypeS3, p.Config)
	}
	bucket, _ := ds.Config["bucket"].(string)
	key, _ := ds.Config["key"].(string)
	region, _ := ds.Config["region"].(string)
	endpoint, _ := ds.Config["endpoint"].(string)
	region = cmp.Or(region, "us-east-1")

	var url string
	if endpoint != "" {
		url = endpoint + "/" + bucket + "/" + key
	} else {
		url = "https://" + bucket + ".s3." + region + ".amazonaws.com/" + key
	}

	return httpsync.NewS3(path.Join(p.Dir, dataFile), url, region, endpoint, ds.Credentials, httpOpts(p.MetadataFields)...), nil
}
