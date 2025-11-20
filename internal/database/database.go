package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/achille-roussel/sqlrange"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // database/sql compatible driver for pgx
	_ "modernc.org/sqlite"

	"github.com/open-policy-agent/opa-control-plane/internal/authz"
	"github.com/open-policy-agent/opa-control-plane/internal/aws"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/jsonpatch"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
)

const (
	sqlite = iota
	postgres
	mysql
)

const SQLiteMemoryOnlyDSN = "file::memory:?cache=shared"

// Database implements the database operations. It will hide any differences between the varying SQL databases from the rest of the codebase.
type Database struct {
	db     *sql.DB
	config *config.Database
	kind   int
	log    *logging.Logger
}

func (d *Database) DB() *sql.DB {
	return d.db
}

func (d *Database) Dialect() (string, error) {
	switch d.kind {
	case sqlite:
		return "sqlite", nil
	case postgres:
		return "postgresql", nil
	case mysql:
		return "mysql", nil
	default:
		return "", fmt.Errorf("unknown kind: %d", d.kind)
	}
}

type ListOptions struct {
	Limit  int
	Cursor string
	name   string
}

func (opts ListOptions) cursor() int64 {
	if opts.Cursor != "" {
		decoded, err := base64.URLEncoding.DecodeString(opts.Cursor)
		if err == nil {
			after, _ := strconv.ParseInt(string(decoded), 10, 64)
			return after
		}
	}
	return 0
}

func encodeCursor(id int64) string {
	cursor := strconv.FormatInt(id, 10)
	return base64.URLEncoding.EncodeToString([]byte(cursor))
}

func (d *Database) WithConfig(config *config.Database) *Database {
	d.config = config
	return d
}

func (d *Database) WithLogger(log *logging.Logger) *Database {
	d.log = log
	return d
}

func (d *Database) InitDB(ctx context.Context) error {
	var err error
	switch {
	case d.config != nil && d.config.AWSRDS != nil:
		// There are three options for authentication to Amazon RDS:
		//
		// 1. Using a secret of type "password". This requires the database user configured with the password.
		// 2. Using a secret of type "aws_auth". The secret stores the AWS credentials to use to authenticate to the database. The database
		//    has no password configured for the user.
		// 3. Using no secret at all. In this case, the AWS SDK will use the default credential provider chain to authenticate to the database. It proceeds
		//    the following in order:
		//    a) Environment variables.
		//    b) Shared credentials file.
		//    c) If your application uses an ECS task definition or RunTask API operation, IAM role for tasks.
		//    d) If your application is running on an Amazon EC2 instance, IAM role for Amazon EC2.
		//
		// In case of the second and third option, the SQL driver will use the AWS SDK to regenerate an authentication token for
		// the database user as necessary.

		c := d.config.AWSRDS
		drv := c.Driver
		endpoint := os.ExpandEnv(c.Endpoint)
		region := os.ExpandEnv(c.Region)
		dbUser := os.ExpandEnv(c.DatabaseUser)
		dbName := os.ExpandEnv(c.DatabaseName)
		dsn := os.ExpandEnv(c.DSN)
		rootCertificates := c.RootCertificates

		var authCallback func(context.Context) (string, error)

		if d.config.AWSRDS.Credentials != nil {
			// Authentication options 1 and 2:
			authCallback = func(ctx context.Context) (string, error) {
				value, err := d.config.AWSRDS.Credentials.Resolve(ctx)
				if err != nil {
					return "", err
				}

				var password string

				switch value := value.(type) {
				case config.SecretPassword:
					password = value.Password
					if password == "" {
						return "", fmt.Errorf("missing or invalid password value in secret %q", d.config.AWSRDS.Credentials.Name)
					}

				case config.SecretAWS:
					credentials := aws.NewSecretCredentialsProvider(d.config.AWSRDS.Credentials)
					password, err = auth.BuildAuthToken(ctx, endpoint, region, dbUser, credentials)
					if err != nil {
						return "", err
					}

				default:
					return "", fmt.Errorf("unsupported secret type '%T' for RDS credentials", value)
				}

				d.log.Debugf("Using a secret for RDS authentication at %s", endpoint)

				return password, nil
			}

		} else {
			// Authentication option 3: no explicit credentials configured, use AWS default credential provider chain.
			awsCfg, err := aws.Config(ctx, region, nil)
			if err != nil {
				return err
			}

			authCallback = func(ctx context.Context) (string, error) {
				return auth.BuildAuthToken(ctx, endpoint, region, dbUser, awsCfg.Credentials)
			}

			d.log.Debugf("Using AWS default credential provider chain for RDS authentication at %s", endpoint)
		}

		var connector driver.Connector
		var err error

		switch drv {
		case "postgres":
			drv = "pgx" // Convenience
			fallthrough
		case "pgx":
			dbHost, dbPort, found := strings.Cut(endpoint, ":")
			if !found {
				return fmt.Errorf("invalid endpoint format, expected host:port, got %s", endpoint)
			}

			port, err := strconv.Atoi(dbPort)
			if err != nil {
				return fmt.Errorf("invalid port in endpoint, expected host:port, got %s", endpoint)
			}

			if port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port number in endpoint, expected host:port, got %s", endpoint)
			}

			var cfg *pgx.ConnConfig
			if dsn != "" {
				cfg, err = pgx.ParseConfig(dsn)
				if err != nil {
					return err
				}

			} else {
				password, err := authCallback(ctx)
				if err != nil {
					return err
				}

				dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=require", dbHost, port, dbUser, password, dbName)
				cfg, err = pgx.ParseConfig(dsn)
				if err != nil {
					return err
				}
			}

			connector = stdlib.GetConnector(*cfg)
			d.kind = postgres

		case "mysql":
			tlsConfigName := "true"
			if rootCertificates != "" {
				rootCertPool := x509.NewCertPool()
				pem, err := os.ReadFile(rootCertificates)
				if err != nil {
					return err
				}

				if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
					return errors.New("failed to process X.509 root certificate PEM file")
				}

				if err := mysqldriver.RegisterTLSConfig("custom", &tls.Config{
					RootCAs:    rootCertPool,
					MinVersion: tls.VersionTLS12,
				}); err != nil {
					return err
				}
				tlsConfigName = "custom"
			}

			var cfg *mysqldriver.Config
			if dsn != "" {
				cfg, err = mysqldriver.ParseDSN(dsn)
				if err != nil {
					return err
				}
			} else {
				cfg = &mysqldriver.Config{
					User:                    dbUser,
					Net:                     "tcp",
					Addr:                    endpoint,
					DBName:                  dbName,
					AllowCleartextPasswords: true,
					AllowNativePasswords:    true,
					AllowOldPasswords:       true,
					TLSConfig:               tlsConfigName,
				}

				_ = cfg.Apply(mysqldriver.BeforeConnect(func(ctx context.Context, config *mysqldriver.Config) error {
					config.Passwd, err = authCallback(ctx)
					return err
				}))
			}

			connector, err = mysqldriver.NewConnector(cfg)
			if err != nil {
				return err
			}
			d.kind = mysql
		default:
			return fmt.Errorf("unsupported AWS RDS driver: %s", drv)
		}

		d.db = sql.OpenDB(connector)

		d.log.Debugf("Connected to %s RDS instance at %s", drv, endpoint)

	case d.config == nil:
		// Default to memory-only SQLite3 if no config is provided.
		fallthrough
	case d.config != nil && d.config.SQL != nil && (d.config.SQL.Driver == "sqlite3" || d.config.SQL.Driver == "sqlite"):
		var dsn string
		if d.config != nil && d.config.SQL != nil && d.config.SQL.DSN != "" {
			dsn = os.ExpandEnv(d.config.SQL.DSN)
		} else {
			dsn = SQLiteMemoryOnlyDSN
		}
		d.kind = sqlite
		d.db, err = sql.Open("sqlite", dsn)
		if err != nil {
			return err
		}
		if _, err := d.db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			return err
		}

	case d.config != nil && d.config.SQL != nil && (d.config.SQL.Driver == "postgres" || d.config.SQL.Driver == "pgx"):
		dsn := os.ExpandEnv(d.config.SQL.DSN)
		d.kind = postgres
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return err
		}
		cfg.TLSConfig, err = tlsConfig(ctx, d.config.SQL.Credentials, cfg.TLSConfig)
		if err != nil {
			return err
		}
		d.db = sql.OpenDB(stdlib.GetConnector(*cfg))

	case d.config != nil && d.config.SQL != nil && d.config.SQL.Driver == "mysql":
		dsn := os.ExpandEnv(d.config.SQL.DSN)
		d.kind = mysql
		cfg, err := mysqldriver.ParseDSN(dsn)
		if err != nil {
			return err
		}
		cfg.TLS, err = tlsConfig(ctx, d.config.SQL.Credentials, cfg.TLS)
		if err != nil {
			return err
		}
		conn, err := mysqldriver.NewConnector(cfg)
		if err != nil {
			return err
		}
		d.db = sql.OpenDB(conn)

	default:
		return errors.New("unsupported database connection type")
	}

	return nil
}

func tlsConfig(ctx context.Context, cred *config.SecretRef, dsn *tls.Config) (*tls.Config, error) {
	if cred == nil {
		return dsn, nil
	}

	value, err := cred.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	creds, ok := value.(config.SecretTLSCert)
	if !ok {
		return nil, fmt.Errorf("unsupported secret type '%T' for SQL credentials", value)
	}

	tc, err := creds.ToConfig(ctx)
	if err != nil {
		return nil, err
	}
	if dsn == nil {
		return tc, err
	}
	// Apply overrides from dsn: Root CA cert pool and "insecure skip verify" are taken from DSN,
	// client certs are merged.
	tc.InsecureSkipVerify = dsn.InsecureSkipVerify
	if len(dsn.Certificates) > 0 {
		tc.Certificates = append(dsn.Certificates, tc.Certificates...)
	}
	if dsn.RootCAs != nil {
		tc.RootCAs = dsn.RootCAs
	}

	return tc, nil
}

func (d *Database) CloseDB() {
	d.db.Close()
}

func (d *Database) SourcesDataGet(ctx context.Context, sourceName, path string, principal string) (any, bool, error) {
	path = filepath.ToSlash(path)
	return tx3(ctx, d, sourcesDataGet(ctx, d, sourceName, path, principal,
		func(bs []byte) (data any, err error) {
			return data, json.Unmarshal(bs, &data)
		}))
}

func (d *Database) SourcesDataPatch(ctx context.Context, sourceName, path string, principal string, patch jsonpatch.Patch) error {
	path = filepath.ToSlash(path)
	return tx1(ctx, d, func(tx *sql.Tx) error {
		previous, _, err := sourcesDataGet(ctx, d, sourceName, path, principal, func(bs []byte) ([]byte, error) { return bs, nil })(tx)
		if err != nil {
			return err
		}
		patched, err := jsonpatch.Apply(patch, previous)
		if err != nil {
			return err
		}
		return d.sourcesDataPut(ctx, sourceName, path, patched, principal)(tx)
	})
}

func sourcesDataGet[T any](ctx context.Context, d *Database, sourceName, path string, principal string,
	f func([]byte) (T, error),
) func(*sql.Tx) (T, bool, error) {
	return func(tx *sql.Tx) (T, bool, error) {
		var zero T
		if err := d.resourceExists(ctx, tx, "sources", sourceName); err != nil {
			return zero, false, err
		}

		expr, err := authz.Partial(ctx, authz.Access{
			Principal:  principal,
			Permission: "sources.data.read",
			Resource:   "sources",
			Name:       sourceName,
		}, nil)
		if err != nil {
			return zero, false, err
		}

		conditions, args := expr.SQL(d.arg, []any{sourceName, path})

		rows, err := tx.Query(fmt.Sprintf(`SELECT
	data
FROM
	sources_data
WHERE source_name = %s AND path = %s AND (`+conditions+")", d.arg(0), d.arg(1)), args...)
		if err != nil {
			return zero, false, err
		}
		defer rows.Close()

		if !rows.Next() {
			return zero, false, nil
		}

		var bs []byte
		if err := rows.Scan(&bs); err != nil {
			return zero, false, err
		}

		data, err := f(bs)
		if err != nil {
			return zero, false, err
		}
		return data, true, nil
	}
}

func (d *Database) SourcesDataPut(ctx context.Context, sourceName, path string, data any, principal string) error {
	path = filepath.ToSlash(path)
	return tx1(ctx, d, d.sourcesDataPut(ctx, sourceName, path, data, principal))
}

func (d *Database) sourcesDataPut(ctx context.Context, sourceName, path string, data any, principal string) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		if err := d.resourceExists(ctx, tx, "sources", sourceName); err != nil {
			return err
		}

		allowed := authz.Check(ctx, tx, d.arg, authz.Access{
			Principal:  principal,
			Permission: "sources.data.write",
			Resource:   "sources",
			Name:       sourceName,
		})
		if !allowed {
			return errors.New("unauthorized")
		}

		bs, err := json.Marshal(data)
		if err != nil {
			return err
		}

		return d.upsertRel(ctx, tx, "sources_data", []string{"source_name", "path", "data"}, []string{"source_name", "path"}, sourceName, path, bs)
	}
}

func (d *Database) SourcesDataDelete(ctx context.Context, sourceName, path string, principal string) error {
	path = filepath.ToSlash(path)
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.resourceExists(ctx, tx, "sources", sourceName); err != nil {
			return err
		}

		expr, err := authz.Partial(ctx, authz.Access{
			Principal:  principal,
			Permission: "sources.data.write",
			Resource:   "sources",
			Name:       sourceName,
		}, nil)
		if err != nil {
			return err
		}

		conditions, args := expr.SQL(d.arg, []any{sourceName, path})

		_, err = tx.Exec(fmt.Sprintf(`DELETE FROM sources_data WHERE source_name = %s AND path = %s AND (`+conditions+")", d.arg(0), d.arg(1)), args...)
		return err
	})
}

// LoadConfig loads the configuration from the configuration file into the database.
// Env vars for values are getting resolved at this point. We don't store "${ADMIN_TOKEN}"
// in the DB, but lookup the current field. Failing lookups are treated as errors!
// Secrets are the exception: they are stored as-is, so if their value refers to an
// env var, it's replaced on use.
func (d *Database) LoadConfig(ctx context.Context, bar *progress.Bar, principal string, root *config.Root) error {

	bar.AddMax(len(root.Sources) + len(root.Stacks) + len(root.Secrets) + len(root.Tokens))

	// Secrets have env lookups done on access, without the secret value persisted in the databse.
	for _, secret := range root.SortedSecrets() {
		if root.Database != nil && root.Database.SQL != nil && root.Database.SQL.Credentials != nil {
			// check if this secret is used for the database, omit it if true
			if secret.Ref().Equal(root.Database.SQL.Credentials) {
				continue
			}
		}
		if err := d.UpsertSecret(ctx, principal, secret); err != nil {
			return fmt.Errorf("upsert secret %q failed: %w", secret.Name, err)
		}
		bar.Add(1)
	}

	sources, err := root.TopologicalSortedSources()
	if err != nil {
		return err
	}

	for _, src := range sources {
		for i, ds := range src.Datasources {
			if ds.Config != nil {
				replaced := make(map[string]any, len(ds.Config))
				for k, v := range ds.Config {
					switch v0 := v.(type) {
					case string:
						v = os.ExpandEnv(v0)
					default:
						v = v0
					}
					replaced[k] = v
				}
				src.Datasources[i].Config = replaced
			}
		}
		if err := d.UpsertSource(ctx, principal, src); err != nil {
			return fmt.Errorf("upsert source %q failed: %w", src.Name, err)
		}
		bar.Add(1)
	}

	for _, b := range root.SortedBundles() {
		if err := d.UpsertBundle(ctx, principal, b); err != nil {
			return fmt.Errorf("upsert bundle %q failed: %w", b.Name, err)
		}
		bar.Add(1)
	}

	for _, stack := range root.SortedStacks() {
		if err := d.UpsertStack(ctx, principal, stack); err != nil {
			return fmt.Errorf("upsert stack %q failed: %w", stack.Name, err)
		}
		bar.Add(1)
	}
	for _, token := range root.Tokens {
		if token.APIKey == "" {
			return fmt.Errorf("token %q: no API key", token.Name)
		}
		token.APIKey = os.ExpandEnv(token.APIKey)
		if token.APIKey == "" {
			return fmt.Errorf("token %q: no API key (after env expansion)", token.Name)
		}
		if err := d.UpsertToken(ctx, principal, token); err != nil {
			return fmt.Errorf("upsert token %q failed: %w", token.Name, err)
		}
		bar.Add(1)
	}

	return nil
}

func (d *Database) GetBundle(ctx context.Context, principal string, name string) (*config.Bundle, error) {
	bundles, _, err := d.ListBundles(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(bundles) == 0 {
		return nil, ErrNotFound
	}

	return bundles[0], nil
}

func (d *Database) DeleteBundle(ctx context.Context, principal string, name string) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareDelete(ctx, tx, principal, "bundles", name, "bundles.manage"); err != nil {
			return err
		}
		id, err := d.lookupID(ctx, tx, "bundles", name)
		if err != nil {
			return fmt.Errorf("lookup bundle %s: %w", name, err)
		}
		if err := d.delete(ctx, tx, "bundles_secrets", "bundle_id", id); err != nil {
			return err
		}
		if err := d.delete(ctx, tx, "bundles_requirements", "bundle_id", id); err != nil {
			return err
		}
		return d.delete(ctx, tx, "bundles", "id", id)
	})
}

func (d *Database) ListBundles(ctx context.Context, principal string, opts ListOptions) ([]*config.Bundle, string, error) {
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.Bundle, string, error) {
		expr, err := authz.Partial(ctx, authz.Access{
			Principal:  principal,
			Resource:   "bundles",
			Permission: "bundles.view",
		}, map[string]authz.ColumnRef{
			"input.name": {Table: "bundles", Column: "name"},
		})
		if err != nil {
			return nil, "", err
		}

		conditions, args := expr.SQL(d.arg, nil)

		// Building the query, we'll first deal with the `bundles` table:
		// 1. apply conditions
		// 2. deal with pagination
		// and _then_ join whatever extra information we need
		bundles := `SELECT
		bundles.id,
		bundles.name,
		bundles.labels,
		bundles.s3url,
		bundles.s3region,
		bundles.s3bucket,
		bundles.s3key,
		bundles.gcp_project,
		bundles.gcp_object,
		bundles.azure_account_url,
		bundles.azure_container,
		bundles.azure_path,
		bundles.filepath,
		bundles.excluded,
 		bundles.rebuild_interval,
		bundles.options
FROM bundles
WHERE (` + conditions + ")"

		if opts.name != "" {
			bundles += fmt.Sprintf(" AND (bundles.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			bundles += fmt.Sprintf(" AND (bundles.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		bundles += " ORDER BY bundles.id"
		if opts.Limit > 0 {
			bundles += " LIMIT " + d.arg(len(args))
			args = append(args, opts.Limit)
		}

		query := fmt.Sprintf(`SELECT
		bundles.*,
		secrets.name AS secret_name,
		secrets.value AS secret_value,
		sources.name AS req_src,
		bundles_requirements.path AS req_path,
		bundles_requirements.prefix AS req_prefix,
		bundles_requirements.gitcommit AS req_commit
FROM (%s) AS bundles
LEFT JOIN
    bundles_secrets ON bundles.id = bundles_secrets.bundle_id
LEFT JOIN
    secrets ON bundles_secrets.secret_id = secrets.id
LEFT JOIN
	bundles_requirements ON bundles.id = bundles_requirements.bundle_id
LEFT JOIN
    sources ON bundles_requirements.source_id = sources.id
`, bundles)

		rows, err := txn.Query(query, args...)
		if err != nil {
			return nil, "", err
		}
		defer rows.Close()

		type bundleRow struct {
			id                                         int64
			bundleName                                 string
			labels                                     *string
			s3url, s3region, s3bucket, s3key           *string // S3 object storage
			gcpProject, gcpObject                      *string // GCP object storage
			azureAccountURL, azureContainer, azurePath *string // Azure object storage
			filepath                                   *string // File system storage
			excluded                                   *string
			interval                                   *string
			options                                    *string
			secretName, secretValue                    *string
			reqSrc, reqCommit                          *string
			reqPath, reqPrefix                         sql.Null[string]
		}
		bundleMap := make(map[string]*config.Bundle)
		idMap := make(map[string]int64)
		var lastId int64

		for rows.Next() {
			var row bundleRow
			if err := rows.Scan(&row.id, &row.bundleName, &row.labels,
				&row.s3url, &row.s3region, &row.s3bucket, &row.s3key, // S3
				&row.gcpProject, &row.gcpObject, // GCP
				&row.azureAccountURL, &row.azureContainer, &row.azurePath, // Azure
				&row.filepath,
				&row.excluded,
				&row.interval,
				&row.options,
				&row.secretName, &row.secretValue,
				&row.reqSrc, &row.reqPath, &row.reqPrefix, &row.reqCommit); err != nil {
				return nil, "", err
			}

			var s *config.Secret
			if row.secretName != nil {
				s = &config.Secret{Name: *row.secretName}
				if err := json.Unmarshal([]byte(*row.secretValue), &s.Value); err != nil {
					return nil, "", err
				}
			}

			bundle, exists := bundleMap[row.bundleName]
			if !exists {
				bundle = &config.Bundle{
					Name: row.bundleName,
				}

				if row.labels != nil {
					if err := json.Unmarshal([]byte(*row.labels), &bundle.Labels); err != nil {
						return nil, "", fmt.Errorf("failed to unmarshal labels for %q: %w", bundle.Name, err)
					}
				}
				if row.options != nil {
					if err := json.Unmarshal([]byte(*row.options), &bundle.Options); err != nil {
						return nil, "", fmt.Errorf("failed to unmarshal options for %q: %w", bundle.Name, err)
					}
				}

				bundleMap[row.bundleName] = bundle
				idMap[row.bundleName] = row.id

				if row.s3region != nil && row.s3bucket != nil && row.s3key != nil {
					bundle.ObjectStorage.AmazonS3 = &config.AmazonS3{
						Region: *row.s3region,
						Bucket: *row.s3bucket,
						Key:    *row.s3key,
					}
					if row.s3url != nil {
						bundle.ObjectStorage.AmazonS3.URL = *row.s3url
					}

					if s != nil {
						bundle.ObjectStorage.AmazonS3.Credentials = s.Ref()
					}

				} else if row.gcpProject != nil && row.s3bucket != nil && row.gcpObject != nil {
					bundle.ObjectStorage.GCPCloudStorage = &config.GCPCloudStorage{
						Project: *row.gcpProject,
						Bucket:  *row.s3bucket,
						Object:  *row.gcpObject,
					}

					if s != nil {
						bundle.ObjectStorage.GCPCloudStorage.Credentials = s.Ref()
					}

				} else if row.azureAccountURL != nil && row.azureContainer != nil && row.azurePath != nil {
					bundle.ObjectStorage.AzureBlobStorage = &config.AzureBlobStorage{
						AccountURL: *row.azureAccountURL,
						Container:  *row.azureContainer,
						Path:       *row.azurePath,
					}

					if s != nil {
						bundle.ObjectStorage.AzureBlobStorage.Credentials = s.Ref()
					}

				} else if row.filepath != nil {
					bundle.ObjectStorage.FileSystemStorage = &config.FileSystemStorage{
						Path: *row.filepath,
					}
				}

				if row.excluded != nil {
					if err := json.Unmarshal([]byte(*row.excluded), &bundle.ExcludedFiles); err != nil {
						return nil, "", fmt.Errorf("failed to unmarshal excluded files for %q: %w", bundle.Name, err)
					}
				}

				if row.interval != nil {
					dur, err := time.ParseDuration(*row.interval)
					if err != nil {
						return nil, "", fmt.Errorf("invalid duration %s: %w", *row.interval, err)
					}
					bundle.Interval = config.Duration(dur)
				}
			}

			if row.reqSrc != nil {
				bundle.Requirements = append(bundle.Requirements, config.Requirement{
					Source: row.reqSrc,
					Git:    config.GitRequirement{Commit: row.reqCommit},
					Path:   row.reqPath.V, // if null, use ""
					Prefix: row.reqPrefix.V,
				})
			}

			if row.id > lastId {
				lastId = row.id
			}
		}
		if err := rows.Err(); err != nil {
			return nil, "", err
		}

		sl := slices.Collect(maps.Values(bundleMap))
		sort.Slice(sl, func(i, j int) bool {
			return idMap[sl[i].Name] < idMap[sl[j].Name]
		})

		var nextCursor string
		if opts.Limit > 0 && len(sl) == opts.Limit {
			nextCursor = encodeCursor(lastId)
		}

		return sl, nextCursor, nil
	})
}

func (d *Database) GetSource(ctx context.Context, principal string, name string) (*config.Source, error) {
	sources, _, err := d.ListSources(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(sources) == 0 {
		return nil, ErrNotFound
	}

	return sources[0], nil
}

func (d *Database) DeleteSource(ctx context.Context, principal string, name string) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareDelete(ctx, tx, principal, "sources", name, "sources.manage"); err != nil {
			return err
		}
		id, err := d.lookupID(ctx, tx, "sources", name)
		if err != nil {
			return fmt.Errorf("lookup source %s: %w", name, err)
		}

		// NB(sr): We do not clean out stacks_requirements and bundles_requirements:
		// that'll ensure that only unused sources can be deleted.
		if err := d.delete(ctx, tx, "sources_datasources", "source_id", id); err != nil {
			return err
		}
		if err := d.delete(ctx, tx, "sources_secrets", "source_id", id); err != nil {
			return err
		}
		if err := d.delete(ctx, tx, "sources_requirements", "source_id", id); err != nil {
			return err
		}
		if err := d.delete(ctx, tx, "sources_data", "source_id", id); err != nil {
			return err
		}
		return d.delete(ctx, tx, "sources", "id", id)
	})
}

// ListSources returns a list of sources in the database. Note it does not return the source data.
func (d *Database) ListSources(ctx context.Context, principal string, opts ListOptions) ([]*config.Source, string, error) {
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.Source, string, error) {
		expr, err := authz.Partial(ctx, authz.Access{
			Principal:  principal,
			Resource:   "sources",
			Permission: "sources.view",
		}, map[string]authz.ColumnRef{
			"input.name": {Table: "sources", Column: "name"},
		})
		if err != nil {
			return nil, "", err
		}

		conditions, args := expr.SQL(d.arg, nil)

		sources := `SELECT
	sources.id,
	sources.name,
	sources.builtin,
	sources.repo,
	sources.ref,
	sources.gitcommit,
	sources.path,
	sources.git_included_files,
	sources.git_excluded_files
FROM sources
WHERE (` + conditions + ")"

		if opts.name != "" {
			sources += fmt.Sprintf(" AND (sources.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			sources += fmt.Sprintf(" AND (sources.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		sources += " ORDER BY sources.id"
		if opts.Limit > 0 {
			sources += " LIMIT " + d.arg(len(args))
			args = append(args, opts.Limit)
		}

		query := fmt.Sprintf(`SELECT
	sources.*,
	secrets.name AS secret_name,
	sources_secrets.ref_type AS secret_ref_type,
	secrets.value AS secret_value,
	required_sources.name,
	sources_requirements.gitcommit,
	sources_requirements.path AS req_path,
	sources_requirements.prefix AS req_prefix
FROM (%s) AS sources
LEFT JOIN
	sources_secrets ON sources.id = sources_secrets.source_id
LEFT JOIN
	secrets ON sources_secrets.secret_id = secrets.id
LEFT JOIN
	sources_requirements ON sources.id = sources_requirements.source_id
LEFT JOIN
    sources AS required_sources ON sources.id = sources_requirements.requirement_id
WHERE (sources_secrets.ref_type = 'git_credentials' OR sources_secrets.ref_type IS NULL)
`, sources)

		rows, err := txn.Query(query, args...)
		if err != nil {
			return nil, "", err
		}
		defer rows.Close()

		type sourceRow struct {
			id                                               int64
			sourceName                                       string
			builtin                                          *string
			repo                                             string
			ref, gitCommit, path, includePaths, excludePaths *string
			secretName, secretRefType, secretValue           *string
			requirementName, requirementCommit               *string
			reqPath, reqPrefix                               sql.Null[string]
		}

		srcMap := make(map[string]*config.Source)
		idMap := make(map[string]int64)
		var last int64

		for rows.Next() {
			var row sourceRow
			if err := rows.Scan(&row.id, &row.sourceName, &row.builtin, &row.repo, &row.ref, &row.gitCommit, &row.path, &row.includePaths, &row.excludePaths, &row.secretName, &row.secretRefType, &row.secretValue, &row.requirementName, &row.requirementCommit, &row.reqPath, &row.reqPrefix); err != nil {
				return nil, "", err
			}

			src, exists := srcMap[row.sourceName]
			if !exists {
				src = &config.Source{
					Name:    row.sourceName,
					Builtin: row.builtin,
					Git: config.Git{
						Repo: row.repo,
					},
				}
				srcMap[row.sourceName] = src
				idMap[row.sourceName] = row.id

				if row.ref != nil {
					src.Git.Reference = row.ref
				}
				if row.gitCommit != nil {
					src.Git.Commit = row.gitCommit
				}
				if row.path != nil {
					src.Git.Path = row.path
				}
				if row.includePaths != nil {
					if err := json.Unmarshal([]byte(*row.includePaths), &src.Git.IncludedFiles); err != nil {
						return nil, "", fmt.Errorf("failed to unmarshal include paths for %q: %w", src.Name, err)
					}
				}
				if row.excludePaths != nil {
					if err := json.Unmarshal([]byte(*row.excludePaths), &src.Git.ExcludedFiles); err != nil {
						return nil, "", fmt.Errorf("failed to unmarshal exclude paths for %q: %w", src.Name, err)
					}
				}
			}

			if row.secretRefType != nil && *row.secretRefType == "git_credentials" && row.secretName != nil {
				s := config.Secret{Name: *row.secretName}
				if row.secretValue != nil {
					if err := json.Unmarshal([]byte(*row.secretValue), &s.Value); err != nil {
						return nil, "", err
					}
				}
				src.Git.Credentials = s.Ref()
			}

			if row.requirementName != nil {
				src.Requirements = append(src.Requirements, config.Requirement{
					Source: row.requirementName,
					Git:    config.GitRequirement{Commit: row.requirementCommit},
					Path:   row.reqPath.V,
					Prefix: row.reqPrefix.V,
				})
			}

			if row.id > last {
				last = row.id
			}
		}
		if err := rows.Err(); err != nil {
			return nil, "", err
		}

		// Load datasources for each source.

		rows2, err := txn.Query(`SELECT
		sources_datasources.name,
		sources.name,
		sources_datasources.path,
		sources_datasources.type,
		sources_datasources.config,
		sources_datasources.transform_query,
	    secrets.name,
	    secrets.value AS secret_value
	FROM
		sources_datasources
	LEFT JOIN
		secrets ON sources_datasources.secret_id = secrets.id
	LEFT JOIN
		sources ON sources_datasources.source_id = sources.id
	`)
		if err != nil {
			return nil, "", err
		}

		defer rows2.Close()

		for rows2.Next() {
			var name, source_name, path, type_, configuration, transformQuery string
			var secretName, secretValue sql.NullString
			if err := rows2.Scan(&name, &source_name, &path, &type_, &configuration, &transformQuery, &secretName, &secretValue); err != nil {
				return nil, "", err
			}

			datasource := config.Datasource{
				Name:           name,
				Type:           type_,
				Path:           path,
				TransformQuery: transformQuery,
			}

			if err := json.Unmarshal([]byte(configuration), &datasource.Config); err != nil {
				return nil, "", err
			}

			if secretName.Valid && secretValue.Valid {
				s := config.Secret{Name: secretName.String}
				if err := json.Unmarshal([]byte(secretValue.String), &s.Value); err != nil {
					return nil, "", err
				}
				datasource.Credentials = s.Ref()
			}

			src, ok := srcMap[source_name]
			if ok {
				src.Datasources = append(src.Datasources, datasource)
			}
		}
		if err := rows2.Err(); err != nil {
			return nil, "", err
		}

		sl := slices.Collect(maps.Values(srcMap))
		sort.Slice(sl, func(i, j int) bool {
			return idMap[sl[i].Name] < idMap[sl[j].Name]
		})

		var nextCursor string
		if opts.Limit > 0 && len(sl) == opts.Limit {
			cursor := strconv.FormatInt(last, 10)
			nextCursor = base64.URLEncoding.EncodeToString([]byte(cursor))
		}

		return sl, nextCursor, nil
	})
}

func (d *Database) GetSecret(ctx context.Context, principal string, name string) (*config.SecretRef, error) {
	secrets, _, err := d.ListSecrets(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(secrets) == 0 {
		return nil, ErrNotFound
	}

	return secrets[0], nil
}

func (d *Database) DeleteSecret(ctx context.Context, principal string, name string) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareDelete(ctx, tx, principal, "secrets", name, "secrets.manage"); err != nil {
			return err
		}

		id, err := d.lookupID(ctx, tx, "secrets", name)
		if err != nil {
			return fmt.Errorf("lookup secret %s: %w", name, err)
		}
		return d.delete(ctx, tx, "secrets", "id", id)
	})
}

func (d *Database) ListSecrets(ctx context.Context, principal string, opts ListOptions) ([]*config.SecretRef, string, error) {
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.SecretRef, string, error) {
		expr, err := authz.Partial(ctx, authz.Access{
			Principal:  principal,
			Resource:   "secrets",
			Permission: "secrets.view",
		}, map[string]authz.ColumnRef{
			"input.name": {Table: "secrets", Column: "name"},
		})
		if err != nil {
			return nil, "", err
		}

		conditions, args := expr.SQL(d.arg, nil)
		query := `SELECT
        secrets.id,
        secrets.name
    FROM
        secrets
    WHERE (` + conditions + ")"

		if opts.name != "" {
			query += fmt.Sprintf(" AND (secrets.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			query += fmt.Sprintf(" AND (secrets.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		query += " ORDER BY secrets.id"
		if opts.Limit > 0 {
			query += " LIMIT " + d.arg(len(args))
			args = append(args, opts.Limit)
		}

		rows, err := txn.Query(query, args...)
		if err != nil {
			return nil, "", err
		}
		defer rows.Close()

		type secretRow struct {
			id   int64
			name string
		}

		var sl []*config.SecretRef
		var lastId int64
		for rows.Next() {
			var row secretRow
			if err := rows.Scan(&row.id, &row.name); err != nil {
				return nil, "", err
			}
			if row.id > lastId {
				lastId = row.id
			}
			sl = append(sl, &config.SecretRef{Name: row.name})
		}
		if err := rows.Err(); err != nil {
			return nil, "", err
		}

		var nextCursor string
		if opts.Limit > 0 && len(sl) == opts.Limit {
			nextCursor = encodeCursor(lastId)
		}
		return sl, nextCursor, nil
	})
}

func (d *Database) GetStack(ctx context.Context, principal string, name string) (*config.Stack, error) {
	stacks, _, err := d.ListStacks(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(stacks) == 0 {
		return nil, ErrNotFound
	}

	return stacks[0], nil
}

func (d *Database) DeleteStack(ctx context.Context, principal string, name string) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareDelete(ctx, tx, principal, "stacks", name, "stacks.manage"); err != nil {
			return err
		}
		id, err := d.lookupID(ctx, tx, "stacks", name)
		if err != nil {
			return fmt.Errorf("lookup stack %s: %w", name, err)
		}

		if err := d.delete(ctx, tx, "stacks_requirements", "stack_id", id); err != nil {
			return err
		}
		return d.delete(ctx, tx, "stacks", "id", id)
	})
}

func (d *Database) ListStacks(ctx context.Context, principal string, opts ListOptions) ([]*config.Stack, string, error) {
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.Stack, string, error) {
		expr, err := authz.Partial(ctx, authz.Access{
			Principal:  principal,
			Resource:   "stacks",
			Permission: "stacks.view",
		}, map[string]authz.ColumnRef{
			"input.name": {Table: "stacks", Column: "name"},
		})
		if err != nil {
			return nil, "", err
		}

		conditions, args := expr.SQL(d.arg, nil)
		stacks := `SELECT
	stacks.id,
	stacks.name,
	stacks.selector,
	stacks.exclude_selector
FROM stacks
WHERE (` + conditions + ")"

		if opts.name != "" {
			stacks += fmt.Sprintf(" AND (stacks.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			stacks += fmt.Sprintf(" AND (stacks.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		stacks += " ORDER BY stacks.id"
		if opts.Limit > 0 {
			stacks += " LIMIT " + d.arg(len(args))
			args = append(args, opts.Limit)
		}

		query := fmt.Sprintf(`SELECT
    stacks.*,
	sources.name,
	stacks_requirements.gitcommit,
	stacks_requirements.path AS req_path,
	stacks_requirements.prefix AS req_prefix
FROM (%s) AS stacks
LEFT JOIN
	stacks_requirements ON stacks.id = stacks_requirements.stack_id
LEFT JOIN
	sources ON sources.id = stacks_requirements.source_id
`, stacks)
		rows, err := txn.Query(query, args...)
		if err != nil {
			return nil, "", err
		}
		defer rows.Close()

		type stackRow struct {
			id                       int64
			stackName                string
			selector                 string
			excludeSelector          *string
			sourceName, sourceCommit *string
			path, prefix             sql.Null[string]
		}

		stacksMap := map[string]*config.Stack{}
		idMap := map[string]int64{}
		var lastId int64

		for rows.Next() {
			var row stackRow
			if err := rows.Scan(&row.id, &row.stackName, &row.selector, &row.excludeSelector, &row.sourceName, &row.sourceCommit, &row.path, &row.prefix); err != nil {
				return nil, "", err
			}

			var selector config.Selector
			if err := json.Unmarshal([]byte(row.selector), &selector); err != nil {
				return nil, "", err
			}

			stack, ok := stacksMap[row.stackName]
			if !ok {
				stack = &config.Stack{
					Name:     row.stackName,
					Selector: selector,
				}
				if row.excludeSelector != nil {
					var excludeSelector config.Selector
					if err := json.Unmarshal([]byte(*row.excludeSelector), &excludeSelector); err != nil {
						return nil, "", err
					}
					stack.ExcludeSelector = &excludeSelector
				}
				stacksMap[row.stackName] = stack
				idMap[row.stackName] = row.id
			}

			if row.sourceName != nil {
				stack.Requirements = append(stack.Requirements, config.Requirement{
					Source: row.sourceName,
					Git:    config.GitRequirement{Commit: row.sourceCommit},
					Path:   row.path.V,
					Prefix: row.prefix.V,
				})
			}

			if row.id > lastId {
				lastId = row.id
			}
		}
		if err := rows.Err(); err != nil {
			return nil, "", err
		}

		sl := slices.Collect(maps.Values(stacksMap))
		sort.Slice(sl, func(i, j int) bool {
			return idMap[sl[i].Name] < idMap[sl[j].Name]
		})

		var nextCursor string
		if opts.Limit > 0 && len(sl) == opts.Limit {
			nextCursor = encodeCursor(lastId)
		}

		return sl, nextCursor, nil
	})
}

type Data struct {
	Path string `sql:"path"`
	Data []byte `sql:"data"`
}

func (d *Database) QuerySourceData(sourceName string) func(context.Context) iter.Seq2[Data, error] {
	return func(ctx context.Context) iter.Seq2[Data, error] {
		return sqlrange.QueryContext[Data](ctx,
			d.db,
			`SELECT path, data FROM sources_data WHERE source_name = `+d.arg(0),
			sourceName)
	}
}

func (d *Database) UpsertBundle(ctx context.Context, principal string, bundle *config.Bundle) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "bundles", bundle.Name, "bundles.create", "bundles.manage"); err != nil {
			return err
		}

		var s3url, s3region, s3bucket, s3key, gcpProject, gcpObject, azureAccountURL, azureContainer, azurePath, filepath *string
		if bundle.ObjectStorage.AmazonS3 != nil {
			s3url = &bundle.ObjectStorage.AmazonS3.URL
			s3region = &bundle.ObjectStorage.AmazonS3.Region
			s3bucket = &bundle.ObjectStorage.AmazonS3.Bucket
			s3key = &bundle.ObjectStorage.AmazonS3.Key
		}
		if bundle.ObjectStorage.GCPCloudStorage != nil {
			gcpProject = &bundle.ObjectStorage.GCPCloudStorage.Project
			s3bucket = &bundle.ObjectStorage.GCPCloudStorage.Bucket
			gcpObject = &bundle.ObjectStorage.GCPCloudStorage.Object
		}
		if bundle.ObjectStorage.AzureBlobStorage != nil {
			azureAccountURL = &bundle.ObjectStorage.AzureBlobStorage.AccountURL
			azureContainer = &bundle.ObjectStorage.AzureBlobStorage.Container
			azurePath = &bundle.ObjectStorage.AzureBlobStorage.Path
		}
		if bundle.ObjectStorage.FileSystemStorage != nil {
			filepath = &bundle.ObjectStorage.FileSystemStorage.Path
		}

		labels, err := json.Marshal(bundle.Labels)
		if err != nil {
			return err
		}

		excluded, err := json.Marshal(bundle.ExcludedFiles)
		if err != nil {
			return err
		}
		var options []byte
		if !bundle.Options.Empty() {
			options, err = json.Marshal(bundle.Options)
			if err != nil {
				return err
			}
		}

		id, err := d.upsert(ctx, tx, "bundles", []string{"name", "labels",
			"s3url", "s3region", "s3bucket", "s3key",
			"gcp_project", "gcp_object",
			"azure_account_url", "azure_container", "azure_path",
			"filepath", "excluded",
			"rebuild_interval", "options"}, []string{"name"},
			bundle.Name, string(labels),
			s3url, s3region, s3bucket, s3key,
			gcpProject, gcpObject,
			azureAccountURL, azureContainer, azurePath,
			filepath, string(excluded), bundle.Interval.String(),
			options)
		if err != nil {
			return err
		}

		if bundle.ObjectStorage.AmazonS3 != nil {
			if cred := bundle.ObjectStorage.AmazonS3.Credentials; cred != nil {
				secretID, err := d.lookupID(ctx, tx, "secrets", cred.Name)
				if err != nil {
					return fmt.Errorf("lookup id of secret %s: %w", cred.Name, err)
				}
				if err := d.upsertRel(ctx, tx, "bundles_secrets", []string{"bundle_id", "secret_id", "ref_type"}, []string{"bundle_id", "secret_id"},
					id, secretID, "aws"); err != nil {
					return fmt.Errorf("table bundles_secrets: %w", err)
				}
			}
		}

		if bundle.ObjectStorage.GCPCloudStorage != nil {
			if cred := bundle.ObjectStorage.GCPCloudStorage.Credentials; cred != nil {
				secretID, err := d.lookupID(ctx, tx, "secrets", cred.Name)
				if err != nil {
					return fmt.Errorf("lookup id of secret %s: %w", cred.Name, err)
				}
				if err := d.upsertRel(ctx, tx, "bundles_secrets", []string{"bundle_id", "secret_id", "ref_type"}, []string{"bundle_id", "secret_id"},
					id, secretID, "gcp"); err != nil {
					return fmt.Errorf("table bundles_secrets: %w", err)
				}
			}
		}

		if bundle.ObjectStorage.AzureBlobStorage != nil {
			if cred := bundle.ObjectStorage.AzureBlobStorage.Credentials; cred != nil {
				secretID, err := d.lookupID(ctx, tx, "secrets", cred.Name)
				if err != nil {
					return fmt.Errorf("lookup id of secret %s: %w", cred.Name, err)
				}
				if err := d.upsertRel(ctx, tx, "bundles_secrets", []string{"bundle_id", "secret_id", "ref_type"}, []string{"bundle_id", "secret_id"},
					id, secretID, "azure"); err != nil {
					return fmt.Errorf("table bundles_secrets: %w", err)
				}
			}
		}

		sources := make([]int, 0, len(bundle.Requirements))
		for _, req := range bundle.Requirements {
			if req.Source != nil {
				reqID, err := d.lookupID(ctx, tx, "sources", *req.Source)
				if err != nil {
					return fmt.Errorf("lookup id of requirement source %s: %w", *req.Source, err)
				}
				if err := d.upsertRel(ctx, tx, "bundles_requirements", []string{"bundle_id", "source_id", "gitcommit", "path", "prefix"}, []string{"bundle_id", "source_id"},
					id, reqID, req.Git.Commit, req.Path, req.Prefix); err != nil {
					return fmt.Errorf("table bundles_requirements: %w", err)
				}
				sources = append(sources, reqID)
			}
		}
		if bundle.Requirements != nil {
			if err := d.deleteNotIn(ctx, tx, "bundles_requirements", "bundle_id", id, "source_id", sources); err != nil {
				return fmt.Errorf("table bundles_requirements (delete): %w", err)
			}
		}

		return nil
	})
}

func (d *Database) UpsertSource(ctx context.Context, principal string, source *config.Source) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "sources", source.Name, "sources.create", "sources.manage"); err != nil {
			return err
		}

		includedFiles, err := json.Marshal(source.Git.IncludedFiles)
		if err != nil {
			return err
		}

		excludedFiles, err := json.Marshal(source.Git.ExcludedFiles)
		if err != nil {
			return err
		}

		id, err := d.upsert(ctx, tx, "sources", []string{"name", "builtin", "repo", "ref", "gitcommit", "path", "git_included_files", "git_excluded_files"}, []string{"name"},
			source.Name, source.Builtin, source.Git.Repo, source.Git.Reference, source.Git.Commit, source.Git.Path, string(includedFiles), string(excludedFiles))
		if err != nil {
			return err
		}

		if source.Git.Credentials != nil {
			secretID, err := d.lookupID(ctx, tx, "secrets", source.Git.Credentials.Name)
			if err != nil {
				return fmt.Errorf("lookup id of secret %s: %w", source.Git.Credentials.Name, err)
			}
			if err := d.upsertRel(ctx, tx, "sources_secrets", []string{"source_id", "secret_id", "ref_type"}, []string{"source_id", "secret_id"},
				id, secretID, "git_credentials"); err != nil {
				return fmt.Errorf("upsert of secret link %s: %w", source.Git.Credentials.Name, err)
			}
		}

		// Upsert data sources
		for _, datasource := range source.Datasources {
			bs, err := json.Marshal(datasource.Config)
			if err != nil {
				return err
			}

			var secret sql.NullInt64
			if datasource.Credentials != nil {
				secretID, err := d.lookupID(ctx, tx, "secrets", datasource.Credentials.Name)
				if err != nil {
					return err
				}
				secret.Int64, secret.Valid = int64(secretID), true
			}
			if err := d.upsertRel(ctx, tx, "sources_datasources", []string{"source_id", "name", "type", "path", "config", "transform_query", "secret_id"},
				[]string{"source_id", "name"},
				id, datasource.Name, datasource.Type, datasource.Path, string(bs), datasource.TransformQuery, secret); err != nil {
				return fmt.Errorf("upsert of datasource link %s: %w", datasource.Name, err)
			}
		}

		// Upsert files
		files, err := source.Files()
		if err != nil {
			return err
		}

		for path, data := range files {
			if _, err := d.upsert(ctx, tx, "sources_data", []string{"source_id", "path", "data"}, []string{"source_id", "path"}, id, path, []byte(data)); err != nil {
				return err
			}
		}

		// Upsert requirements
		var sources []int
		for _, r := range source.Requirements {
			if r.Source != nil {
				reqID, err := d.lookupID(ctx, tx, "sources", *r.Source)
				if err != nil {
					return fmt.Errorf("lookup id of requirement source %s: %w", *r.Source, err)
				}
				if err := d.upsertRel(ctx, tx, "sources_requirements", []string{"source_id", "requirement_id", "gitcommit", "path", "prefix"},
					[]string{"source_id", "requirement_id"},
					id, reqID, r.Git.Commit, r.Path, r.Prefix,
				); err != nil {
					return fmt.Errorf("upsert of requirement source link %s: %w", *r.Source, err)
				}
				sources = append(sources, reqID)
			}
		}

		if source.Requirements != nil {
			if err := d.deleteNotIn(ctx, tx, "sources_requirements", "source_id", id, "requirement_id", sources); err != nil {
				return err
			}
		}

		return nil
	})
}

func (d *Database) UpsertSecret(ctx context.Context, principal string, secret *config.Secret) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "secrets", secret.Name, "secrets.create", "secrets.manage"); err != nil {
			return err
		}

		if len(secret.Value) > 0 {
			bs, err := json.Marshal(secret.Value)
			if err != nil {
				return err
			}

			return d.upsertNoID(ctx, tx, "secrets", []string{"name", "value"}, []string{"name"}, secret.Name, string(bs))
		}

		return d.upsertNoID(ctx, tx, "secrets", []string{"name", "value"}, []string{"name"}, secret.Name, nil)
	})
}

func (d *Database) UpsertStack(ctx context.Context, principal string, stack *config.Stack) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "stacks", stack.Name, "stacks.create", "stacks.manage"); err != nil {
			return err
		}

		selector, err := json.Marshal(stack.Selector)
		if err != nil {
			return err
		}

		var exclude *[]byte
		if stack.ExcludeSelector != nil {
			bs, err := json.Marshal(stack.ExcludeSelector)
			if err != nil {
				return err
			}
			exclude = &bs
		}

		id, err := d.upsert(ctx, tx, "stacks", []string{"name", "selector", "exclude_selector"}, []string{"name"}, stack.Name, string(selector), exclude)
		if err != nil {
			return err
		}

		for _, r := range stack.Requirements {
			if r.Source != nil {
				sourceID, err := d.lookupID(ctx, tx, "sources", *r.Source)
				if err != nil {
					return fmt.Errorf("lookup source %s: %w", *r.Source, err)
				}
				if err := d.upsertRel(ctx, tx, "stacks_requirements", []string{"stack_id", "source_id", "gitcommit", "path", "prefix"}, []string{"stack_id", "source_id"},
					id, sourceID, r.Git.Commit, r.Path, r.Prefix); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (d *Database) UpsertToken(ctx context.Context, principal string, token *config.Token) error {

	if len(token.Scopes) != 1 {
		return fmt.Errorf("exactly one scope must be provided for token %q", token.Name)
	}

	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "tokens", token.Name, "tokens.create", "tokens.manage"); err != nil {
			return err
		}

		if err := d.upsertNoID(ctx, tx, "tokens", []string{"name", "api_key"}, []string{"name"}, token.Name, token.APIKey); err != nil {
			return err
		}

		return d.UpsertPrincipalTx(ctx, tx, Principal{Id: token.Name, Role: token.Scopes[0].Role})
	})
}

func (d *Database) prepareUpsert(ctx context.Context, tx *sql.Tx, principal, resource, name string, permCreate, permUpdate string) error {

	var a authz.Access

	if err := d.resourceExists(ctx, tx, resource, name); err == nil {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permUpdate,
			Name:       name,
		}
	} else if errors.Is(err, ErrNotFound) {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permCreate,
		}
		if err := d.upsertNoID(ctx, tx, "resource_permissions", []string{"name", "resource", "principal_id", "role"}, []string{"name", "resource"}, name, resource, principal, "owner"); err != nil {
			return err
		}
	} else {
		return err
	}

	if !authz.Check(ctx, tx, d.arg, a) {
		return ErrNotAuthorized
	}

	return nil
}

func (d *Database) prepareDelete(ctx context.Context, tx *sql.Tx, principal, resource, name string, permUpdate string) error {
	a := authz.Access{
		Principal:  principal,
		Resource:   resource,
		Permission: permUpdate,
		Name:       name,
	}

	if authz.Check(ctx, tx, d.arg, a) {
		return d.resourceExists(ctx, tx, resource, name) // only inform about existence if authorized
	}

	return ErrNotAuthorized
}

func (d *Database) resourceExists(ctx context.Context, tx *sql.Tx, table string, name string) error {
	var exists any
	err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM %v as T WHERE T.name = %s", table, d.arg(0)), name).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (d *Database) lookupID(ctx context.Context, tx *sql.Tx, table string, name string) (int, error) {
	var id int
	query := fmt.Sprintf("SELECT id FROM %s WHERE (name = %s)", table, d.arg(0))
	return id, tx.QueryRowContext(ctx, query, name).Scan(&id)
}

func (d *Database) upsertNoID(ctx context.Context, tx *sql.Tx, table string, columns []string, primaryKey []string, values ...any) error {
	_, err := d.upsertReturning(ctx, false, tx, table, columns, primaryKey, values...)
	return err
}

func (d *Database) upsert(ctx context.Context, tx *sql.Tx, table string, columns []string, primaryKey []string, values ...any) (int, error) {
	return d.upsertReturning(ctx, true, tx, table, columns, primaryKey, values...)
}

func (d *Database) upsertRel(ctx context.Context, tx *sql.Tx, table string, columns []string, primaryKey []string, values ...any) error {
	_, err := d.upsertReturning(ctx, false, tx, table, columns, primaryKey, values...)
	return err
}

func (d *Database) upsertReturning(ctx context.Context, returning bool, tx *sql.Tx, table string, columns []string, primaryKey []string, values ...any) (int, error) {
	var query string
	switch d.kind {
	case sqlite:
		query = fmt.Sprintf(`INSERT OR REPLACE INTO %s (%s) VALUES (%s)`, table, strings.Join(columns, ", "),
			strings.Join(d.args(len(columns)), ", "))

	case postgres:
		set := make([]string, 0, len(columns))
		for i := range columns {
			if !slices.Contains(primaryKey, columns[i]) { // do not update primary key columns
				set = append(set, fmt.Sprintf("%s = EXCLUDED.%s", columns[i], columns[i]))
			}
		}

		values := d.args(len(columns))

		if len(set) == 0 {
			query = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING`, table, strings.Join(columns, ", "),
				strings.Join(values, ", "),
				strings.Join(primaryKey, ", "))
		} else {
			query = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s`, table, strings.Join(columns, ", "),
				strings.Join(values, ", "),
				strings.Join(primaryKey, ", "),
				strings.Join(set, ", "))
		}

	case mysql:
		set := make([]string, 0, len(columns))
		for i := range columns {
			set = append(set, fmt.Sprintf("%s = VALUES(%s)", columns[i], columns[i]))
		}

		values := d.args(len(columns))

		query = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s`, table, strings.Join(columns, ", "),
			strings.Join(values, ", "),
			strings.Join(set, ", "))
	}

	if returning {
		var id int
		query += " RETURNING id"
		if err := tx.QueryRowContext(ctx, query, values...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	} else {
		_, err := tx.ExecContext(ctx, query, values...)
		return 0, err
	}
}

func (d *Database) delete(ctx context.Context, tx *sql.Tx, table, keyColumn string, keyValue any) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE %s = %s", table, keyColumn, d.arg(0))
	_, err := tx.ExecContext(ctx, query, keyValue)
	return err
}

func (d *Database) deleteNotIn(ctx context.Context, tx *sql.Tx, table, keyColumn string, keyValue any, column string, values []int) error {
	if len(values) == 0 {
		return d.delete(ctx, tx, table, keyColumn, keyValue)
	}

	placeholders := make([]string, len(values))
	for i := range values {
		placeholders[i] = d.arg(i + 1)
	}
	query := fmt.Sprintf("DELETE FROM %s WHERE %s = %s AND %s NOT IN (%s)", table, keyColumn, d.arg(0), column, strings.Join(placeholders, ", "))

	args := make([]any, 0, 1+len(values))
	args = append(args, keyValue)
	for _, v := range values {
		args = append(args, v)
	}
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func (d *Database) arg(i int) string {
	if d.kind == postgres {
		return "$" + strconv.Itoa(i+1)
	}
	return "?"
}

func (d *Database) args(n int) []string {
	args := make([]string, n)
	for i := range n {
		args[i] = d.arg(i)
	}

	return args
}

func tx1(ctx context.Context, db *Database, f func(*sql.Tx) error) error {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	if err := f(tx); err != nil {
		return err
	}

	return tx.Commit()
}

func tx3[T any, U bool | string](ctx context.Context, db *Database, f func(*sql.Tx) (T, U, error)) (T, U, error) {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		var t T
		var u U
		return t, u, err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	result, result2, err := f(tx)
	if err != nil {
		var t T
		var u U
		return t, u, err
	}

	if err = tx.Commit(); err != nil {
		var t T
		var u U
		return t, u, err
	}

	return result, result2, nil
}
