package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// refreshCredentialsInterval sets the refreshing interval to ensure they are up to date.
const refreshCredentialsInterval = 5 * time.Minute

// SecretCredentialsProvider is a custom credentials provider that retrieves AWS credentials from a secret every 5 minutes.
// It implements the aws.CredentialsProvider interface.
type SecretCredentialsProvider struct {
	aws.Credentials
	credentials *config.SecretRef
}

func NewSecretCredentialsProvider(credentials *config.SecretRef) aws.CredentialsProvider {
	return &SecretCredentialsProvider{
		credentials: credentials,
	}
}

func (s *SecretCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	value, err := s.credentials.Resolve(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	switch value := value.(type) {
	case config.SecretAWS:
		if value.AccessKeyID != "" || value.SecretAccessKey != "" || value.SessionToken != "" {
			return aws.Credentials{
				AccessKeyID:     value.AccessKeyID,
				SecretAccessKey: value.SecretAccessKey,
				SessionToken:    value.SessionToken,
				Source:          "configurated credentials",
				CanExpire:       true,
				Expires:         time.Now().Add(refreshCredentialsInterval),
			}, nil
		}

		return aws.Credentials{}, errors.New("missing access_key_id or secret_access_key in credentials")
	}

	return aws.Credentials{}, fmt.Errorf("unsupported authentication type: %T", value)
}

func Config(ctx context.Context, region string, credentials *config.SecretRef) (aws.Config, error) {
	var options []func(*awsconfig.LoadOptions) error

	if region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}

	if credentials == nil {
		// Option 1: default chain.
	} else {
		// Option 2: use a secret of type "aws_auth".
		options = append(options, awsconfig.WithCredentialsProvider(NewSecretCredentialsProvider(credentials)))
	}

	return awsconfig.LoadDefaultConfig(ctx, options...)
}
