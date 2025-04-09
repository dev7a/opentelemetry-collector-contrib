// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secretsmanagerauthextension

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		expectedErr error
	}{
		{
			name: "valid configuration",
			cfg: Config{
				SecretName:      "otel/test/headers",
				RefreshInterval: 2 * time.Minute,
			},
			expectedErr: nil,
		},
		{
			name: "missing secret name",
			cfg: Config{
				RefreshInterval: time.Minute,
			},
			expectedErr: errNoSecretName,
		},
		{
			name: "zero refresh interval gets set to default",
			cfg: Config{
				SecretName:      "otel/test/headers",
				RefreshInterval: 0,
			},
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.cfg.Validate()
			if test.expectedErr != nil {
				assert.Equal(t, test.expectedErr, err)
			} else {
				assert.NoError(t, err)
				if test.cfg.RefreshInterval == 0 {
					assert.Equal(t, time.Minute, test.cfg.RefreshInterval)
				}
			}
		})
	}
}

func TestConfigClone(t *testing.T) {
	cfg := &Config{
		Region:          "us-west-2",
		SecretName:      "otel/test/headers",
		RefreshInterval: 2 * time.Minute,
		FallbackHeaders: map[string]string{
			"User-Agent": "test-agent",
		},
		AssumeRole: AssumeRoleConfig{
			ARN:       "arn:aws:iam::123456789012:role/test",
			STSRegion: "us-east-1",
		},
	}

	// Ensure we're checking the error return from Validate
	err := cfg.Validate()
	require.NoError(t, err)
}
