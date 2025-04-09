// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secretsmanagerauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/secretsmanagerauthextension"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

const (
	// The value of extension "type" in configuration.
	typeStr = "secretsmanagerauth"
	// The stability level of the extension.
	stability = component.StabilityLevelBeta
)

// NewFactory creates a factory for the AWS Secrets Manager authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		createExtension,
		stability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		RefreshInterval: time.Minute,
	}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	config := cfg.(*Config)
	return newAuthenticator(config, set.Logger)
}
