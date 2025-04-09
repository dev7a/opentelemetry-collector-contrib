// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secretsmanagerauthextension

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))

	smCfg, ok := cfg.(*Config)
	require.True(t, ok, "config is not of type *Config")

	assert.Equal(t, component.MustNewType(typeStr), factory.Type())
	assert.Equal(t, "", smCfg.Region)
	assert.Equal(t, "", smCfg.SecretName)
}

func TestCreateExtension(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.SecretName = "test-secret"

	ext, err := factory.Create(
		t.Context(),
		extensiontest.NewNopSettings(factory.Type()),
		cfg,
	)
	require.NoError(t, err)
	require.NotNil(t, ext)

	// Test with invalid config
	invalidCfg := factory.CreateDefaultConfig().(*Config)
	// No SecretName - should fail validation
	ext, err = factory.Create(
		t.Context(),
		extensiontest.NewNopSettings(factory.Type()),
		invalidCfg,
	)
	require.Error(t, err)
	require.Nil(t, ext)
}
