package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseValidSettings(t *testing.T) {
	expected_registries := []string{"foo", "bar"}
	settingsJSON := []byte(`
	    {
	        "container_registries": [ "foo", "bar" ]
	    }`)

	settings, err := newSettings(settingsJSON)
	require.NoError(t, err)

	for _, expected_registry := range expected_registries {
		require.Truef(t, settings.ContainerRegistries.Contains(expected_registry), "did not find: %s, in: %s", expected_registry, settings.ContainerRegistries.String())
	}
}

func TestParseInvalidSettings(t *testing.T) {
	settingsJSON := []byte(`
	    {
	        "container_registries": []
	    }`)

	settings, err := newSettings(settingsJSON)
	require.NoError(t, err)

	isValid, err := settings.Valid()
	assert.False(t, isValid)
	require.Error(t, err)
}
