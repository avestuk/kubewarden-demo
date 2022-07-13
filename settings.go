package main

import (
	mapset "github.com/deckarep/golang-set"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"

	"fmt"
)

type Settings struct {
	ContainerRegistries mapset.Set
}

func (s *Settings) Valid() (bool, error) {
	if s.ContainerRegistries.Cardinality() == 0 {
		return false, fmt.Errorf("cannot have 0 valid container registries")
	}

	return true, nil
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	return newSettings(validationReq.Settings)
}

func newSettings(settingsJson []byte) (Settings, error) {
	basicSettings := BasicSettings{}
	if err := easyjson.Unmarshal(settingsJson, &basicSettings); err != nil {
		return Settings{}, err
	}

	acceptedContainerRegistries := mapset.NewThreadUnsafeSet()
	for _, registry := range basicSettings.ContainerRegistries {
		acceptedContainerRegistries.Add(registry)
	}

	return Settings{
		ContainerRegistries: acceptedContainerRegistries,
	}, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := newSettings(payload)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	if valid, err := settings.Valid(); !valid || err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	return kubewarden.AcceptSettings()
}
