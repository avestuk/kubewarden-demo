// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// VolumeProjection Projection that may be projected along with other supported volume types
//
// swagger:model VolumeProjection
type VolumeProjection struct {

	// configMap information about the configMap data to project
	ConfigMap *ConfigMapProjection `json:"configMap,omitempty"`

	// downwardAPI information about the downwardAPI data to project
	DownwardAPI *DownwardAPIProjection `json:"downwardAPI,omitempty"`

	// secret information about the secret data to project
	Secret *SecretProjection `json:"secret,omitempty"`

	// serviceAccountToken is information about the serviceAccountToken data to project
	ServiceAccountToken *ServiceAccountTokenProjection `json:"serviceAccountToken,omitempty"`
}
