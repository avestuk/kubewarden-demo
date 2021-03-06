// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// QuobyteVolumeSource Represents a Quobyte mount that lasts the lifetime of a pod. Quobyte volumes do not support ownership management or SELinux relabeling.
//
// swagger:model QuobyteVolumeSource
type QuobyteVolumeSource struct {

	// group to map volume access to Default is no group
	Group string `json:"group,omitempty"`

	// readOnly here will force the Quobyte volume to be mounted with read-only permissions. Defaults to false.
	ReadOnly bool `json:"readOnly,omitempty"`

	// registry represents a single or multiple Quobyte Registry services specified as a string as host:port pair (multiple entries are separated with commas) which acts as the central registry for volumes
	// Required: true
	Registry *string `json:"registry"`

	// tenant owning the given Quobyte volume in the Backend Used with dynamically provisioned Quobyte volumes, value is set by the plugin
	Tenant string `json:"tenant,omitempty"`

	// user to map volume access to Defaults to serivceaccount user
	User string `json:"user,omitempty"`

	// volume is a string that references an already created Quobyte volume by name.
	// Required: true
	Volume *string `json:"volume"`
}
