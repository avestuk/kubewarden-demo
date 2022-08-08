package main

import (
	"fmt"
	"strings"

	onelog "github.com/francoispqt/onelog"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
)

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := easyjson.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Access the **raw** JSON that describes the object
	podJSON := validationRequest.Request.Object

	// Try to create a Pod instance using the RAW JSON we got from the
	// ValidationRequest.
	pod := &corev1.Pod{}
	if err := easyjson.Unmarshal([]byte(podJSON), pod); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("Cannot decode Pod object: %s", err.Error())),
			kubewarden.Code(400))
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		e.String("name", pod.Metadata.Name)
		e.String("namespace", pod.Metadata.Namespace)
	})

	// If there are no hostShennanigans we can accept the request
	h := hostShennanigans(pod)
	if h == 0 {
		return kubewarden.AcceptRequest()
	}

	// Collect all the container registries that all the containers in the
	// pod are using.
	containerRegistries := make(map[string]int)
	for _, c := range pod.Spec.InitContainers {
		registry := strings.Split(c.Image, ":")[0]
		if _, ok := containerRegistries[registry]; !ok {
			containerRegistries[registry] = 1
		}
	}

	for _, c := range pod.Spec.Containers {
		registry := strings.Split(c.Image, ":")[0]
		if _, ok := containerRegistries[registry]; !ok {
			containerRegistries[registry] = 1
		}
	}

	// Validate whether unauthorized containers are being used in conjuction with hostPaths/hostNetworking
	for containerRegistry := range containerRegistries {
		if !settings.ContainerRegistries.Contains(containerRegistry) {
			logger.InfoWithFields("rejecting pod object", func(e onelog.Entry) {
				e.String("name", pod.Metadata.Name)
				e.String("unauthorized_registry", containerRegistry)
				e.String("host shennanigans not allowed: ", h.String())
			})

			return kubewarden.RejectRequest(
				kubewarden.Message(
					fmt.Sprintf("pod '%s' uses %s and uses an image: %s that is not from an authorized registry", pod.Metadata.Name, h.String(), containerRegistry)),
				kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}

type hostShennanigan int

func (h *hostShennanigan) String() string {
	return [...]string{
		"",
		"hostNetwork",
		"hostIPC",
		"hostPID",
		"hostPath",
		"privilegedContainer",
	}[*h]
}

const (
	hostNetwork hostShennanigan = iota + 1
	hostIPC
	hostPID
	hostPath
	privilegedContainer
)

func hostShennanigans(pod *corev1.Pod) hostShennanigan {
	if pod.Spec.HostNetwork {
		return hostNetwork
	}

	if pod.Spec.HostIPC {
		return hostIPC
	}

	if pod.Spec.HostPID {
		return hostPID
	}

	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return hostPath
		}
	}

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged {
			return privilegedContainer
		}
	}
	return 0
}
