package main

import (
	"testing"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
	"github.com/mailru/easyjson"
	"github.com/stretchr/testify/require"
)

func TestValidateContainerRegistry(t *testing.T) {
	cases := map[string]struct {
		containerRegistries    []string
		podContainerRegistries []string
		hostShennanigan        bool
		hostShennaniganType    hostShennanigan
		expectedIsValid        bool
	}{
		"valid registries": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"foo", "bar"},
			expectedIsValid:        true,
		},
		"invalid registries": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"baz", "bat"},
			expectedIsValid:        true,
		},
		"invalid registries with host network": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"baz", "bat"},
			hostShennanigan:        true,
			hostShennaniganType:    hostNetwork,
			expectedIsValid:        false,
		},
		"invalid registries with host IPC": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"baz", "bat"},
			hostShennanigan:        true,
			hostShennaniganType:    hostIPC,
			expectedIsValid:        false,
		},
		"invalid registries with host PID": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"baz", "bat"},
			hostShennanigan:        true,
			hostShennaniganType:    hostPID,
			expectedIsValid:        false,
		},
		"invalid registries with host path": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"baz", "bat"},
			hostShennanigan:        true,
			hostShennaniganType:    hostPath,
			expectedIsValid:        false,
		},
		"invalid registries with privileged container": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"baz", "bat"},
			hostShennanigan:        true,
			hostShennaniganType:    privilegedContainer,
			expectedIsValid:        false,
		},
		"valid registries with host network": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"foo", "bar"},
			hostShennanigan:        true,
			hostShennaniganType:    hostNetwork,
			expectedIsValid:        true,
		},
		"valid registries with host IPC": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"foo", "bar"},
			hostShennanigan:        true,
			hostShennaniganType:    hostIPC,
			expectedIsValid:        true,
		},
		"valid registries with host PID": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"foo", "bar"},
			hostShennanigan:        true,
			hostShennaniganType:    hostPID,
			expectedIsValid:        true,
		},
		"valid registries with host path": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"foo", "bar"},
			hostShennanigan:        true,
			hostShennaniganType:    hostPath,
			expectedIsValid:        true,
		},
		"valid registries with privileged container": {
			containerRegistries:    []string{"foo", "bar"},
			podContainerRegistries: []string{"foo", "bar"},
			hostShennanigan:        true,
			hostShennaniganType:    privilegedContainer,
			expectedIsValid:        true,
		},
	}

	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			basicSettings := BasicSettings{
				ContainerRegistries: settings.containerRegistries,
			}

			containers := []*corev1.Container{}
			for _, cr := range settings.podContainerRegistries {
				containers = append(containers, &corev1.Container{
					Image: cr,
				})
			}

			pod := corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "bobby",
					Namespace: "tables",
				},
				Spec: &corev1.PodSpec{
					Containers: containers,
				},
			}

			if settings.hostShennanigan {
				switch settings.hostShennaniganType {
				case hostNetwork:
					pod.Spec.HostNetwork = true
				case hostIPC:
					pod.Spec.HostIPC = true
				case hostPID:
					pod.Spec.HostPID = true
				case hostPath:
					hostPath := "/sys"
					pod.Spec.Volumes = append(pod.Spec.Volumes, &corev1.Volume{
						HostPath: &corev1.HostPathVolumeSource{
							Path: &hostPath,
						},
					})
				case privilegedContainer:
					t.Logf("pod containers:\n %#v", pod.Spec.Containers)
					pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
						Privileged: true,
					}
				}
			}

			payload, err := kubewarden_testing.BuildValidationRequest(&pod, &basicSettings)
			require.NoError(t, err)

			responsePayload, err := validate(payload)
			require.NoError(t, err)

			var response kubewarden_protocol.ValidationResponse
			require.NoError(t, easyjson.Unmarshal(responsePayload, &response))

			if settings.expectedIsValid {
				require.True(t, response.Accepted)
			} else {
				require.False(t, response.Accepted)
			}

		})
	}
}

func TestShennaniganString(t *testing.T) {
	expected := []string{
		"",
		"hostNetwork",
		"hostIPC",
		"hostPID",
		"hostPath",
		"privilegedContainer",
	}

	for i := 1; i >= int(privilegedContainer); i++ {
		h := hostShennanigan(i)
		require.Equal(t, expected[i], h.String())
	}

}
