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
