#!/usr/bin/env bats

@test "reject because host ipc shennanigans are in play and container registry is not accepted" {
  run kwctl run annotated-policy.wasm -r ./test_data/disallowed_pod_host_ipc.json  --settings-json "$(cat ./settings.sample.json)"
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*pod 'test-pod' uses hostIPC and uses an image: fsb/notnotpetyaiswear*") -ne 0 ]
}

@test "reject because host network shennanigans are in play and container registry is not accepted" {
  run kwctl run annotated-policy.wasm -r ./test_data/disallowed_pod_host_network.json  --settings-json "$(cat ./settings.sample.json)"

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*pod 'test-pod' uses hostNetwork and uses an image: fsb/notnotpetyaiswear*") -ne 0 ]
}

@test "reject because host path shennanigans are in play and container registry is not accepted" {
  run kwctl run annotated-policy.wasm -r ./test_data/disallowed_pod_host_path.json --settings-json "$(cat ./settings.sample.json)"

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*pod 'test-pod' uses hostPath and uses an image: fsb/notnotpetyaiswear*") -ne 0 ]
}

@test "accept because container is on the container_registry list" {
  run kwctl run annotated-policy.wasm -r ./test_data/pod.json --settings-json "$(cat ./settings.sample.json)"
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
