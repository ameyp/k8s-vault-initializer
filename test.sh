#!/bin/bash

set -euo pipefail

UNSEAL_INITIALIZER="vault-unsealer-init"
MAIN_INITIALIZER="vault-init"

function wait_for_pod_ready() {
    local POD_NAME=$1

    while [[ $(kubectl get pod $POD_NAME -o jsonpath="{.status.containerStatuses[0].ready}") != 'true' ]]; do
        echo "$POD_NAME is not yet ready"
        sleep 10
    done

    echo "$POD_NAME is ready"
}

function wait_for_pod_termination() {
    local POD_NAME=$1

    echo "Wait for the initializer to terminate"
    while [[ $(kubectl get pod $POD_NAME -o jsonpath="{.status.containerStatuses[0].ready}") != 'false' ]]; do
        echo "$POD_NAME is not yet done"
        sleep 10
    done

    if [[ $(kubectl get pod $POD_NAME -o jsonpath="{.status.containerStatuses[0].state.terminated.exitCode}") == '0' ]]; then
        echo "$POD_NAME succeeded"
    else
        echo "Initializer failed"
        echo "---- Pod details ----"
        kubectl describe pod $POD_NAME
        echo "---- Pod logs ----"
        kubectl logs $POD_NAME
        exit 1
    fi
}

echo "Create service accounts, roles and bindings"
kubectl apply -f test/rbac.yaml

echo "Create the initializer pod"
kubectl apply -f test/unsealer-init-pod.yaml

echo "Wait for the initializer to start"
wait_for_pod_ready $UNSEAL_INITIALIZER

echo "Install vault unsealer"
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault-unsealer hashicorp/vault -f test/vault-unsealer-values.yaml

wait_for_pod_termination $UNSEAL_INITIALIZER

echo "Wait for vault-unsealer to be ready"
wait_for_pod_ready vault-unsealer-0

echo "Vault unsealed, transit engine and kubernetes auth enabled."

# For the second vault cluster

echo "Create the certificates"
openssl req -x509 -newkey rsa:4096 -sha256 -days 1 -nodes \
        -keyout internal.key -out internal.crt -subj "/CN=*.vault-internal" \
        -addext "subjectAltName=DNS:*.vault-internal,IP:127.0.0.1"

openssl req -x509 -newkey rsa:4096 -sha256 -days 1 -nodes \
        -keyout web.key -out web.crt -subj "/CN=vault-ui.default.svc" \
        -addext "subjectAltName=DNS:vault-ui.default.svc"

echo "Create the secrets"
kubectl create secret tls vault-internal-tls-secret --key="internal.key" --cert="internal.crt"
kubectl create secret tls vault-web-tls-secret --key="web.key" --cert="web.crt"

echo "Remove local cert files"
rm -f *.crt *.key

echo "Create the injector config-map"
kubectl apply -f test/agent-configmap.yaml

echo "Create the initializer pod"
kubectl apply -f test/vault-init-pod.yaml

echo "Wait for the initializer to start"
wait_for_pod_ready $MAIN_INITIALIZER

echo "Install vault"
helm install vault hashicorp/vault -f test/vault-values.yaml

wait_for_pod_termination $MAIN_INITIALIZER

echo "Wait for vault to be ready"
wait_for_pod_ready vault-0
