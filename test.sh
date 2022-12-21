#!/bin/bash

# Install vault
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault-unsealer hashicorp/vault -f test/vault-unsealer-values.yaml

# Create service accounts, roles and bindings
kubectl apply -f test/rbac.yaml

# Create a pod with the image we want to test
kubectl apply -f test/pod.yaml

# Wait for vault to be initialized and unsealed by the pod
while [[ $(kubectl get pod vault-unsealer-0 -o jsonpath="{.status.containerStatuses[0].ready}") != 'true' ]]; do
    echo "Vault is not yet unsealed"
    sleep 10
done

echo "Vault unsealed, transit engine and kubernetes auth enabled."

# Port forward vault's HTTP port
LOCAL_PORT="45000"
kubectl port-forward pods/vault-unsealer-0 $LOCAL_PORT:8200 &

# Get a valid service account token for an account authorized to access the autounseal transit engine
SERVICE_ACCOUNT_TOKEN=$(kubectl create token vault)

# Login using the service account token and get a valid vault token
VAULT_TOKEN=$(curl -s http://localhost:$LOCAL_PORT/v1/auth/kubernetes/login -X POST --data-raw "{\"role\": \"autounseal\", \"jwt\": \"$SERVICE_ACCOUNT_TOKEN\"}" | jq -r '.auth.client_token')

# We just care that the request succeeds and returns encrypted text.
curl -s http://localhost:$LOCAL_PORT/v1/transit/encrypt/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"plaintext": "abcd"}' | jq -r '.data.ciphertext'

# For the second vault cluster

# Create the certificate
openssl req -x509 -newkey rsa:4096 -sha256 -days 1 -nodes \
  -keyout vault.key -out vault.crt -subj "/CN=*.vault-internal" \
  -addext "subjectAltName=DNS:*.vault-internal,IP:127.0.0.1"

# Create the secret
kubectl create secret tls vault-internal-tls-secret --key="vault.key" --cert="vault.crt"

# Remove local cert files
rm -f vault.crt vault.key
