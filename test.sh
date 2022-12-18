#!/bin/bash

helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault hashicorp/vault -f test/vault-values.yaml

kubectl apply -f test/rbac.yaml
kubectl apply -f test/pod.yaml

while [[ $(kubectl get pod vault-0 -o jsonpath="{.status.containerStatuses[0].ready}") != 'true' ]]; do
    echo "Vault is not yet unsealed"
    sleep 10
done

echo "Vault unsealed"
