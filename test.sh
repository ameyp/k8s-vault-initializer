#!/bin/bash

helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault hashicorp/vault -f test/vault-values.yaml

kubectl apply -f test/rbac.yaml
kubectl apply -f test/pod.yaml
