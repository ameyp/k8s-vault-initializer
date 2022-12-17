#!/bin/bash

CGO_ENABLED=0 go build -o build/k8s-vault-initializer -v main.go
