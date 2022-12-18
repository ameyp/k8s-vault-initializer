package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	k8s_secrets "github.com/ameyp/k8s-secret-creator/secrets"
)

type VaultStatus struct {
	Initialized bool
}

type VaultInitConfig struct {
	SecretShares int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type VaultSealConfig struct {
	Keys []string
	KeysBase64 []string `json:"keys_base64"`
	RootToken string `json:"root_token"`
}

func requireEnv(variable string) []byte {
	value := os.Getenv(variable)
	if value == "" {
		log.Fatalf("ENV variable %s is not set", variable)
	}

	return []byte(value)
}

func getNamespace() string {
	namespace, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Fatalf("Could not read namespace file: %v", err.Error())
	}

	return string(namespace)
}

func isVaultInitialized(vault_addr string) (bool, error) {
	endpoint := fmt.Sprintf("%s/v1/sys/init", vault_addr)
	resp, err := http.Get(endpoint)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var status VaultStatus
	json.Unmarshal(body, &status)

	return status.Initialized, nil
}

func initializeVault(vault_addr string) (*VaultSealConfig, error) {
	endpoint := fmt.Sprintf("%s/v1/sys/init", vault_addr)
	data, err := json.Marshal(VaultInitConfig{SecretShares: 5, SecretThreshold: 3})

	if err != nil {
		return nil, err
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(data))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(fmt.Sprintf(
			"POST response status code: %v, body: %s", resp.StatusCode, string(responseBody)))
	}

	var sealConfig VaultSealConfig
	err = json.NewDecoder(resp.Body).Decode(&sealConfig)
	if err != nil {
		return nil, err
	}

	return &sealConfig, nil
}

func main() {
	vault_addr := string(requireEnv("VAULT_ADDR"))

	var isInitialized bool
	var err error
	fmt.Println("Checking if vault has been initialized.")
	// Keep retrying until we can get vault's status
	for true {
		isInitialized, err = isVaultInitialized(vault_addr)
		if err == nil {
			break
		}

		fmt.Printf("Vault not ready, error: %v\n", err)
		time.Sleep(10 * time.Second)
	}

	if isInitialized {
		fmt.Println("Vault is already initialized.")
		return
	}

	fmt.Println("Vault has not been initialized.")
	sealConfig, err := initializeVault(vault_addr)
	if err != nil {
		log.Fatalf("Could not initialize vault: %v", err)
	}

	fmt.Println("Initialized vault.")
	sealJson, err := json.Marshal(sealConfig)
	if err != nil {
		log.Fatalf("Could not convert seal config to byte array")
	}

	fmt.Println("Serialized and encoded vault seal configuration, creating secret.")

	secretData := map[string]string{"seal-config": string(sealJson)}

	fmt.Println(secretData)

	namespace := getNamespace()
	secretsManager := k8s_secrets.GetSecretsManager(namespace)
	k8s_secrets.CreateSecret("unsealer-keys", secretData, namespace, secretsManager)
}
