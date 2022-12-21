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

type VaultUnsealSubmission struct {
	Key string
}

type VaultSecretEngine struct {
	Type string `json:"type"`
}

type VaultKubernetesConfig struct {
	KubernetesHost string `json:"kubernetes_host"`
}

type VaultPolicy struct {
	Policy string `json:"policy"`
}

type VaultRole struct {
	BoundServiceAccountNames []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
	TokenPeriod string `json:"token_period"`
	TokenPolicies []string `json:"token_policies"`
}

func (sealConfig *VaultSealConfig) toMap() map[string]string {
	sealMap := make(map[string]string)

	sealMap["rookToken"] = sealConfig.RootToken

	for i := 0; i < len(sealConfig.Keys); i++ {
		sealMap[fmt.Sprintf("key%d", i+1)] = sealConfig.Keys[i]
	}

	return sealMap
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
		return false, fmt.Errorf("Could not create GET request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("Could not read response of init: %w", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return false, errors.New(
			fmt.Sprintf("GET response status code: %v, body: %s", resp.StatusCode, string(body)))
	}

	var status VaultStatus
	json.Unmarshal(body, &status)

	return status.Initialized, nil
}

func initializeVault(vault_addr string) (*VaultSealConfig, error) {
	endpoint := fmt.Sprintf("%s/v1/sys/init", vault_addr)
	data, err := json.Marshal(VaultInitConfig{SecretShares: 5, SecretThreshold: 3})

	if err != nil {
		return nil, fmt.Errorf("Could not marshal VaultInitConfig: %w", err)
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(data))

	if err != nil {
		return nil, fmt.Errorf("Could not make POST request: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Could not read response of vault initialization: %w", err)
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

func makePostRequest(endpoint string, data []byte, token ...string) error {
	client := &http.Client{}
	var dataReader io.Reader
	if data != nil {
		dataReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest("POST", endpoint, dataReader)
	if err != nil {
		return fmt.Errorf("Could not create POST request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	if len(token) != 0 {
		req.Header.Add("X-Vault-Token", token[0])
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Could not make POST request: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Could not read POST response: %w", err)
		}
		return errors.New(fmt.Sprintf(
			"POST response status code: %v, body: %s", resp.StatusCode, string(responseBody)))
	}

	return nil
}

func submitUnsealKey(vault_addr string, key string) error {
	data, err := json.Marshal(VaultUnsealSubmission{Key: key})

	if err != nil {
		return fmt.Errorf("Could not marshal VaultUnsealSubmission: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/unseal", vault_addr)
	return makePostRequest(endpoint, data)
}

func enableTransitEngine(vault_addr string, token string) error {
	data, err := json.Marshal(VaultSecretEngine{Type: "transit"})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultSecretEngine: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/mounts/transit", vault_addr)
	return makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/transit/keys/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST
func createAutoUnsealKey(vault_addr string, token string) error {
	endpoint := fmt.Sprintf("%s/v1/transit/keys/autounseal", vault_addr)
	return makePostRequest(endpoint, nil, token)
}

// curl $VAULT_ADDR/v1/sys/auth/kubernetes -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"type": "kubernetes"}'
func enableKubernetesAuth(vault_addr string, token string) error {
	data, err := json.Marshal(VaultSecretEngine{Type: "kubernetes"})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultSecretEngine: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/auth/kubernetes", vault_addr)
	return makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/auth/kubernetes/config -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"kubernetes_host": "https://kubernetes.default.svc"}'
func configureKubernetesAuth(vault_addr, token string) error {
	data, err := json.Marshal(VaultKubernetesConfig{KubernetesHost: "https://kubernetes.default.svc"})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultKubernetesConfig: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/auth/kubernetes/config", vault_addr)
	return makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/sys/policy/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"policy": "path \"transit/encrypt/autounseal\" { capabilities = [ \"update\" ] } \n\n path \"transit/decrypt/autounseal\" { capabilities = [ \"update\" ] }"}'
func createAutoUnsealPolicy(vault_addr, token string) error {
	policy := `
path "transit/encrypt/autounseal" {
  capabilities = [ "update" ]
}

path "transit/decrypt/autounseal" {
  capabilities = [ "update" ]
}
`
	data, err := json.Marshal(VaultPolicy{Policy: policy})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultPolicy: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/policy/autounseal", vault_addr)
	return makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/auth/kubernetes/role/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"bound_service_account_names": ["vault"], "bound_service_account_namespaces": ["vault", "default"], "token_period": "3600", "token_policies": ["autounseal"]}'
func createAutoUnsealRole(vault_addr, token string) error {
	data, err := json.Marshal(VaultRole{
		BoundServiceAccountNames: []string{"vault"},
		BoundServiceAccountNamespaces: []string{"vault", "default"},
		TokenPeriod: "3600",
		TokenPolicies: []string{"autounseal"},
	})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultRole: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/auth/kubernetes/role/autounseal", vault_addr)
	return makePostRequest(endpoint, data, token)
}

func main() {
	vault_addr := string(requireEnv("VAULT_ADDR"))

	var isInitialized bool
	var err error
	log.Println("Checking if vault has been initialized.")
	// Keep retrying until we can get vault's status
	for true {
		isInitialized, err = isVaultInitialized(vault_addr)
		if err == nil {
			break
		}

		log.Printf("Vault not ready, error: %s\n", err.Error())
		time.Sleep(10 * time.Second)
	}

	if isInitialized {
		log.Println("Vault is already initialized.")
		return
	}

	log.Println("Vault has not been initialized.")
	sealConfig, err := initializeVault(vault_addr)
	if err != nil {
		log.Fatalf("Could not initialize vault: %s", err.Error())
	}

	log.Println("Initialized vault.")

	secretData := sealConfig.toMap()
	log.Println("Serialized and encoded vault seal configuration, creating secret.")

	namespace := getNamespace()
	secretsManager, err := k8s_secrets.GetSecretsManager(namespace)
	if err != nil {
		log.Fatalf("Could not get secrets manager: %s", err.Error())
	}

	err = k8s_secrets.CreateSecret("unsealer-keys", secretData, namespace, secretsManager)
	if err != nil {
		log.Fatalf("Could not create the secret: %s", err.Error())
	}

	log.Println("Created the secret.")

	log.Println("Unsealing the vault.")
	for i := 0; i < 3; i += 1 {
		submitUnsealKey(vault_addr, sealConfig.Keys[i])
	}

	log.Println("Enabling transit engine.")
	if err = enableTransitEngine(vault_addr, sealConfig.RootToken); err != nil {
		log.Fatalf("Could not enable transit engine: %s", err.Error())
	}

	log.Println("Creating autounseal key.")
	if err = createAutoUnsealKey(vault_addr, sealConfig.RootToken); err != nil {
		log.Fatalf("Could not create autounseal key: %s", err.Error())
	}

	log.Println("Enabling kubernetes auth.")
	if err = enableKubernetesAuth(vault_addr, sealConfig.RootToken); err != nil {
		log.Fatalf("Could not enable kubernetes auth: %s", err.Error())
	}

	log.Println("Configuring kubernetes auth")
	if err = configureKubernetesAuth(vault_addr, sealConfig.RootToken); err != nil {
		log.Fatalf("Could not configure kubernetes auth: %s", err.Error())
	}

	log.Println("Creating autounseal policy")
	if err = createAutoUnsealPolicy(vault_addr, sealConfig.RootToken); err != nil {
		log.Fatalf("Could not create autounseal policy: %s", err.Error())
	}

	log.Println("Creating autounseal role")
	if err = createAutoUnsealRole(vault_addr, sealConfig.RootToken); err != nil {
		log.Fatalf("Could not create autounseal role: %s", err.Error())
	}

	// curl http://vault.default.svc:8200/v1/auth/kubernetes/login -X POST --data-raw "{\"role\": \"redis\", \"jwt\": \"$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\"}"
}
