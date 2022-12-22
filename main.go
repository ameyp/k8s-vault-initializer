package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
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

type VaultTransitSealInitConfig struct {
	StoredShares int `json:"stored_shares"`
	RecoveryShares int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

type VaultSealSecretKeys struct {
	Keys []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken string `json:"root_token"`
}

type VaultSealRecoveryKeys struct {
	Keys []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RecoveryKeys []string `json:"recovery_keys"`
	RecoveryKeys64 []string `json:"recovery_keys_base64"`
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

func (sealConfig *VaultSealSecretKeys) toMap() map[string]string {
	sealMap := make(map[string]string)

	sealMap["rookToken"] = sealConfig.RootToken

	for i := 0; i < len(sealConfig.Keys); i++ {
		sealMap[fmt.Sprintf("key%d", i+1)] = sealConfig.Keys[i]
	}

	return sealMap
}

type Vault struct {
	Address string
	client *http.Client
}

func (vault *Vault) SetupClient() {
	if certFile := os.Getenv("VAULT_CACERT"); certFile != "" {
		caCert, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		vault.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
				},
			},
		}

	} else {
		vault.client = &http.Client{}
	}
}

func (vault *Vault) isInitialized() (bool, error) {
	endpoint := fmt.Sprintf("%s/v1/sys/init", vault.Address)
	resp, err := vault.client.Get(endpoint)
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

func (vault *Vault) initialize(initConfig any, initResponse any) error {
	endpoint := fmt.Sprintf("%s/v1/sys/init", vault.Address)
	data, err := json.Marshal(initConfig)

	if err != nil {
		return fmt.Errorf("Could not marshal VaultInitConfig: %w", err)
	}

	resp, err := vault.client.Post(endpoint, "application/json", bytes.NewBuffer(data))

	if err != nil {
		return fmt.Errorf("Could not make POST request: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Could not read response of vault initialization: %w", err)
		}
		return errors.New(fmt.Sprintf(
			"POST response status code: %v, body: %s", resp.StatusCode, string(responseBody)))
	}

	err = json.NewDecoder(resp.Body).Decode(initResponse)
	if err != nil {
		return fmt.Errorf("Could not unmarshal the JSON response of vault initialization: %w", err)
	}

	return nil
}

func (vault *Vault) initializeForAutoUnseal() (*VaultSealSecretKeys, error) {
	vaultInitConfig := VaultInitConfig{SecretShares: 5, SecretThreshold: 3}
	var secretKeys VaultSealSecretKeys

	if err := vault.initialize(vaultInitConfig, &secretKeys); err != nil {
		return nil, fmt.Errorf("Could not initialize vault for auto-unsealing other vaults: %w", err)
	}

	return &secretKeys, nil
}

func (vault *Vault) initializeWithTransitSeal() (*VaultSealRecoveryKeys, error) {
	vaultInitConfig := VaultTransitSealInitConfig{StoredShares: 5, RecoveryShares: 5, RecoveryThreshold: 5}
	var recoveryKeys VaultSealRecoveryKeys

	if err := vault.initialize(vaultInitConfig, &recoveryKeys); err != nil {
		return nil, fmt.Errorf("Could not initialize vault with transit seal: %w", err)
	}

	return &recoveryKeys, nil
}

func (vault *Vault) makePostRequest(endpoint string, data []byte, token ...string) error {
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

	resp, err := vault.client.Do(req)
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

func (vault *Vault) submitUnsealKey(key string) error {
	data, err := json.Marshal(VaultUnsealSubmission{Key: key})

	if err != nil {
		return fmt.Errorf("Could not marshal VaultUnsealSubmission: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/unseal", vault.Address)
	return vault.makePostRequest(endpoint, data)
}

func (vault *Vault) enableTransitEngine(token string) error {
	data, err := json.Marshal(VaultSecretEngine{Type: "transit"})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultSecretEngine: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/mounts/transit", vault.Address)
	return vault.makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/transit/keys/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST
func (vault *Vault) createAutoUnsealKey(token string) error {
	endpoint := fmt.Sprintf("%s/v1/transit/keys/autounseal", vault.Address)
	return vault.makePostRequest(endpoint, nil, token)
}

// curl $VAULT_ADDR/v1/sys/auth/kubernetes -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"type": "kubernetes"}'
func (vault *Vault) enableKubernetesAuth(token string) error {
	data, err := json.Marshal(VaultSecretEngine{Type: "kubernetes"})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultSecretEngine: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/sys/auth/kubernetes", vault.Address)
	return vault.makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/auth/kubernetes/config -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"kubernetes_host": "https://kubernetes.default.svc"}'
func (vault *Vault) configureKubernetesAuth(token string) error {
	data, err := json.Marshal(VaultKubernetesConfig{KubernetesHost: "https://kubernetes.default.svc"})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultKubernetesConfig: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/auth/kubernetes/config", vault.Address)
	return vault.makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/sys/policy/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"policy": "path \"transit/encrypt/autounseal\" { capabilities = [ \"update\" ] } \n\n path \"transit/decrypt/autounseal\" { capabilities = [ \"update\" ] }"}'
func (vault *Vault) createAutoUnsealPolicy(token string) error {
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

	endpoint := fmt.Sprintf("%s/v1/sys/policy/autounseal", vault.Address)
	return vault.makePostRequest(endpoint, data, token)
}

// curl $VAULT_ADDR/v1/auth/kubernetes/role/autounseal -H "X-Vault-Token: $VAULT_TOKEN" -X POST --data-raw '{"bound_service_account_names": ["vault"], "bound_service_account_namespaces": ["vault", "default"], "token_period": "3600", "token_policies": ["autounseal"]}'
func (vault *Vault) createAutoUnsealRole(token string) error {
	data, err := json.Marshal(VaultRole{
		BoundServiceAccountNames: []string{"vault"},
		BoundServiceAccountNamespaces: []string{"vault", "default"},
		TokenPeriod: "3600",
		TokenPolicies: []string{"autounseal"},
	})
	if err != nil {
		return fmt.Errorf("Could not marshal VaultRole: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/auth/kubernetes/role/autounseal", vault.Address)
	return vault.makePostRequest(endpoint, data, token)
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


func main() {
	var vaultForAutounseal = flag.Bool("vault-for-autounseal", false,
		"Whether the vault instance should be set up for auto-unsealing other vaults")
	flag.Parse()

	vault_addr := string(requireEnv("VAULT_ADDR"))
	vault := Vault{Address: vault_addr}
	vault.SetupClient()

	var isInitialized bool
	var err error
	log.Println("Checking if vault has been initialized.")
	// Keep retrying until we can get vault's status
	for true {
		isInitialized, err = vault.isInitialized()
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

	namespace := getNamespace()
	secretsManager, err := k8s_secrets.GetSecretsManager(namespace)
	if err != nil {
		log.Fatalf("Could not get secrets manager: %s", err.Error())
	}

	if *vaultForAutounseal {
		sealConfig, err := vault.initializeForAutoUnseal()
		if err != nil {
			log.Fatalf("Could not initialize vault: %s", err.Error())
		}

		log.Println("Initialized vault.")

		secretData := sealConfig.toMap()
		log.Println("Serialized and encoded vault seal configuration, creating secret.")

		err = k8s_secrets.CreateSecret("vault-secret-keys", secretData, namespace, secretsManager)
		if err != nil {
			log.Fatalf("Could not create the secret: %s", err.Error())
		}

		log.Println("Unsealing the vault.")
		for i := 0; i < 3; i += 1 {
			vault.submitUnsealKey(sealConfig.Keys[i])
		}

		log.Println("Enabling transit engine.")
		if err = vault.enableTransitEngine(sealConfig.RootToken); err != nil {
			log.Fatalf("Could not enable transit engine: %s", err.Error())
		}

		log.Println("Creating autounseal key.")
		if err = vault.createAutoUnsealKey(sealConfig.RootToken); err != nil {
			log.Fatalf("Could not create autounseal key: %s", err.Error())
		}

		log.Println("Enabling kubernetes auth.")
		if err = vault.enableKubernetesAuth(sealConfig.RootToken); err != nil {
			log.Fatalf("Could not enable kubernetes auth: %s", err.Error())
		}

		log.Println("Configuring kubernetes auth")
		if err = vault.configureKubernetesAuth(sealConfig.RootToken); err != nil {
			log.Fatalf("Could not configure kubernetes auth: %s", err.Error())
		}

		log.Println("Creating autounseal policy")
		if err = vault.createAutoUnsealPolicy(sealConfig.RootToken); err != nil {
			log.Fatalf("Could not create autounseal policy: %s", err.Error())
		}

		log.Println("Creating autounseal role")
		if err = vault.createAutoUnsealRole(sealConfig.RootToken); err != nil {
			log.Fatalf("Could not create autounseal role: %s", err.Error())
		}
	} else {
		sealConfig, err := vault.initializeForAutoUnseal()
		if err != nil {
			log.Fatalf("Could not initialize vault: %s", err.Error())
		}

		log.Println("Initialized vault.")

		secretData := sealConfig.toMap()
		log.Println("Serialized and encoded vault seal configuration, creating secret.")

		err = k8s_secrets.CreateSecret("vault-recovery-keys", secretData, namespace, secretsManager)
		if err != nil {
			log.Fatalf("Could not create the secret: %s", err.Error())
		}
	}
}
