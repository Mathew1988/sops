package vault

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"go.mozilla.org/sops/logging"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("VAULT_TRANSIT")
}

// MasterKey is a Vault Transit backend path used to encrypt and decrypt sops' data key.
type MasterKey struct {
	EncryptedKey   string
	KeyName        string
	TransitBackend string
	CreationDate   time.Time
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Encrypt takes a sops data key, encrypts it with Vault Transit and stores the result in the EncryptedKey field
func (key *MasterKey) Encrypt(dataKey []byte) error {
	path := filepath.Join(key.TransitBackend, "encrypt", key.KeyName)
	cli, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.WithField("Path", path).Info("Vault connections failed")
		return fmt.Errorf("Cannot create Vault Client: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(dataKey)
	payload := make(map[string]interface{})
	payload["plaintext"] = encoded
	raw, err := cli.Logical().Write(path, payload)
	if err != nil {
		log.WithField("Path", path).Info("Encryption failed")
		return err
	}
	if raw == nil || raw.Data == nil {
		return fmt.Errorf("The transit backend %s is empty", path)
	}
	encrypted, ok := raw.Data["ciphertext"]
	if ok != true {
		return fmt.Errorf("there's not encrypted data")
	}
	encryptedKey, ok := encrypted.(string)
	if ok != true {
		return fmt.Errorf("the ciphertext cannot be casted to string")
	}
	key.EncryptedKey = encryptedKey
	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// Decrypt decrypts the EncryptedKey field with CGP KMS and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	path := filepath.Join(key.TransitBackend, "decrypt", key.KeyName)
	cli, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.WithField("Path", path).Info("Vault connections failed")
		return nil, fmt.Errorf("Cannot create Vault Client: %v", err)
	}
	payload := make(map[string]interface{})
	payload["ciphertext"] = key.EncryptedKey
	raw, err := cli.Logical().Write(path, payload)
	if err != nil {
		log.WithField("Path", path).Info("Encryption failed")
		return nil, err
	}
	if raw == nil || raw.Data == nil {
		return nil, fmt.Errorf("The transit backend %s is empty", path)
	}
	decrypted, ok := raw.Data["plaintext"]
	if ok != true {
		return nil, fmt.Errorf("there's no decrypted data")
	}
	dataKey, ok := decrypted.(string)
	if ok != true {
		return nil, fmt.Errorf("the plaintest cannot be casted to string")
	}
	result, err := base64.StdEncoding.DecodeString(dataKey)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decode base64 plaintext")
	}
	return result, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
// This is simply copied from GCPKMS
// TODO: handle key rotation on vault side
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate) > (time.Hour * 24 * 30 * 6)
}

// ToString converts the key to a string representation
func (key *MasterKey) ToString() string {
	return key.KeyName
}

func newMasterKey(backendPath, keyName string) MasterKey {
	return MasterKey{
		KeyName:        keyName,
		TransitBackend: backendPath,
	}
}

func (key *MasterKey) createVaultTransitAndKey() error {
	cli, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("Cannot create Vault Client: %v", err)
	}
	err = cli.Sys().Mount(key.TransitBackend, &api.MountInput{
		Type:        "transit",
		Description: "backend transit used by SOPS",
	})
	if err != nil {
		return err
	}
	path := filepath.Join(key.TransitBackend, "keys", key.KeyName)
	payload := make(map[string]interface{})
	payload["type"] = "rsa-4096"
	_, err = cli.Logical().Write(path, payload)
	if err != nil {
		return err
	}
	_, err = cli.Logical().Read(path)
	if err != nil {
		return err
	}
	return nil
}

// ToMap converts the MasterKey to a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["keyname"] = key.KeyName
	out["backend"] = key.TransitBackend
	out["enc"] = key.EncryptedKey
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	return out
}
