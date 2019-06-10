package vault

import (
	"fmt"
	logger "log"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		logger.Fatalf("Could not connect to docker: %s", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run("vault", "1.1.3", []string{"VAULT_DEV_ROOT_TOKEN_ID=secret"})
	if err != nil {
		logger.Fatalf("Could not start resource: %s", err)
	}

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1:%v", resource.GetPort("8200/tcp")))
	os.Setenv("VAULT_TOKEN", "secret")

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		cli, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return fmt.Errorf("Cannot create Vault Client: %v", err)
		}
		status, err := cli.Sys().InitStatus()
		if err != nil {
			return err
		}
		if status != true {
			return fmt.Errorf("Vault not ready yet")
		}
		return nil
	}); err != nil {
		logger.Fatalf("Could not connect to docker: %s", err)
	}

	key := newMasterKey("sops", "main")
	err = key.createVaultTransitAndKey()
	if err != nil {
		logger.Fatal(err)
	}
	code := 0
	if err == nil {
		code = m.Run()
	}

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		logger.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func TestKeyToMap(t *testing.T) {
	key := MasterKey{
		CreationDate:   time.Date(2016, time.October, 31, 10, 0, 0, 0, time.UTC),
		TransitBackend: "foo",
		KeyName:        "bar",
		EncryptedKey:   "this is encrypted",
	}
	assert.Equal(t, map[string]interface{}{
		"backend":    "foo",
		"keyname":    "bar",
		"enc":        "this is encrypted",
		"created_at": "2016-10-31T10:00:00Z",
	}, key.ToMap())
}

func TestEncryptionDecryption(t *testing.T) {
	dataKey := []byte("super very Secret Key!!!")
	key := MasterKey{
		TransitBackend: "sops",
		KeyName:        "main",
	}
	err := key.Encrypt(dataKey)
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
	decrypted, err := key.Decrypt()
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
	assert.Equal(t, dataKey, decrypted)
}
