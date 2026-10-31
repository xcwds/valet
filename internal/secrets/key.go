package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KeySize is the master key's length: AES-256.
const KeySize = 32

// DefaultKeyEnv is read when the config names neither a key file nor a
// variable.
const DefaultKeyEnv = "VALET_MASTER_KEY"

// MasterKey is the key that wraps every secret's data key. It never leaves
// valetd and is never stored in the database.
type MasterKey struct {
	key Secret
	id  string
}

// ID identifies the key without revealing anything about it.
func (k *MasterKey) ID() string { return k.id }

// NewMasterKey generates a random master key and returns it base64-encoded,
// the form LoadMasterKey reads.
func NewMasterKey() (string, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ParseMasterKey decodes a base64 master key. Surrounding whitespace (a
// trailing newline in a file) is ignored.
func ParseMasterKey(encoded string) (*MasterKey, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("master key is empty")
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("master key is not valid base64") // never echo the input
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("master key is %d bytes, want %d (generate one with: valet secrets init-key)", len(b), KeySize)
	}
	mac := hmac.New(sha256.New, b)
	mac.Write([]byte("valet master key id v1"))
	return &MasterKey{key: NewSecret(b), id: hex.EncodeToString(mac.Sum(nil))[:16]}, nil
}

// LoadMasterKey reads the master key from file if set, otherwise from the
// environment variable env (DefaultKeyEnv when empty).
func LoadMasterKey(file, env string, getenv func(string) string) (*MasterKey, error) {
	if file != "" {
		b, err := os.ReadFile(file) //nolint:gosec // The operator chooses the key file.
		if err != nil {
			return nil, fmt.Errorf("master key: %w", err)
		}
		k, err := ParseMasterKey(string(b))
		if err != nil {
			return nil, fmt.Errorf("master key file %s: %w", file, err)
		}
		return k, nil
	}
	if env == "" {
		env = DefaultKeyEnv
	}
	v := getenv(env)
	if v == "" {
		return nil, fmt.Errorf("no master key: set master_key.file, or put a key in $%s (generate one with: valet secrets init-key)", env)
	}
	k, err := ParseMasterKey(v)
	if err != nil {
		return nil, fmt.Errorf("master key in $%s: %w", env, err)
	}
	return k, nil
}
