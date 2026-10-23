package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const maxVaultSize = 1 << 20

type Credential struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type vault struct {
	Version int                   `json:"version"`
	Entries map[string]Credential `json:"entries"`
}

func NormalizeEndpoint(endpoint string) (string, error) {
	origin, err := url.Parse(endpoint)
	if err != nil || origin == nil || (origin.Scheme != "https" && origin.Scheme != "http") ||
		origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", fmt.Errorf("credential endpoint must be an HTTP(S) origin without credentials, path, query, or fragment")
	}
	origin.Host = strings.ToLower(origin.Host)
	origin.Path = ""
	return origin.String(), nil
}

func validateReference(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("a non-empty credential reference is required")
	}
	return nil
}

func validateCredential(credential Credential) error {
	if _, err := NormalizeEndpoint(credential.Endpoint); err != nil {
		return err
	}
	if strings.TrimSpace(credential.Username) == "" || credential.Password == "" {
		return fmt.Errorf("credential username and password must not be empty")
	}
	return nil
}

func decode(data []byte, passphrase string) (*vault, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("vault passphrase must not be empty")
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create age identity: %w", err)
	}
	// Bound the memory/work requested by an untrusted age scrypt header.
	identity.SetMaxWorkFactor(18)
	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, fmt.Errorf("cannot unlock credentials: incorrect passphrase or invalid encrypted file")
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxVaultSize+1))
	defer clear(plaintext)
	if err != nil {
		return nil, fmt.Errorf("cannot unlock credentials: encrypted file is damaged or incomplete")
	}
	if len(plaintext) > maxVaultSize {
		return nil, fmt.Errorf("decrypted credential file exceeds %d bytes", maxVaultSize)
	}
	var contents vault
	if err := json.Unmarshal(plaintext, &contents); err != nil {
		return nil, fmt.Errorf("decrypted credential file has an invalid format")
	}
	if contents.Version != 1 || contents.Entries == nil {
		return nil, fmt.Errorf("unsupported credential file version or missing entries")
	}
	for ref, credential := range contents.Entries {
		if err := validateReference(ref); err != nil {
			return nil, err
		}
		if err := validateCredential(credential); err != nil {
			return nil, err
		}
	}
	return &contents, nil
}

func readVault(path, passphrase string) (*vault, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxVaultSize+1))
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	if len(data) > maxVaultSize {
		return nil, fmt.Errorf("encrypted credential file exceeds %d bytes", maxVaultSize)
	}
	return decode(data, passphrase)
}

func Lookup(path, passphrase, ref, endpoint string) (Credential, error) {
	if err := validateReference(ref); err != nil {
		return Credential{}, err
	}
	origin, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return Credential{}, err
	}
	contents, err := readVault(path, passphrase)
	if err != nil {
		return Credential{}, err
	}
	credential, exists := contents.Entries[ref]
	if !exists {
		return Credential{}, fmt.Errorf("credential reference not found; no other credential will be tried")
	}
	storedOrigin, err := NormalizeEndpoint(credential.Endpoint)
	if err != nil {
		return Credential{}, err
	}
	if storedOrigin != origin {
		return Credential{}, fmt.Errorf("credential reference is bound to a different endpoint; no credentials sent")
	}
	return credential, nil
}

func encode(contents *vault, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("vault passphrase must not be empty")
	}
	plaintext, err := json.Marshal(contents)
	if err != nil {
		return nil, fmt.Errorf("encode credential file")
	}
	defer clear(plaintext)
	if len(plaintext) > maxVaultSize {
		return nil, fmt.Errorf("credential file exceeds %d bytes", maxVaultSize)
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create age recipient: %w", err)
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt credential file: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt credential file: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish credential encryption: %w", err)
	}
	if ciphertext.Len() > maxVaultSize {
		return nil, fmt.Errorf("encrypted credential file exceeds %d bytes", maxVaultSize)
	}
	return ciphertext.Bytes(), nil
}

func Set(path, passphrase, ref string, credential Credential, replace bool) (err error) {
	if err := validateReference(ref); err != nil {
		return err
	}
	if err := validateCredential(credential); err != nil {
		return err
	}
	credential.Endpoint, err = NormalizeEndpoint(credential.Endpoint)
	if err != nil {
		return err
	}
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("lock credential file (another update may be in progress): %w", err)
	}
	defer func() {
		err = errors.Join(err, lock.Close(), os.Remove(lockPath))
	}()
	contents, err := readVault(path, passphrase)
	if errors.Is(err, os.ErrNotExist) {
		contents = &vault{Version: 1, Entries: make(map[string]Credential)}
	} else if err != nil {
		return err
	}
	if _, exists := contents.Entries[ref]; exists && !replace {
		return fmt.Errorf("credential reference already exists; use --replace to update it")
	}
	contents.Entries[ref] = credential
	data, err := encode(contents, passphrase)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".redfish-credentials-*.age")
	if err != nil {
		return fmt.Errorf("create encrypted temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove encrypted temporary file: %w", removeErr))
		}
	}()
	if _, err := temp.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write encrypted credential file: %w", err), temp.Close())
	}
	if err := temp.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync encrypted credential file: %w", err), temp.Close())
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close encrypted credential file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace encrypted credential file: %w", err)
	}
	return nil
}
