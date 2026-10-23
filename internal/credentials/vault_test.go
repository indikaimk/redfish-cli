package credentials

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestSetAndLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.age")
	passphrase := "test vault passphrase"
	first := Credential{Endpoint: "https://192.0.2.16/", Username: "operator-16", Password: "test-password-16"}
	second := Credential{Endpoint: "https://192.0.2.17", Username: "operator-17", Password: "test-password-17"}
	if err := Set(path, passphrase, "host16", first, false); err != nil {
		t.Fatal(err)
	}
	first.Endpoint = strings.TrimSuffix(first.Endpoint, "/")
	assertLookup(t, path, passphrase, "host16", first)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) {
		t.Fatal("file is not in age format")
	}
	for _, secret := range []string{passphrase, first.Username, first.Password, first.Endpoint, "host16"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("credential metadata or secret appeared as plaintext on disk")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected file permissions: %v", info.Mode())
	}
	for _, test := range []struct{ passphrase, ref, endpoint string }{
		{"wrong passphrase", "host16", first.Endpoint},
		{passphrase, "unknown", first.Endpoint},
		{passphrase, "host16", second.Endpoint},
		{passphrase, "host16", "http://192.0.2.16"},
	} {
		if _, err := Lookup(path, test.passphrase, test.ref, test.endpoint); err == nil {
			t.Fatal("expected rejected lookup")
		}
	}
	if err := Set(path, passphrase, "host16", second, false); err == nil {
		t.Fatal("existing reference must require --replace")
	}
	if err := Set(path, "wrong passphrase", "host17", second, false); err == nil {
		t.Fatal("wrong passphrase must not overwrite existing vault")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, unchanged) {
		t.Fatal("failed updates modified the original encrypted file")
	}
	if err := Set(path, passphrase, "host17", second, false); err != nil {
		t.Fatal(err)
	}
	first.Password = "updated-password-16"
	if err := Set(path, passphrase, "host16", first, true); err != nil {
		t.Fatal(err)
	}
	assertLookup(t, path, passphrase, "host16", first)
	assertLookup(t, path, passphrase, "host17", second)
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || files[0].Name() != "credentials.age" {
		t.Fatalf("unexpected files after update: %v, %v", files, err)
	}
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		t.Fatalf("standard age library cannot decrypt the stored file: %v", err)
	}
	plaintext, err := io.ReadAll(decrypted)
	defer clear(plaintext)
	if err != nil || !bytes.Contains(plaintext, []byte(first.Password)) {
		t.Fatal("stored vault did not round-trip through age")
	}
}

func assertLookup(t *testing.T, path, passphrase, ref string, want Credential) {
	t.Helper()
	got, err := Lookup(path, passphrase, ref, want.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("credential did not round-trip correctly")
	}
}

func encryptedFixture(t *testing.T, plaintext string) []byte {
	t.Helper()
	recipient, err := age.NewScryptRecipient("fixture passphrase")
	if err != nil {
		t.Fatal(err)
	}
	// Keep malformed-input tests inexpensive; production uses age's default cost.
	recipient.SetWorkFactor(10)
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestDecodeRejectsDamagedOrInvalidVaultsWithoutLeakingSecrets(t *testing.T) {
	valid := encryptedFixture(t, `{"version":1,"entries":{}}`)
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1] ^= 1
	tests := [][]byte{
		[]byte("not encrypted"),
		valid[:len(valid)-1],
		tampered,
		encryptedFixture(t, `{"version":1,"entries":{"marker-secret":`),
		encryptedFixture(t, `{"version":2,"entries":{}}`),
		encryptedFixture(t, `{"version":1}`),
		encryptedFixture(t, `{"version":1,"entries":{"marker-secret":{"endpoint":"invalid","username":"marker-secret","password":"marker-secret"}}}`),
		encryptedFixture(t, strings.Repeat("x", maxVaultSize+1)),
	}
	for index, data := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			_, err := decode(data, "fixture passphrase")
			if err == nil {
				t.Fatal("expected invalid vault rejection")
			}
			if strings.Contains(err.Error(), "marker-secret") {
				t.Fatal("error exposed decrypted data")
			}
		})
	}
	if _, err := decode(valid, ""); err == nil {
		t.Fatal("empty passphrase must fail")
	}
}

func TestSetLockAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.age")
	credential := Credential{Endpoint: "https://192.0.2.16", Username: "operator", Password: "password"}
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "passphrase", "host", credential, false); err == nil {
		t.Fatal("existing lock must block updates")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("locked update created a vault")
	}
	for _, invalid := range []Credential{
		{Endpoint: credential.Endpoint, Password: "password"},
		{Endpoint: credential.Endpoint, Username: "operator"},
		{Endpoint: "https://user:password@example.com", Username: "operator", Password: "password"},
	} {
		if err := Set(filepath.Join(dir, "invalid.age"), "passphrase", "ref", invalid, false); err == nil {
			t.Fatal("invalid credential was accepted")
		}
	}
	if err := Set(path, "passphrase", " ", credential, false); err == nil {
		t.Fatal("empty reference must fail")
	}
	oversized := filepath.Join(dir, "oversized.age")
	if err := os.WriteFile(oversized, make([]byte, maxVaultSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(oversized, "passphrase", "host", credential.Endpoint); err == nil {
		t.Fatal("oversized encrypted file must fail")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	for _, endpoint := range []string{"https://BMC.EXAMPLE/", "https://bmc.example"} {
		got, err := NormalizeEndpoint(endpoint)
		if err != nil || got != "https://bmc.example" {
			t.Fatalf("unexpected normalized endpoint: %q, %v", got, err)
		}
	}
	for _, endpoint := range []string{"", "bmc.example", "ftp://bmc.example", "https://u:p@bmc.example", "https://bmc.example/path", "https://bmc.example?q=1", "https://bmc.example?", "https://bmc.example#fragment"} {
		if _, err := NormalizeEndpoint(endpoint); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
}
