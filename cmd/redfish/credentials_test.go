package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redfish-tool/internal/credentials"
)

func scriptedPrompt(t *testing.T, values ...string) secretPrompt {
	t.Helper()
	index := 0
	return func(string) ([]byte, error) {
		if index == len(values) {
			t.Fatal("unexpected additional secret prompt")
		}
		value := []byte(values[index])
		index++
		return value, nil
	}
}

func TestCredentialsSetAndResolve(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.age")
	passphrase := "test vault passphrase"
	password := "test BMC password"
	err := runCredentials([]string{
		"set", "--file", path, "--ref", "host16", "--endpoint", "https://192.0.2.16", "--username", "stored-user",
	}, scriptedPrompt(t, passphrase, passphrase, password, password))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDFISH_USERNAME", "wrong-env-user")
	t.Setenv("REDFISH_PASSWORD", "wrong-env-password")
	opts := options{
		endpoint: "https://192.0.2.16", username: "wrong-env-user", credentialsFile: path, credentialRef: "host16",
	}
	credential, err := resolveCredentials(opts, scriptedPrompt(t, passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if credential.Username != "stored-user" || credential.Password != password {
		t.Fatal("vault selection used the wrong credentials")
	}
	for _, test := range []struct {
		name       string
		opts       options
		passphrase string
	}{
		{"wrong passphrase", opts, "wrong passphrase"},
		{"unknown reference", options{endpoint: opts.endpoint, credentialsFile: path, credentialRef: "unknown"}, passphrase},
		{"different host", options{endpoint: "https://192.0.2.17", credentialsFile: path, credentialRef: "host16"}, passphrase},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveCredentials(test.opts, scriptedPrompt(t, test.passphrase))
			if err == nil || got != (credentials.Credential{}) {
				t.Fatal("invalid vault selection must fail without environment fallback")
			}
			for _, secret := range []string{passphrase, password, "wrong-env-password"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("secret appeared in error")
				}
			}
		})
	}
}

func TestCredentialOptionValidationAndEnvironmentCompatibility(t *testing.T) {
	t.Setenv("REDFISH_PASSWORD", "environment-password")
	noPrompt := func(string) ([]byte, error) {
		t.Fatal("validation or environment auth must not prompt")
		return nil, nil
	}
	got, err := resolveCredentials(options{username: "environment-user"}, noPrompt)
	if err != nil || got.Username != "environment-user" || got.Password != "environment-password" {
		t.Fatal("environment authentication changed")
	}
	for _, opts := range []options{
		{credentialsFile: "missing.age"},
		{credentialRef: "host16"},
		{credentialsFile: "missing.age", credentialRef: "host16", usernameExplicit: true},
		{credentialsFile: "missing.age", credentialRef: "host16", endpoint: "https://192.0.2.16"},
	} {
		if _, err := resolveCredentials(opts, noPrompt); err == nil {
			t.Fatal("expected invalid vault options to fail")
		}
	}
}

func TestConfirmSecretFailuresClearInput(t *testing.T) {
	for _, test := range []struct {
		name         string
		confirmation []byte
		err          error
	}{
		{"mismatch", []byte("different"), nil},
		{"read error", []byte("partial"), errors.New("input failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := []byte("sensitive-value")
			calls := 0
			prompt := func(string) ([]byte, error) {
				calls++
				if calls == 1 {
					return value, nil
				}
				return test.confirmation, test.err
			}
			if _, err := confirmSecret(prompt, "Secret"); err == nil {
				t.Fatal("expected confirmation failure")
			}
			if !bytes.Equal(value, make([]byte, len(value))) ||
				!bytes.Equal(test.confirmation, make([]byte, len(test.confirmation))) {
				t.Fatal("temporary prompt buffers were not cleared")
			}
		})
	}
}

func TestCredentialsSetValidationDoesNotPromptOrCreateFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.age")
	for _, args := range [][]string{
		nil, {"get"}, {"set"}, {"set", "--file", path, "--ref", "host16", "--username", "operator"},
		{"set", "--file", path, "--ref", "host16", "--username", "operator", "--endpoint", "https://user:password@example.com"},
		{"set", "--file", path, "--ref", "host16", "--username", "operator", "--endpoint", "https://192.0.2.16", "extra"},
	} {
		if err := runCredentials(args, scriptedPrompt(t)); err == nil {
			t.Fatal("invalid credential arguments accepted")
		}
	}
	err := runCredentials([]string{
		"set", "--file", path, "--ref", "host16", "--username", "operator", "--endpoint", "https://192.0.2.16",
	}, scriptedPrompt(t, "phrase1", "phrase2"))
	if err == nil {
		t.Fatal("mismatched confirmation must fail")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid credential setup created files")
	}
}
