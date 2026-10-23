package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"redfish-tool/internal/credentials"
)

type secretPrompt func(string) ([]byte, error)

func promptSecret(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("secret entry requires an interactive terminal; redirected input is not supported")
	}
	fmt.Fprint(os.Stderr, label)
	value, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		clear(value)
		return nil, fmt.Errorf("read hidden input: %w", err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}
	return value, nil
}

func confirmSecret(prompt secretPrompt, label string) ([]byte, error) {
	value, err := prompt(label + ": ")
	if err != nil {
		clear(value)
		return nil, err
	}
	confirmation, err := prompt("Confirm " + strings.ToLower(label) + ": ")
	defer clear(confirmation)
	if err != nil {
		clear(value)
		return nil, err
	}
	if len(value) == 0 || !bytes.Equal(value, confirmation) {
		clear(value)
		return nil, fmt.Errorf("secret is empty or confirmation does not match")
	}
	return value, nil
}

func runCredentials(args []string, prompt secretPrompt) error {
	if len(args) == 0 || args[0] != "set" {
		return fmt.Errorf("usage: redfish credentials set --file credentials.age --ref NAME --endpoint https://BMC --username USER [--replace]")
	}
	flags := flag.NewFlagSet("credentials set", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("file", "", "age-encrypted credentials file (created if missing)")
	ref := flags.String("ref", "", "explicit credential reference")
	endpoint := flags.String("endpoint", "", "BMC origin to bind this credential to")
	username := flags.String("username", "", "Redfish username")
	replace := flags.Bool("replace", false, "replace an existing reference")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || strings.TrimSpace(*ref) == "" || strings.TrimSpace(*username) == "" {
		return fmt.Errorf("--file, --ref, --endpoint, and --username are required")
	}
	origin, err := credentials.NormalizeEndpoint(*endpoint)
	if err != nil {
		return err
	}
	passphrase, err := confirmSecret(prompt, "Vault passphrase")
	if err != nil {
		return err
	}
	defer clear(passphrase)
	password, err := confirmSecret(prompt, "BMC password")
	if err != nil {
		return err
	}
	defer clear(password)
	if err := credentials.Set(*path, string(passphrase), *ref, credentials.Credential{
		Endpoint: origin, Username: *username, Password: string(password),
	}, *replace); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Encrypted credential saved.")
	return nil
}

func resolveCredentials(opts options, prompt secretPrompt) (credentials.Credential, error) {
	if (opts.credentialsFile == "") != (opts.credentialRef == "") {
		return credentials.Credential{}, fmt.Errorf("--credentials-file and --credential-ref must be specified together")
	}
	if opts.credentialsFile == "" {
		return credentials.Credential{Username: opts.username, Password: os.Getenv("REDFISH_PASSWORD")}, nil
	}
	if opts.usernameExplicit {
		return credentials.Credential{}, fmt.Errorf("--username cannot be combined with --credentials-file; the stored username is used")
	}
	if _, err := credentials.NormalizeEndpoint(opts.endpoint); err != nil {
		return credentials.Credential{}, err
	}
	if _, err := os.Stat(opts.credentialsFile); err != nil {
		return credentials.Credential{}, fmt.Errorf("open credential file: %w", err)
	}
	passphrase, err := prompt("Vault passphrase: ")
	if err != nil {
		return credentials.Credential{}, err
	}
	defer clear(passphrase)
	credential, err := credentials.Lookup(opts.credentialsFile, string(passphrase), opts.credentialRef, opts.endpoint)
	if err != nil {
		return credentials.Credential{}, fmt.Errorf("resolve vault credential (environment credentials will not be used): %w", err)
	}
	return credential, nil
}
