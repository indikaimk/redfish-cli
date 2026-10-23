package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"redfish-tool/internal/redfish"
)

const (
	maxScanAddresses = 1024
	scanWorkers      = 8
	scanTimeout      = 5 * time.Second
)

type scanResult struct {
	IP          string
	Endpoint    string
	Status      string
	UUID        string
	ProductName string
	Error       string
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	target := flags.String("target", "", "IPv4 CIDR or inclusive start-end range (maximum 1024 addresses)")
	output := flags.String("output", "", "new YAML inventory file (required; existing files are not overwritten)")
	failuresOutput := flags.String("failures-output", "", "new YAML failures file (default: inventory basename + .failures.yaml)")
	insecure := flags.Bool("insecure", false, "skip TLS certificate verification (not recommended)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" {
		return fmt.Errorf("usage: redfish scan --target CIDR_OR_START-END --output inventory.yaml [--failures-output failures.yaml] [--insecure]")
	}
	addresses, err := scanAddresses(*target)
	if err != nil {
		return err
	}
	if *failuresOutput == "" {
		*failuresOutput = strings.TrimSuffix(*output, filepath.Ext(*output)) + ".failures.yaml"
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create inventory: %w", err)
	}
	failuresFile, err := os.OpenFile(*failuresOutput, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.Join(fmt.Errorf("create failures file: %w", err), file.Close(), os.Remove(*output))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "Scanning %d addresses anonymously over HTTPS (up to %d workers, %s per request).\n", len(addresses), scanWorkers, scanTimeout)
	results := scanHosts(ctx, addresses, func(ctx context.Context, address netip.Addr) scanResult {
		return probeHost(ctx, address.String(), "https://"+address.String(), *insecure)
	})
	inventoryErr := writeInventory(file, results, "hosts")
	failuresErr := writeInventory(failuresFile, results, "failures")
	saveErr := errors.Join(inventoryErr, failuresErr, file.Close(), failuresFile.Close())
	if saveErr != nil {
		return fmt.Errorf("save inventory %s and failures %s (files may be incomplete): %w", *output, *failuresOutput, saveErr)
	}
	found := 0
	for _, result := range results {
		if result.Status == "discovered" {
			found++
			if result.UUID == "" || result.ProductName == "" {
				fmt.Fprintf(os.Stderr, "%s: discovered, but UUID or ProductName is not advertised\n", result.IP)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "Inventory saved to %s: %d Redfish hosts. Failures saved to %s: %d results.\n", *output, found, *failuresOutput, len(results)-found)
	if ctx.Err() != nil {
		return fmt.Errorf("scan interrupted; failures file includes cancelled targets: %w", ctx.Err())
	}
	return nil
}

func scanAddresses(target string) ([]netip.Addr, error) {
	var start, end netip.Addr
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("--target must be an IPv4 CIDR or start-end IPv4 range")
		}
		if prefix.Bits() < 22 {
			return nil, fmt.Errorf("target exceeds maximum %d addresses; use /22 or a smaller subnet", maxScanAddresses)
		}
		start = prefix.Masked().Addr()
		count := 1 << (32 - prefix.Bits())
		end = start
		for i := 1; i < count; i++ {
			end = end.Next()
		}
		if prefix.Bits() <= 30 {
			start = start.Next()
			end = end.Prev()
		}
	} else {
		parts := strings.Split(target, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("--target must be an IPv4 CIDR or start-end IPv4 range")
		}
		var err error
		start, err = netip.ParseAddr(strings.TrimSpace(parts[0]))
		if err != nil || !start.Is4() {
			return nil, fmt.Errorf("invalid IPv4 range start %q", parts[0])
		}
		end, err = netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil || !end.Is4() || start.Compare(end) > 0 {
			return nil, fmt.Errorf("invalid or reversed IPv4 range end %q", parts[1])
		}
	}
	var addresses []netip.Addr
	for address := start; address.IsValid() && address.Compare(end) <= 0; address = address.Next() {
		if len(addresses) == maxScanAddresses {
			return nil, fmt.Errorf("target exceeds maximum %d addresses", maxScanAddresses)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func scanHosts(ctx context.Context, addresses []netip.Addr, probe func(context.Context, netip.Addr) scanResult) []scanResult {
	results := make([]scanResult, len(addresses))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < scanWorkers; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index] = probe(ctx, addresses[index])
			}
		}()
	}
	for index := range addresses {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	return results
}

func probeHost(ctx context.Context, ip, endpoint string, insecure bool) scanResult {
	result := scanResult{IP: ip, Endpoint: endpoint}
	client, err := redfish.NewClient(redfish.Config{
		Endpoint: endpoint, Anonymous: true, Insecure: insecure, RequestTimeout: scanTimeout,
	})
	if err != nil {
		result.Status, result.Error = "error", err.Error()
		return result
	}
	defer client.CloseIdleConnections()
	data, err := client.Get(ctx, serviceRootPath)
	if err != nil {
		result.Status, result.Error = scanErrorStatus(err), err.Error()
		return result
	}
	var root struct {
		Type           string `json:"@odata.type"`
		RedfishVersion string
		UUID           string
		Oem            struct {
			Huawei struct {
				ProductName string
			}
		}
	}
	if err := json.Unmarshal(data, &root); err != nil {
		result.Status, result.Error = "invalid_response", err.Error()
		return result
	}
	if !strings.HasPrefix(root.Type, "#ServiceRoot.") || root.RedfishVersion == "" {
		result.Status, result.Error = "invalid_response", "response is not a Redfish service root"
		return result
	}
	result.Status = "discovered"
	result.UUID, result.ProductName = root.UUID, root.Oem.Huawei.ProductName
	return result
}

func scanErrorStatus(err error) string {
	var httpErr *redfish.HTTPError
	var certificateErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var networkErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &httpErr):
		switch httpErr.StatusCode {
		case http.StatusUnauthorized:
			return "authentication_required"
		case http.StatusForbidden:
			return "forbidden"
		default:
			return "http_error"
		}
	case errors.As(err, &certificateErr), errors.As(err, &unknownAuthority):
		return "tls_error"
	case errors.As(err, &networkErr):
		if networkErr.Timeout() {
			return "timeout"
		}
		return "connection_error"
	default:
		return "invalid_response"
	}
}

func writeInventory(w io.Writer, results []scanResult, group string) error {
	if group != "hosts" && group != "failures" {
		return fmt.Errorf("invalid scan result group %q", group)
	}
	if _, err := fmt.Fprintln(w, "version: 1"); err != nil {
		return err
	}
	var entries []scanResult
	for _, result := range results {
		if (result.Status == "discovered") == (group == "hosts") {
			entries = append(entries, result)
		}
	}
	if len(entries) == 0 {
		if _, err := fmt.Fprintf(w, "%s: []\n", group); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "%s:\n", group); err != nil {
		return err
	}
	for _, result := range entries {
		fields := []struct{ name, value string }{
			{"ip", result.IP}, {"endpoint", result.Endpoint}, {"status", result.Status},
		}
		if group == "hosts" {
			fields = append(fields, struct{ name, value string }{"uuid", result.UUID}, struct{ name, value string }{"product_name", result.ProductName})
		} else {
			fields = append(fields, struct{ name, value string }{"error", result.Error})
		}
		for index, field := range fields {
			prefix := "    "
			if index == 0 {
				prefix = "  - "
			}
			if _, err := fmt.Fprintf(w, "%s%s: ", prefix, field.name); err != nil {
				return err
			}
			// JSON-quoted strings are YAML-compatible and prevent scalar injection.
			if err := json.NewEncoder(w).Encode(field.value); err != nil {
				return err
			}
		}
	}
	return nil
}
