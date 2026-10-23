package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanAddresses(t *testing.T) {
	tests := []struct {
		target string
		count  int
		first  string
		last   string
	}{
		{"192.0.2.99/24", 254, "192.0.2.1", "192.0.2.254"},
		{"192.0.2.0/31", 2, "192.0.2.0", "192.0.2.1"},
		{"192.0.2.16/32", 1, "192.0.2.16", "192.0.2.16"},
		{"192.0.0.0/22", 1022, "192.0.0.1", "192.0.3.254"},
		{"192.0.2.250-192.0.3.2", 9, "192.0.2.250", "192.0.3.2"},
		{"192.0.0.0-192.0.3.255", 1024, "192.0.0.0", "192.0.3.255"},
		{"255.255.255.255-255.255.255.255", 1, "255.255.255.255", "255.255.255.255"},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			addresses, err := scanAddresses(test.target)
			if err != nil {
				t.Fatal(err)
			}
			if len(addresses) != test.count || addresses[0].String() != test.first ||
				addresses[len(addresses)-1].String() != test.last {
				t.Fatalf("unexpected expansion: %v", addresses)
			}
		})
	}
	for _, target := range []string{
		"", "192.0.2.1", "192.0.2.0/21", "0.0.0.0/0", "::/120",
		"bad/24", "192.0.2.2-192.0.2.1", "bad-192.0.2.1",
		"192.0.2.1-bad", "192.0.0.0-192.0.4.0", "::1-::2",
	} {
		t.Run("invalid "+target, func(t *testing.T) {
			if _, err := scanAddresses(target); err == nil {
				t.Fatal("expected invalid target to be rejected")
			}
		})
	}
}

func TestProbeHostAnonymousDiscovery(t *testing.T) {
	t.Setenv("REDFISH_USERNAME", "must-not-send")
	t.Setenv("REDFISH_PASSWORD", "must-not-send")
	tests := []struct {
		name        string
		status      int
		body        string
		wantStatus  string
		wantUUID    string
		wantProduct string
	}{
		{
			name: "Huawei root", status: http.StatusOK,
			body: `{"@odata.type":"#ServiceRoot.v1_1_0.ServiceRoot","RedfishVersion":"1.0.2",
				"UUID":"5FCA285B-0488-B3E0-E911-9335CE76F877","Oem":{"Huawei":{"ProductName":"CH121 V5"}}}`,
			wantStatus: "discovered", wantUUID: "5FCA285B-0488-B3E0-E911-9335CE76F877", wantProduct: "CH121 V5",
		},
		{name: "missing optional identity", status: 200, body: `{"@odata.type":"#ServiceRoot.v1_1_0.ServiceRoot","RedfishVersion":"1.0.2"}`, wantStatus: "discovered"},
		{name: "authentication", status: 401, body: `{}`, wantStatus: "authentication_required"},
		{name: "forbidden", status: 403, body: `{}`, wantStatus: "forbidden"},
		{name: "not found", status: 404, body: `{}`, wantStatus: "http_error"},
		{name: "redirect not followed", status: 302, body: `{}`, wantStatus: "http_error"},
		{name: "HTML", status: 200, body: `<html>not Redfish</html>`, wantStatus: "invalid_response"},
		{name: "unrelated JSON", status: 200, body: `{"UUID":"not-enough"}`, wantStatus: "invalid_response"},
		{name: "wrong identity type", status: 200, body: `{"UUID":23}`, wantStatus: "invalid_response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("anonymous scan sent Authorization")
				}
				if r.Method != http.MethodGet || r.URL.Path != serviceRootPath {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			result := probeHost(context.Background(), "192.0.2.16", server.URL, false)
			if result.Status != test.wantStatus || result.UUID != test.wantUUID || result.ProductName != test.wantProduct {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.Status != "discovered" && result.Error == "" {
				t.Fatal("failure must include a diagnostic")
			}
		})
	}
}

func TestProbeHostTLSAndNetworkErrors(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"@odata.type":"#ServiceRoot.v1_1_0.ServiceRoot","RedfishVersion":"1.0.2"}`)
	}))
	defer server.Close()
	if result := probeHost(context.Background(), "127.0.0.1", server.URL, false); result.Status != "tls_error" {
		t.Fatalf("expected TLS verification error: %+v", result)
	}
	if result := probeHost(context.Background(), "127.0.0.1", server.URL, true); result.Status != "discovered" {
		t.Fatalf("explicit insecure opt-in failed: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := probeHost(ctx, "127.0.0.1", server.URL, true); result.Status != "cancelled" {
		t.Fatalf("expected cancelled: %+v", result)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if result := probeHost(ctx, "127.0.0.1", slow.URL, false); result.Status != "timeout" {
		t.Fatalf("expected timeout: %+v", result)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if result := probeHost(context.Background(), "127.0.0.1", closed.URL, false); result.Status != "connection_error" {
		t.Fatalf("expected connection error: %+v", result)
	}
}

func TestScanHostsBoundedAndOrdered(t *testing.T) {
	addresses, err := scanAddresses("192.0.2.1-192.0.2.32")
	if err != nil {
		t.Fatal(err)
	}
	var active, peak atomic.Int32
	results := scanHosts(context.Background(), addresses, func(_ context.Context, address netip.Addr) scanResult {
		current := active.Add(1)
		for previous := peak.Load(); current > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return scanResult{IP: address.String(), Status: "discovered"}
	})
	if peak.Load() > scanWorkers || peak.Load() < 2 {
		t.Fatalf("unexpected peak concurrency: %d", peak.Load())
	}
	for index, result := range results {
		if result.IP != addresses[index].String() {
			t.Fatalf("result %d is out of order: %+v", index, result)
		}
	}
}

func TestWriteInventory(t *testing.T) {
	var output bytes.Buffer
	results := []scanResult{
		{IP: "192.0.2.16", Endpoint: "https://192.0.2.16", Status: "discovered", UUID: "id", ProductName: "CH121 V5\ninjected: true"},
		{IP: "192.0.2.17", Endpoint: "https://192.0.2.17", Status: "authentication_required", Error: `HTTP 401: "protected"`},
	}
	err := writeInventory(&output, results, "hosts")
	if err != nil {
		t.Fatal(err)
	}
	want := `version: 1
hosts:
  - ip: "192.0.2.16"
    endpoint: "https://192.0.2.16"
    status: "discovered"
    uuid: "id"
    product_name: "CH121 V5\ninjected: true"
`
	if output.String() != want {
		t.Fatalf("unexpected inventory:\n%s", output.String())
	}
	output.Reset()
	if err := writeInventory(&output, results, "failures"); err != nil {
		t.Fatal(err)
	}
	want = `version: 1
failures:
  - ip: "192.0.2.17"
    endpoint: "https://192.0.2.17"
    status: "authentication_required"
    error: "HTTP 401: \"protected\""
`
	if output.String() != want {
		t.Fatalf("unexpected inventory:\n%s", output.String())
	}
	output.Reset()
	for _, group := range []string{"hosts", "failures"} {
		output.Reset()
		if err := writeInventory(&output, nil, group); err != nil {
			t.Fatal(err)
		}
		if output.String() != "version: 1\n"+group+": []\n" {
			t.Fatalf("unexpected empty output: %s", output.String())
		}
		if err := writeInventory(failingWriter{}, results, group); err == nil {
			t.Fatal("expected write failure")
		}
	}

}

func TestRunScanRejectsExistingFailuresFile(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprint("custom=", custom), func(t *testing.T) {
			dir := t.TempDir()
			inventory := filepath.Join(dir, "inventory.yaml")
			failures := filepath.Join(dir, "inventory.failures.yaml")
			args := []string{"scan", "--target", "192.0.2.16/32", "--output", inventory}
			if custom {
				failures = filepath.Join(dir, "custom.yaml")
				args = append(args, "--failures-output", failures)
			}
			if err := os.WriteFile(failures, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run(args); err == nil || !strings.Contains(err.Error(), "create failures file") {
				t.Fatalf("expected existing failures file rejection: %v", err)
			}
			data, err := os.ReadFile(failures)
			if err != nil || string(data) != "keep" {
				t.Fatalf("existing failures changed: %q, %v", data, err)
			}
			if _, err := os.Stat(inventory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("empty inventory should be cleaned up before scan: %v", err)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunScanRejectsInvalidInputAndExistingInventory(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--target", "192.0.2.0/24"}, {"--output", "unused.yaml"},
		{"--target", "0.0.0.0/0", "--output", "unused.yaml"},
		{"--target", "192.0.2.0/24", "--output", "unused.yaml", "extra"},
	} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			if err := run(append([]string{"scan"}, args...)); err == nil {
				t.Fatal("expected invalid scan arguments to fail")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"scan", "--target", "192.0.2.16/32", "--output", path})
	if err == nil || !strings.Contains(err.Error(), "create inventory") {
		t.Fatalf("expected existing output rejection: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("existing inventory changed: %q, %v", data, err)
	}
}
