package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"redfish-tool/internal/redfish"
)

func TestFetchSystemsUsesAdvertisedLinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1":
			_, _ = w.Write([]byte(`{"Systems":{"@odata.id":"/custom/systems"}}`))
		case "/custom/systems":
			_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/custom/systems/1"}]}`))
		case "/custom/systems/1":
			_, _ = w.Write([]byte(`{"Id":"1","Name":"System One"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := redfish.NewClient(redfish.Config{
		Endpoint: server.URL, Username: "operator", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	systems, err := fetchSystems(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if len(systems) != 1 || string(systems[0]) != `{"Id":"1","Name":"System One"}` {
		t.Fatalf("unexpected systems result: %s", systems)
	}
}

func TestFetchSystemsReportsMissingCollectionMembers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1" {
			_, _ = w.Write([]byte(`{"Systems":{"@odata.id":"/redfish/v1/Systems"}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := redfish.NewClient(redfish.Config{
		Endpoint: server.URL, Username: "operator", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchSystems(context.Background(), client); err == nil {
		t.Fatal("expected missing Members to be reported")
	}
}

func TestExecuteSyslogPatchesOnlySelectedServerAndPreservesOtherSlots(t *testing.T) {
	var patchPayload map[string]json.RawMessage
	var patchCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Managers/Blade7/SyslogService" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{
				"ServiceEnabled": false,
				"TransmissionProtocol": "UDP",
				"MessageFormat": "Custom",
				"SyslogServers": [
					{"MemberId":"0","Enabled":false,"Address":"","Port":0,"LogType":["OperationLog"]},
					{"MemberId":"1","Enabled":false,"Address":"","Port":0,"LogType":["SecurityLog"]}
				]
			}`))
		case http.MethodPatch:
			patchCount++
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
			}
			if err := json.NewDecoder(r.Body).Decode(&patchPayload); err != nil {
				t.Errorf("decode PATCH body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client, err := redfish.NewClient(redfish.Config{
		Endpoint: server.URL, Username: "operator", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := syslogOptions{
		manager: "Blade7", serverID: "0", address: "172.26.103.27", port: 6514,
		logTypes: "OperationLog,SecurityLog,EventLog", transmissionProtocol: "TCP",
		messageFormat: "RFC3164", enable: true, apply: true,
	}
	if err := executeSyslog(context.Background(), client, opts); err != nil {
		t.Fatal(err)
	}
	if patchCount != 1 {
		t.Fatalf("expected one PATCH, got %d", patchCount)
	}

	var servers []map[string]json.RawMessage
	if err := json.Unmarshal(patchPayload["SyslogServers"], &servers); err != nil {
		t.Fatalf("decode patched servers: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected both server slots to be preserved, got %d", len(servers))
	}
	var enabled bool
	var address string
	var port int
	var logTypes []string
	if err := json.Unmarshal(servers[0]["Enabled"], &enabled); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(servers[0]["Address"], &address); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(servers[0]["Port"], &port); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(servers[0]["LogType"], &logTypes); err != nil {
		t.Fatal(err)
	}
	if !enabled || address != "172.26.103.27" || port != 6514 || len(logTypes) != 3 {
		t.Fatalf("selected slot was not configured: %s", patchPayload["SyslogServers"])
	}
	if string(servers[1]["LogType"]) != `["SecurityLog"]` {
		t.Fatalf("other slot was not preserved: %s", servers[1]["LogType"])
	}
	if string(patchPayload["ServiceEnabled"]) != "true" ||
		string(patchPayload["TransmissionProtocol"]) != `"TCP"` ||
		string(patchPayload["MessageFormat"]) != `"RFC3164"` {
		t.Fatalf("unexpected service patch fields: %s", patchPayload)
	}
}

func TestExecuteSyslogDryRunDoesNotPatch(t *testing.T) {
	var patchCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `W/"syslog-1"`)
		if r.Method == http.MethodPatch {
			patchCount++
			return
		}
		_, _ = w.Write([]byte(`{"SyslogServers":[{"MemberId":"0","Enabled":false}]}`))
	}))
	defer server.Close()

	client, err := redfish.NewClient(redfish.Config{
		Endpoint: server.URL, Username: "operator", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = executeSyslog(context.Background(), client, syslogOptions{
		manager: "Blade1", serverID: "0", address: "syslog.example.com",
		port: 6514, enable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if patchCount != 0 {
		t.Fatalf("dry run unexpectedly sent %d PATCH request(s)", patchCount)
	}
}

func TestExecuteSyslogConditionalPatch(t *testing.T) {
	tests := []struct {
		name       string
		headerETag string
		bodyETag   string
		wantMatch  string
		status     int
		wantError  string
	}{
		{name: "header", headerETag: `"version-1"`, wantMatch: `"version-1"`, status: http.StatusNoContent},
		{name: "weak header unchanged", headerETag: `W/"version-1"`, wantMatch: `W/"version-1"`, status: http.StatusOK},
		{name: "body fallback", bodyETag: `W/"version-2"`, wantMatch: `W/"version-2"`, status: http.StatusNoContent},
		{name: "header takes precedence", headerETag: `"header-version"`, bodyETag: `"body-version"`, wantMatch: `"header-version"`, status: http.StatusNoContent},
		{name: "no etag supported", status: http.StatusNoContent},
		{name: "stale version", headerETag: `"old"`, wantMatch: `"old"`, status: http.StatusPreconditionFailed, wantError: "the BMC rejected If-Match"},
		{name: "etag required but missing", status: http.StatusPreconditionFailed, wantError: "no ETag was available"},
		{name: "other error preserved", headerETag: `"version-1"`, wantMatch: `"version-1"`, status: http.StatusBadRequest, wantError: "invalid configuration"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getCount, patchCount := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/redfish/v1/Managers/Blade6/SyslogService" {
					t.Errorf("unexpected resource: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				username, password, ok := r.BasicAuth()
				if !ok || username != "operator" || password != "secret" {
					t.Error("missing or incorrect Basic authentication")
				}
				switch r.Method {
				case http.MethodGet:
					getCount++
					if test.headerETag != "" {
						w.Header().Set("ETag", test.headerETag)
					}
					if err := json.NewEncoder(w).Encode(map[string]any{
						"@odata.etag": test.bodyETag,
						"SyslogServers": []map[string]any{
							{"MemberId": "0", "Enabled": false, "Address": "", "Port": 0},
						},
					}); err != nil {
						t.Errorf("encode service: %v", err)
					}
				case http.MethodPatch:
					patchCount++
					if got := r.Header.Get("If-Match"); got != test.wantMatch {
						t.Errorf("If-Match = %q, want %q", got, test.wantMatch)
						w.WriteHeader(http.StatusPreconditionFailed)
						return
					}
					var payload map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Errorf("decode PATCH: %v", err)
					}
					if _, exists := payload["@odata.etag"]; exists {
						t.Error("ETag must not be sent as a writable property")
					}
					w.WriteHeader(test.status)
					if test.status == http.StatusBadRequest {
						_, _ = w.Write([]byte(`{"error":"invalid configuration"}`))
					}
				default:
					t.Errorf("unexpected method: %s", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()

			client, err := redfish.NewClient(redfish.Config{
				Endpoint: server.URL, Username: "operator", Password: "secret",
			})
			if err != nil {
				t.Fatal(err)
			}
			err = executeSyslog(context.Background(), client, syslogOptions{
				manager: "Blade6", serverID: "0", address: "172.26.103.27",
				port: 6514, enable: true, apply: true,
			})
			wantGets := 2
			if test.wantError != "" {
				wantGets = 1
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if getCount != wantGets || patchCount != 1 {
				t.Fatalf("got %d GETs and %d PATCHes, want %d GETs and one PATCH (no retries)", getCount, patchCount, wantGets)
			}
		})
	}
}

func TestValidateSyslogOptions(t *testing.T) {
	tests := []struct {
		name string
		opts syslogOptions
	}{
		{name: "requires explicit manager", opts: syslogOptions{serverID: "0", enable: true, address: "host", port: 6514}},
		{name: "rejects unsafe manager path", opts: syslogOptions{manager: "../Blade1", serverID: "0", enable: true, address: "host", port: 6514}},
		{name: "requires an explicit action", opts: syslogOptions{manager: "Blade1", serverID: "0"}},
		{name: "requires address and port", opts: syslogOptions{manager: "Blade1", serverID: "0", enable: true}},
		{name: "rejects invalid slot", opts: syslogOptions{manager: "Blade1", serverID: "4", disable: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateSyslogOptions(test.opts); err == nil {
				t.Fatal("expected invalid syslog options to be rejected")
			}
		})
	}
}
