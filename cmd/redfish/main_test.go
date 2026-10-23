package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
