package main

import (
	"context"
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
