package redfish

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUsesBasicAuthAndReturnsJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "operator" || password != "secret" {
			t.Errorf("unexpected basic auth: %q, %q, %t", username, password, ok)
		}
		if r.URL.Path != "/redfish/v1" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Name":"Service Root"}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL, Username: "operator", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	body, err := client.Get(context.Background(), "/redfish/v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"Name":"Service Root"}` {
		t.Fatalf("unexpected response: %s", body)
	}
}

func TestGetRejectsExternalResourcePath(t *testing.T) {
	client, err := NewClient(Config{
		Endpoint: "https://192.0.2.10", Username: "operator", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), "//example.com/redfish/v1"); err == nil {
		t.Fatal("expected external resource path to be rejected")
	}
}

func TestNewClientRequiresOriginAndCredentials(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{name: "missing credentials", config: Config{Endpoint: "https://192.0.2.10"}},
		{name: "anonymous with credentials", config: Config{Endpoint: "https://192.0.2.10", Anonymous: true, Username: "u", Password: "p"}},
		{name: "endpoint path", config: Config{Endpoint: "https://192.0.2.10/redfish/v1", Username: "u", Password: "p"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewClient(test.config); err == nil {
				t.Fatal("expected invalid configuration to be rejected")
			}
		})
	}
}

func TestAnonymousClientCannotPatch(t *testing.T) {
	client, err := NewClient(Config{Endpoint: "https://192.0.2.10", Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Patch(context.Background(), "/redfish/v1", []byte(`{}`), ""); err == nil {
		t.Fatal("anonymous client must not PATCH")
	}
}
