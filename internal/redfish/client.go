package redfish

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseSize = 8 << 20

type Client struct {
	baseURL  *url.URL
	username string
	password string
	http     *http.Client
}

type Config struct {
	Endpoint       string
	Username       string
	Password       string
	Insecure       bool
	RequestTimeout time.Duration
}

func NewClient(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	if (endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.Host == "" {
		return nil, fmt.Errorf("endpoint must be an absolute HTTP or HTTPS URL")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") {
		return nil, fmt.Errorf("endpoint must contain only the server origin, without credentials, path, query, or fragment")
	}
	if config.Username == "" || config.Password == "" {
		return nil, fmt.Errorf("username and password are required")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 30 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.Insecure} // #nosec G402 -- only enabled by explicit user opt-in

	return &Client{
		baseURL:  endpoint,
		username: config.Username,
		password: config.Password,
		http: &http.Client{
			Timeout:       config.RequestTimeout,
			Transport:     transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) Get(ctx context.Context, resourcePath string) (json.RawMessage, error) {
	resourceURL, err := c.resourceURL(resourcePath)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.SetBasicAuth(c.username, c.password)
	request.Header.Set("Accept", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", resourcePath, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", resourcePath, err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", resourcePath, maxResponseSize)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		detail := strings.TrimSpace(string(body))
		if len(detail) > 512 {
			detail = detail[:512] + "..."
		}
		return nil, fmt.Errorf("GET %s returned HTTP %s: %s", resourcePath, response.Status, detail)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("GET %s returned invalid JSON", resourcePath)
	}
	return json.RawMessage(body), nil
}

func (c *Client) Patch(ctx context.Context, resourcePath string, body []byte) error {
	resourceURL, err := c.resourceURL(resourcePath)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, resourceURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.SetBasicAuth(c.username, c.password)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("PATCH %s: %w", resourcePath, err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("read response from %s: %w", resourcePath, err)
	}
	if len(responseBody) > maxResponseSize {
		return fmt.Errorf("response from %s exceeds %d bytes", resourcePath, maxResponseSize)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		detail := strings.TrimSpace(string(responseBody))
		if len(detail) > 512 {
			detail = detail[:512] + "..."
		}
		return fmt.Errorf("PATCH %s returned HTTP %s: %s", resourcePath, response.Status, detail)
	}
	return nil
}

func (c *Client) resourceURL(resourcePath string) (*url.URL, error) {
	if !strings.HasPrefix(resourcePath, "/") || strings.HasPrefix(resourcePath, "//") {
		return nil, fmt.Errorf("resource path must be an absolute Redfish path beginning with a single slash")
	}
	reference, err := url.Parse(resourcePath)
	if err != nil {
		return nil, fmt.Errorf("parse resource path: %w", err)
	}
	if reference.IsAbs() || reference.Host != "" || reference.RawQuery != "" || reference.Fragment != "" {
		return nil, fmt.Errorf("resource path must not include a host, scheme, query, or fragment")
	}
	return c.baseURL.ResolveReference(reference), nil
}
