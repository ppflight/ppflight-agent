// Package pve provides a small, bounded client for the Proxmox VE API.
// Collection code should use the typed read methods. The deliberately narrow
// Do method is available to a separately authorised command executor.
package pve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

var storageSegmentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

const (
	defaultTimeout      = 15 * time.Second
	defaultResponseSize = int64(8 << 20) // 8 MiB
	maxResponseSize     = int64(32 << 20)
)

// Config contains connection settings for a PVE API endpoint. TokenID has the
// usual PVE form user@realm!token-name. CAFile is optional; system roots are
// still used when it is empty.
type Config struct {
	Endpoint      string
	TokenID       string
	TokenSecret   string
	CAFile        string
	TLSServerName string
	// InsecureSkipTLS is retained only so legacy configurations fail closed.
	// PVE API credentials must never be sent with certificate verification off.
	InsecureSkipTLS  bool
	Timeout          time.Duration
	MaxResponseBytes int64
}

// Client performs authenticated, bounded requests against PVE's /api2/json.
type Client struct {
	baseURL  *url.URL
	http     *http.Client
	tokenID  string
	secret   string
	maxBytes int64
	progress func()
}

// NewClient creates a client. It does not make a network request.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("pve endpoint is required")
	}
	if strings.TrimSpace(cfg.TokenID) == "" || cfg.TokenSecret == "" {
		return nil, errors.New("pve token id and secret are required")
	}
	if cfg.InsecureSkipTLS {
		return nil, errors.New("pve insecure TLS is forbidden")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || netpolicy.ValidateIPv4URL(u) != nil {
		return nil, fmt.Errorf("invalid pve endpoint %q", cfg.Endpoint)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("pve endpoint must use http or https")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("plain HTTP is allowed only for a loopback PVE endpoint")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, errors.New("pve request timeout must be between 1s and 30s")
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = defaultResponseSize
	}
	if maxBytes > maxResponseSize {
		return nil, fmt.Errorf("pve max response size exceeds %d bytes", maxResponseSize)
	}

	if cfg.TLSServerName != "" {
		if err := ValidateTLSServerName(cfg.TLSServerName); err != nil {
			return nil, fmt.Errorf("invalid PVE TLS server name: %w", err)
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.TLSServerName}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read pve ca file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("pve ca file contains no valid certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		baseURL: u, tokenID: cfg.TokenID, secret: cfg.TokenSecret, maxBytes: maxBytes,
		http: &http.Client{Timeout: timeout, Transport: netpolicy.ApplyIPv4Only(&http.Transport{
			TLSClientConfig: tlsConfig,
			// PVE API credentials must not be sent through an ambient proxy.
			Proxy: nil,
		}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// SetProgressReporter installs a data-free callback used by the process
// watchdog. It must be called during Agent initialization, before requests are
// started. Every completed or failed bounded API request advances progress.
func (c *Client) SetProgressReporter(reporter func()) {
	if c != nil {
		c.progress = reporter
	}
}

func (c *Client) reportProgress() {
	if c != nil && c.progress != nil {
		c.progress()
	}
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || host == "127.0.0.1"
}

// Do requests an API path and decodes the PVE JSON envelope. apiPath must be
// an absolute API path below /api2/json (for example /nodes/pve1/status). It is
// intentionally a low-level primitive: callers issuing writes must validate
// their own command schema, authorisation, expiry and idempotency first.
func (c *Client) Do(ctx context.Context, method, apiPath string, query url.Values, form url.Values, out any) error {
	return c.do(ctx, method, apiPath, "", query, form, out)
}

// DeleteSnippetVolume deletes one already-validated PVE snippets volume. It is
// deliberately narrower than Do: callers cannot supply an API path, URL, or
// content type, and the volume is encoded as one opaque final path segment.
func (c *Client) DeleteSnippetVolume(ctx context.Context, node, storage, volume string, out any) error {
	if !storageSegmentRE.MatchString(node) || !storageSegmentRE.MatchString(storage) ||
		!strings.HasPrefix(volume, storage+":snippets/") || strings.ContainsAny(volume, "\\\x00\r\n") {
		return errors.New("invalid PVE snippet volume identity")
	}
	filename := strings.TrimPrefix(volume, storage+":snippets/")
	if strings.Count(volume, ":") != 1 || filename == "" || filename == "." || filename == ".." || strings.ContainsAny(filename, "/%") || strings.HasPrefix(filename, ".") || strings.HasSuffix(filename, ".") || len(filename) > 255 {
		return errors.New("invalid PVE snippet volume identity")
	}
	for _, r := range filename {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return errors.New("invalid PVE snippet volume identity")
		}
	}
	decodedPath := "/nodes/" + node + "/storage/" + storage + "/content/" + volume
	escapedVolume := strings.ReplaceAll(url.PathEscape(volume), ":", "%3A")
	escapedPath := "/nodes/" + url.PathEscape(node) + "/storage/" + url.PathEscape(storage) + "/content/" + escapedVolume
	return c.do(ctx, http.MethodDelete, decodedPath, escapedPath, nil, nil, out)
}

func (c *Client) do(ctx context.Context, method, apiPath, escapedAPIPath string, query url.Values, form url.Values, out any) error {
	defer c.reportProgress()
	if !strings.HasPrefix(apiPath, "/") || strings.Contains(apiPath, "..") {
		return fmt.Errorf("unsafe pve API path %q", apiPath)
	}
	method = strings.ToUpper(method)
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		return fmt.Errorf("unsupported pve method %q", method)
	}
	u := *c.baseURL
	u.Path = path.Join(c.baseURL.Path, "/api2/json", apiPath)
	if escapedAPIPath != "" {
		u.RawPath = path.Join(c.baseURL.EscapedPath(), "/api2/json", escapedAPIPath)
	}
	u.RawQuery = query.Encode()
	var requestBody io.Reader
	if method != http.MethodGet && form != nil {
		requestBody = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), requestBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.tokenID+"="+c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pve request %s: %w", apiPath, err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, c.maxBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read pve response: %w", err)
	}
	if int64(len(responseBody)) > c.maxBytes {
		return fmt.Errorf("pve response exceeds %d bytes", c.maxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{StatusCode: resp.StatusCode, Body: boundedText(responseBody, 1024)}
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return fmt.Errorf("decode pve response: %w", err)
	}
	if len(envelope.Data) == 0 {
		return errors.New("pve response has no data field")
	}
	// Successful PVE writes may return {"data":null}. Reads treat that as a
	// missing result, while the command executor may pass a json.RawMessage to
	// retain the explicit null without inventing a value.
	if string(envelope.Data) == "null" && method == http.MethodGet {
		return errors.New("pve response has no data field")
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("decode pve data: %w", err)
	}
	return nil
}

// get is kept private so all collection calls remain visibly read-only.
func (c *Client) get(ctx context.Context, apiPath string, query url.Values, out any) error {
	return c.Do(ctx, http.MethodGet, apiPath, query, nil, out)
}

func boundedText(value []byte, limit int) string {
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.TrimSpace(string(value))
}

// HTTPError is returned for a non-success PVE API response. Body is truncated.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("pve API returned HTTP %d: %s", e.StatusCode, e.Body)
}
