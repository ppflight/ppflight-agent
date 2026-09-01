package assignment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

type allowedActionsV2Golden struct {
	SchemaVersion                int    `json:"schemaVersion"`
	Name                         string `json:"name"`
	TestOnlyPrivateKeySeedBase64 string `json:"testOnlyPrivateKeySeedBase64"`
	PublicKeyBase64              string `json:"publicKeyBase64"`
	AgentRef                     string `json:"agentRef"`
	DeviceID                     string `json:"deviceId"`
	ClusterRef                   string `json:"clusterRef"`
	Cursor                       string `json:"cursor"`
	Revision                     string `json:"revision"`
	IssuedAt                     string `json:"issuedAt"`
	ExpiresAt                    string `json:"expiresAt"`
	Nonce                        string `json:"nonce"`
	SigningKeyID                 string `json:"signingKeyId"`
	AssignmentDocument           string `json:"assignmentDocument"`
	ContentSHA256                string `json:"contentSha256"`
	CanonicalPayload             string `json:"canonicalPayload"`
	SignatureBase64              string `json:"signatureBase64"`
}

func TestAllowedActionsV2CrossLanguageGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/allowed-actions-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden allowedActionsV2Golden
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&golden); err != nil {
		t.Fatal(err)
	}
	if golden.SchemaVersion != 1 || golden.Name != "signed-assignment-allowed-actions-v2" {
		t.Fatalf("unexpected golden identity: %#v", golden)
	}
	seed, err := base64.StdEncoding.DecodeString(golden.TestOnlyPrivateKeySeedBase64)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("invalid test-only seed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey, err := base64.StdEncoding.DecodeString(golden.PublicKeyBase64)
	if err != nil || !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("public key does not match test-only seed: %v", err)
	}
	revision, err := strconv.ParseUint(golden.Revision, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, golden.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, golden.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		SchemaVersion: golden.SchemaVersion, AgentRef: golden.AgentRef, DeviceID: golden.DeviceID, ClusterRef: golden.ClusterRef,
		Cursor: golden.Cursor, Revision: revision, IssuedAt: issuedAt, ExpiresAt: expiresAt, Nonce: golden.Nonce,
		ContentSHA256: golden.ContentSHA256, SigningKeyID: golden.SigningKeyID,
		AssignmentDocument: json.RawMessage(golden.AssignmentDocument), Signature: golden.SignatureBase64,
	}
	digest := sha256.Sum256(bundle.AssignmentDocument)
	if hex.EncodeToString(digest[:]) != golden.ContentSHA256 {
		t.Fatal("assignment document hash does not match golden")
	}
	payload, err := bundle.CanonicalPayload()
	if err != nil || string(payload) != golden.CanonicalPayload {
		t.Fatalf("canonical payload mismatch: %q %v", payload, err)
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		t.Fatalf("golden signature did not verify: got=%s want=%s payload=%q err=%v", bundle.Signature, base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)), payload, err)
	}
	client := &Client{agentRef: golden.AgentRef, deviceID: golden.DeviceID, clusterRef: golden.ClusterRef, signingKeyID: golden.SigningKeyID, publicKey: publicKey, maxSkew: 5 * time.Minute, now: func() time.Time { return issuedAt.Add(time.Minute) }}
	result, err := client.verify(bundle, State{Revision: revision - 1, Cursor: "assignment-cursor-3"})
	if err != nil || len(result.Document.AllowedActions) != 18 {
		t.Fatalf("golden bundle verification failed: result=%#v err=%v", result, err)
	}
}

var testNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func TestRefreshSuccessSignsRequestAndReturnsVerifiedBundle(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var gotQuery bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("deviceId") != "device-1" || r.URL.Query().Get("clusterRef") != "cluster-1" ||
			r.URL.Query().Get("cursor") != "cursor-1" || r.URL.Query().Get("version") != "7" || r.URL.Query().Get("afterRevision") != "7" || r.URL.Query().Get("wait") != "1" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		gotQuery = true
		if err := protocol.VerifyRequest(r, nil, func(keyID string) ([]byte, error) {
			if keyID != "assignment-key-1" {
				t.Fatalf("key id = %q", keyID)
			}
			return []byte("0123456789abcdef"), nil
		}, protocol.VerifyOptions{Now: testNow}); err != nil {
			t.Fatal(err)
		}
		writeBundle(t, w, signedBundle(t, private, public, nil))
	}))
	defer server.Close()
	client := testClient(t, server.URL, public, server.Client(), time.Second)
	result, err := client.Refresh(context.Background(), State{Revision: 7, Cursor: "cursor-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !gotQuery || result.State.Revision != 8 || result.State.Cursor != "cursor-2" || result.Document.Revision != "rev-8" || len(result.Document.AllowedActions) != 3 || len(result.DocumentRaw) == 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRefreshRejectsTamperingExpiryRollbackAndCrossIdentity(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Bundle){
		"signature tampering": func(b *Bundle) { b.Signature = base64.StdEncoding.EncodeToString([]byte("wrong")) },
		"content tampering": func(b *Bundle) {
			b.AssignmentDocument = json.RawMessage(`{"schemaVersion":1,"revision":"rev-8","issuedAt":"2026-08-30T12:00:00Z","assignments":[{"serviceRef":"service-1","clusterRef":"cluster-1","vmid":102,"generation":1,"instanceUuid":"instance-1","guestType":"qemu","billingState":"disabled"}]}`)
		},
		"expired":        func(b *Bundle) { b.ExpiresAt = testNow.Add(-time.Second) },
		"rollback":       func(b *Bundle) { b.Revision = 7 },
		"cross identity": func(b *Bundle) { b.DeviceID = "device-2" },
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bundle := signedBundle(t, private, public, nil)
				mutate(&bundle)
				writeBundle(t, w, bundle)
			}))
			defer server.Close()
			client := testClient(t, server.URL, public, server.Client(), time.Second)
			if _, err := client.Refresh(context.Background(), State{Revision: 7, Cursor: "cursor-1"}); err == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}

func TestRefreshRejectsRedirectAndOversizedResponse(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	redirected := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer server.Close()
	client := testClient(t, server.URL, public, server.Client(), time.Second)
	if _, err := client.Refresh(context.Background(), State{}); err == nil || redirected {
		t.Fatalf("redirect err=%v followed=%t", err, redirected)
	}

	large := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{" + strings.Repeat("x", MaxResponseBytes+1) + "}"))
	}))
	defer large.Close()
	client = testClient(t, large.URL, public, large.Client(), time.Second)
	if _, err := client.Refresh(context.Background(), State{}); err == nil {
		t.Fatal("accepted oversized response")
	}
}

func TestRefreshRejectsUnknownAndDuplicateJSONFields(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]func() []byte{
		"unknown": func() []byte {
			bundle := signedBundle(t, private, public, nil)
			body, _ := json.Marshal(bundle)
			return append(body[:len(body)-1], []byte(`,"unexpected":true}`)...)
		},
		"duplicate": func() []byte {
			bundle := signedBundle(t, private, public, nil)
			body, _ := json.Marshal(bundle)
			return append(body[:len(body)-1], []byte(`,"cursor":"other"}`)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(raw())
			}))
			defer server.Close()
			client := testClient(t, server.URL, public, server.Client(), time.Second)
			if _, err := client.Refresh(context.Background(), State{Revision: 7, Cursor: "cursor-1"}); err == nil {
				t.Fatal("accepted non-strict JSON")
			}
		})
	}
}

func TestNewClientRequiresHTTPSAndHardensTransport(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testClientConfig("http://service.example/assignments", public, nil, time.Second); err == nil {
		t.Fatal("accepted HTTP endpoint")
	}
	loopbackConfig := Config{Endpoint: "http://127.0.0.1:18080/assignments", AgentRef: "agent-1", DeviceID: "device-1", ClusterRef: "cluster-1",
		Credential:   enrollment.HMACCredential{KeyID: "assignment-key-1", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))},
		SigningKeyID: "assignment-signing-1", SigningPublicKey: public, Wait: time.Second, Timeout: 3 * time.Second, AllowLoopbackHTTP: true, ServerIPv4Allowlist: []string{"127.0.0.1"}}
	if _, err := NewClient(loopbackConfig); err != nil {
		t.Fatalf("test-only IPv4 loopback HTTP was rejected: %v", err)
	}
	loopbackConfig.Endpoint = "http://[::1]:18080/assignments"
	if _, err := NewClient(loopbackConfig); err == nil {
		t.Fatal("IPv6 loopback HTTP was accepted")
	}
	base := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: nil}}
	client, err := testClientConfig("https://service.example/assignments", public, base, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatal("transport did not disable proxy and require TLS 1.2")
	}
}

func testClient(t *testing.T, endpoint string, public ed25519.PublicKey, httpClient *http.Client, wait time.Duration) *Client {
	t.Helper()
	client, err := testClientConfig(endpoint, public, httpClient, wait)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testClientConfig(endpoint string, public ed25519.PublicKey, httpClient *http.Client, wait time.Duration) (*Client, error) {
	return NewClient(Config{Endpoint: endpoint, AgentRef: "agent-1", DeviceID: "device-1", ClusterRef: "cluster-1",
		Credential:   enrollment.HMACCredential{KeyID: "assignment-key-1", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))},
		SigningKeyID: "assignment-signing-1", SigningPublicKey: public, Wait: wait, HTTPClient: httpClient,
		Now: func() time.Time { return testNow }, Timeout: wait + 2*time.Second, ServerIPv4Allowlist: []string{"127.0.0.1"}})
}

func signedBundle(t *testing.T, private ed25519.PrivateKey, _ ed25519.PublicKey, mutate func(*Bundle)) Bundle {
	t.Helper()
	document := json.RawMessage(`{"schemaVersion":1,"revision":"rev-8","issuedAt":"2026-08-30T12:00:00Z","allowedActions":["pve.discover","vm.set-disk-io","firewall.guest.verify-ipfilter"],"assignments":[{"serviceRef":"service-1","clusterRef":"cluster-1","vmid":101,"generation":1,"instanceUuid":"instance-1","guestType":"qemu","billingState":"disabled"}]}`)
	hash := sha256.Sum256(document)
	bundle := Bundle{SchemaVersion: 1, AgentRef: "agent-1", DeviceID: "device-1", ClusterRef: "cluster-1", Cursor: "cursor-2", Revision: 8,
		IssuedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Nonce: "0123456789abcdef", ContentSHA256: hex.EncodeToString(hash[:]), SigningKeyID: "assignment-signing-1", AssignmentDocument: document}
	if mutate != nil {
		mutate(&bundle)
	}
	payload, err := bundle.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	return bundle
}

func writeBundle(t *testing.T, w http.ResponseWriter, bundle Bundle) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(bundle); err != nil {
		t.Fatal(err)
	}
}
