package bindstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const (
	pendingSchemaVersion   = 2
	pendingTemplateVersion = 1
	maxPendingStateBytes   = 16 << 10
)

var (
	pendingKind = regexp.MustCompile(`^(website|monitoring)$`)
	uuidID      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type pendingRequest struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Kind          string                 `json:"kind"`
	RequestID     string                 `json:"requestId"`
	Fingerprint   string                 `json:"fingerprint"`
	Template      BindingRequestTemplate `json:"template"`
	CreatedAt     time.Time              `json:"createdAt"`
}

// BindingRequestTemplate is the non-secret, canonical portion of an
// enrollment request. It is persisted with a requestId before the first
// network call so an ambiguous retry cannot silently rediscover a different
// hostname, PVE version, device identity, or capability set. BindingCode is
// intentionally absent: it participates only in Fingerprint and is never
// written to disk.
type BindingRequestTemplate struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Domain        string               `json:"domain"`
	Endpoint      string               `json:"endpoint"`
	DeviceID      string               `json:"deviceId"`
	AgentVersion  string               `json:"agentVersion"`
	Hostname      string               `json:"hostname"`
	NodeClaim     enrollment.NodeClaim `json:"nodeClaim"`
	Capabilities  []string             `json:"capabilities"`
}

// NewBindingRequestTemplate canonicalizes the destination and copies all
// discovery-derived claims. Callers must use the returned value to construct
// both the first request and every retry.
func NewBindingRequestTemplate(domain, endpoint, deviceID, agentVersion, hostname string, nodeClaim enrollment.NodeClaim, capabilities []string) (BindingRequestTemplate, error) {
	canonical, err := canonicalBindingEndpointString(endpoint)
	if err != nil {
		return BindingRequestTemplate{}, err
	}
	value := BindingRequestTemplate{
		SchemaVersion: pendingTemplateVersion,
		Domain:        domain,
		Endpoint:      canonical,
		DeviceID:      deviceID,
		AgentVersion:  agentVersion,
		Hostname:      hostname,
		NodeClaim:     nodeClaim,
		Capabilities:  append([]string(nil), capabilities...),
	}
	if err := value.Validate(domain); err != nil {
		return BindingRequestTemplate{}, err
	}
	return value, nil
}

// Validate rejects unknown domains and validates the exact request shape that
// each enrollment service accepts, using a placeholder valid requestId/code.
// This keeps persisted templates strict without ever storing a one-time code.
func (t BindingRequestTemplate) Validate(kind string) error {
	if t.SchemaVersion != pendingTemplateVersion || t.Domain != kind || !pendingKind.MatchString(kind) || len(t.Endpoint) == 0 || len(t.Endpoint) > 2048 {
		return errors.New("invalid pending binding request template")
	}
	canonical, err := canonicalBindingEndpointString(t.Endpoint)
	if err != nil || canonical != t.Endpoint {
		return errors.New("invalid pending binding request template")
	}
	if kind == "website" {
		request := enrollment.Request{SchemaVersion: enrollment.SchemaVersion, RequestID: "123e4567-e89b-42d3-a456-426614174000", BindingCode: "PENDING-123456", DeviceID: t.DeviceID, AgentVersion: t.AgentVersion, Hostname: t.Hostname, NodeClaim: t.NodeClaim, Capabilities: append([]string(nil), t.Capabilities...)}
		if err := request.Validate(); err != nil {
			return errors.New("invalid pending binding request template")
		}
		return nil
	}
	request := monitorenrollment.Request{SchemaVersion: monitorenrollment.SchemaVersion, RequestID: "123e4567-e89b-42d3-a456-426614174000", BindingCode: "PENDING-123456", DeviceID: t.DeviceID, AgentVersion: t.AgentVersion, Hostname: t.Hostname, NodeClaim: t.NodeClaim, Capabilities: append([]string(nil), t.Capabilities...)}
	if err := request.Validate(); err != nil {
		return errors.New("invalid pending binding request template")
	}
	return nil
}

func canonicalBindingEndpointString(value string) (string, error) {
	canonical, err := canonicalBindingEndpoint(value)
	if err != nil {
		return "", err
	}
	host := canonical.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return canonical.scheme + "://" + host + ":" + canonical.port + canonical.path, nil
}

// CanonicalBindingEndpoint exposes the strict endpoint identity used by a
// pending request. It is safe to compare directly and deliberately excludes
// query, fragment, credentials, and loose default-port spellings.
func CanonicalBindingEndpoint(value string) (string, error) {
	return canonicalBindingEndpointString(value)
}

func PendingPath(stateDirectory, kind string) string {
	return filepath.Join(Directory(stateDirectory), "."+kind+"-binding-pending.json")
}

// RequestFingerprint hashes the canonical JSON request before RequestID is
// added. The binding code participates in the digest but is never persisted.
func RequestFingerprint(request any) (string, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// BindingRequestFingerprint binds the durable one-time-code request ID to the
// trust domain and the exact canonical enrollment destination as well as the
// canonical request body.  A retry cannot silently switch the endpoint after
// an ambiguous network outcome and reuse a requestId that another service may
// already have consumed.
//
// The endpoint is deliberately represented as separate scheme/host/port/path
// fields rather than a loose URL string. Queries, fragments, credentials and
// opaque forms are rejected; callers already enforce the stricter HTTPS/
// loopback policy appropriate for their domain before they reach this helper.
func BindingRequestFingerprint(domain, endpoint string, request any) (string, error) {
	if !pendingKind.MatchString(domain) {
		return "", errors.New("invalid binding request domain")
	}
	canonical, err := canonicalBindingEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	material := struct {
		Domain   string `json:"domain"`
		Endpoint struct {
			Scheme string `json:"scheme"`
			Host   string `json:"host"`
			Port   string `json:"port"`
			Path   string `json:"path"`
		} `json:"endpoint"`
		Request json.RawMessage `json:"request"`
	}{Domain: domain, Request: raw}
	material.Endpoint.Scheme = canonical.scheme
	material.Endpoint.Host = canonical.host
	material.Endpoint.Port = canonical.port
	material.Endpoint.Path = canonical.path
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

type canonicalEndpoint struct {
	scheme string
	host   string
	port   string
	path   string
}

func canonicalBindingEndpoint(value string) (canonicalEndpoint, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return canonicalEndpoint{}, errors.New("invalid binding request endpoint")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return canonicalEndpoint{}, errors.New("invalid binding request endpoint")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return canonicalEndpoint{}, errors.New("invalid binding request endpoint")
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return canonicalEndpoint{}, errors.New("invalid binding request endpoint")
	}
	// URL.Hostname removes IPv6 brackets. Normalize the textual representation
	// when possible so equivalent literal input cannot produce two identities.
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		host = parsedIP.String()
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return canonicalEndpoint{}, errors.New("invalid binding request endpoint")
	}
	return canonicalEndpoint{scheme: scheme, host: host, port: strconv.FormatUint(portNumber, 10), path: path}, nil
}

// PreparePending persists an idempotency request ID before the first network
// call. Repeating byte-equivalent binding input reuses it. A different request
// is rejected while the old outcome is ambiguous: replacing its requestId
// could orphan a binding which the service already issued. The caller must
// serialize bind commands with the returned lock.
func PreparePending(stateDirectory, kind, fingerprint string, template BindingRequestTemplate) (string, BindingRequestTemplate, *fsutil.Lock, error) {
	if !pendingKind.MatchString(kind) || !hexDigest.MatchString(fingerprint) {
		return "", BindingRequestTemplate{}, nil, errors.New("invalid pending binding request")
	}
	lock, err := AcquireTransaction(stateDirectory)
	if err != nil {
		return "", BindingRequestTemplate{}, nil, err
	}
	requestID, storedTemplate, err := PreparePendingLocked(stateDirectory, kind, fingerprint, template)
	if err != nil {
		_ = lock.Close()
		return "", BindingRequestTemplate{}, nil, err
	}
	return requestID, storedTemplate, lock, nil
}

// PreparePendingLocked is PreparePending's lock-aware form.  The caller must
// hold the process-wide lock returned by AcquireTransaction for stateDirectory
// for its entire read/modify/network/commit transaction.  It deliberately
// does not take .admin-transaction.lock itself: taking a second non-reentrant
// flock on Linux would fail before an enrollment request could be sent.
//
// Normal standalone callers should use PreparePending.  Binding commands that
// already hold AcquireTransaction must use this function so both trust domains
// remain serialized by one lock rather than accidentally self-deadlocking.
func PreparePendingLocked(stateDirectory, kind, fingerprint string, template BindingRequestTemplate) (string, BindingRequestTemplate, error) {
	if !pendingKind.MatchString(kind) || !hexDigest.MatchString(fingerprint) || template.Validate(kind) != nil {
		return "", BindingRequestTemplate{}, errors.New("invalid pending binding request")
	}
	if _, err := ensureBindingDirectory(stateDirectory); err != nil {
		return "", BindingRequestTemplate{}, err
	}
	path := PendingPath(stateDirectory, kind)
	if existing, loadErr := loadPending(path); loadErr == nil {
		if existing.Kind == kind && existing.Fingerprint == fingerprint {
			return existing.RequestID, existing.Template, nil
		}
		return "", BindingRequestTemplate{}, errors.New("pending binding request differs from the unresolved request")
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return "", BindingRequestTemplate{}, loadErr
	}
	requestID, err := protocol.NewID()
	if err != nil {
		return "", BindingRequestTemplate{}, err
	}
	value := pendingRequest{SchemaVersion: pendingSchemaVersion, Kind: kind, RequestID: requestID, Fingerprint: fingerprint, Template: template, CreatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(value)
	if err := writePrivateAtomic(stateDirectory, path, append(raw, '\n')); err != nil {
		return "", BindingRequestTemplate{}, err
	}
	return requestID, template, nil
}

// LoadPendingTemplate returns the exact immutable request template and ID for
// an unresolved ambiguous enrollment. Old pending schemas are deliberately
// rejected rather than guessed, because they cannot prove the retry will send
// the same canonical claim set consumed by the service.
func LoadPendingTemplate(stateDirectory, kind string) (string, BindingRequestTemplate, error) {
	if !pendingKind.MatchString(kind) {
		return "", BindingRequestTemplate{}, errors.New("invalid pending binding kind")
	}
	value, err := loadPending(PendingPath(stateDirectory, kind))
	if err != nil {
		return "", BindingRequestTemplate{}, err
	}
	return value.RequestID, value.Template, nil
}

// PendingRequestExists strictly reports whether a domain has an unresolved
// request. A malformed/unsafe file is an error so service startup and root
// mutations remain fail closed.
func PendingRequestExists(stateDirectory, kind string) (bool, error) {
	if !pendingKind.MatchString(kind) {
		return false, errors.New("invalid pending binding kind")
	}
	_, err := loadPending(PendingPath(stateDirectory, kind))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func ClearPending(stateDirectory, kind string) error {
	if !pendingKind.MatchString(kind) {
		return errors.New("invalid pending binding kind")
	}
	path := PendingPath(stateDirectory, kind)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing unsafe pending binding state")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return fsutil.SyncDir(Directory(stateDirectory))
}

func loadPending(filename string) (pendingRequest, error) {
	raw, err := readPrivateFile(filename, maxPendingStateBytes)
	if err != nil {
		return pendingRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value pendingRequest
	if err := decoder.Decode(&value); err != nil {
		return pendingRequest{}, errors.New("invalid pending binding state")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || value.SchemaVersion != pendingSchemaVersion || !pendingKind.MatchString(value.Kind) || !uuidID.MatchString(value.RequestID) || !hexDigest.MatchString(value.Fingerprint) || value.CreatedAt.IsZero() || value.Template.Validate(value.Kind) != nil {
		return pendingRequest{}, errors.New("invalid pending binding state")
	}
	return value, nil
}
