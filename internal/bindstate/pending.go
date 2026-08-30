package bindstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const pendingSchemaVersion = 1

var (
	pendingKind = regexp.MustCompile(`^(website|monitoring)$`)
	uuidID      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type pendingRequest struct {
	SchemaVersion int       `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	RequestID     string    `json:"requestId"`
	Fingerprint   string    `json:"fingerprint"`
	CreatedAt     time.Time `json:"createdAt"`
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

// PreparePending persists an idempotency request ID before the first network
// call. Repeating byte-equivalent binding input reuses it; changed input gets a
// fresh ID. The caller must serialize bind commands with the returned lock.
func PreparePending(stateDirectory, kind, fingerprint string) (string, *fsutil.Lock, error) {
	if !pendingKind.MatchString(kind) || !hexDigest.MatchString(fingerprint) {
		return "", nil, errors.New("invalid pending binding request")
	}
	directory, err := ensureBindingDirectory(stateDirectory)
	if err != nil {
		return "", nil, err
	}
	lock, err := fsutil.AcquireExclusive(filepath.Join(directory, ".binding-update.lock"))
	if err != nil {
		return "", nil, err
	}
	path := PendingPath(stateDirectory, kind)
	if existing, loadErr := loadPending(path); loadErr == nil && existing.Kind == kind && existing.Fingerprint == fingerprint {
		return existing.RequestID, lock, nil
	} else if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		_ = lock.Close()
		return "", nil, loadErr
	}
	requestID, err := protocol.NewID()
	if err != nil {
		_ = lock.Close()
		return "", nil, err
	}
	value := pendingRequest{SchemaVersion: pendingSchemaVersion, Kind: kind, RequestID: requestID, Fingerprint: fingerprint, CreatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(value)
	if err := writePrivateAtomic(stateDirectory, path, append(raw, '\n')); err != nil {
		_ = lock.Close()
		return "", nil, err
	}
	return requestID, lock, nil
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
	raw, err := readPrivateFile(filename, 4096)
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
	if err := decoder.Decode(&extra); err != io.EOF || value.SchemaVersion != pendingSchemaVersion || !pendingKind.MatchString(value.Kind) || !uuidID.MatchString(value.RequestID) || !hexDigest.MatchString(value.Fingerprint) || value.CreatedAt.IsZero() {
		return pendingRequest{}, errors.New("invalid pending binding state")
	}
	return value, nil
}
