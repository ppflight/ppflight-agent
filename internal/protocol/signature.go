package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderKeyID     = "X-PPFlight-Key-Id"
	HeaderTimestamp = "X-PPFlight-Timestamp"
	HeaderNonce     = "X-PPFlight-Nonce"
	HeaderBodyHash  = "X-PPFlight-Content-SHA256"
	HeaderSignature = "X-PPFlight-Signature"
)

// CanonicalRequest is deliberately small and unambiguous. target must be the
// escaped request path followed by the raw query, exactly as transmitted.
func CanonicalRequest(method, target, keyID, timestamp, nonce, bodyHash string) string {
	return strings.Join([]string{
		strings.ToUpper(method), target,
		"x-ppflight-key-id:" + keyID,
		"x-ppflight-timestamp:" + timestamp,
		"x-ppflight-nonce:" + nonce,
		"x-ppflight-content-sha256:" + bodyHash,
	}, "\n")
}

func SignCanonical(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func RequestTarget(r *http.Request) string {
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	return target
}

// SignRequest installs all mandatory authentication headers. The caller owns
// the body and must pass precisely the bytes sent over HTTP.
func SignRequest(r *http.Request, body []byte, keyID string, secret []byte, now time.Time, nonce string) error {
	if keyID == "" || len(secret) == 0 {
		return errors.New("key ID and secret are required")
	}
	if nonce == "" {
		generated, err := NewNonce()
		if err != nil {
			return err
		}
		nonce = generated
	}
	stamp := strconv.FormatInt(now.UTC().Unix(), 10)
	hash := BodyHash(body)
	r.Header.Set(HeaderKeyID, keyID)
	r.Header.Set(HeaderTimestamp, stamp)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderBodyHash, hash)
	r.Header.Set(HeaderSignature, SignCanonical(secret, CanonicalRequest(r.Method, RequestTarget(r), keyID, stamp, nonce, hash)))
	return nil
}

type SecretResolver func(keyID string) ([]byte, error)

type VerifyOptions struct {
	Now     time.Time
	MaxSkew time.Duration
}

// VerifyRequest authenticates request integrity and rejects stale timestamps.
// Replay protection is intentionally a server concern: persist accepted nonces
// with their timestamp for at least MaxSkew.
func VerifyRequest(r *http.Request, body []byte, resolve SecretResolver, options VerifyOptions) error {
	if resolve == nil {
		return errors.New("secret resolver is required")
	}
	keyID, stamp, nonce := r.Header.Get(HeaderKeyID), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderNonce)
	providedHash, signature := r.Header.Get(HeaderBodyHash), r.Header.Get(HeaderSignature)
	if keyID == "" || stamp == "" || nonce == "" || providedHash == "" || signature == "" {
		return errors.New("missing PPFlight signature headers")
	}
	if len(nonce) < 16 || len(nonce) > 256 {
		return errors.New("invalid nonce")
	}
	if !hmac.Equal([]byte(providedHash), []byte(BodyHash(body))) {
		return errors.New("body hash mismatch")
	}
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxSkew := options.MaxSkew
	if maxSkew == 0 {
		maxSkew = 5 * time.Minute
	}
	if delta := now.Sub(time.Unix(seconds, 0)); delta > maxSkew || delta < -maxSkew {
		return errors.New("signature timestamp outside allowed skew")
	}
	secret, err := resolve(keyID)
	if err != nil {
		return fmt.Errorf("resolve signing key: %w", err)
	}
	expected := SignCanonical(secret, CanonicalRequest(r.Method, RequestTarget(r), keyID, stamp, nonce, providedHash))
	if !hmac.Equal([]byte(strings.ToLower(signature)), []byte(expected)) {
		return errors.New("signature mismatch")
	}
	return nil
}

func NewNonce() (string, error) {
	var bytes [24]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}
