// Package templatebootstrap verifies and invokes the immutable cloud-template
// bundle shipped with ppflight-agent. It never downloads code or accepts a
// catalog path; network image locations remain compiled into the vetted helper.
package templatebootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	DefaultRoot      = "/usr/local/lib/ppflight-agent/template-bootstrap"
	managedRoot      = "/usr/local/lib/ppflight-agent/template-bundles"
	ManifestFilename = "agent-vendor-manifest.v1.json"
	ManifestSchema   = "ppflight.agent-vendor-manifest/v1"
	DefaultMaxOutput = int64(16 << 20)
	maximumFileBytes = int64(4 << 20)
)

var (
	safeVersion  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	safeRevision = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$`)
	digestValue  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Manifest struct {
	SchemaVersion         string                `json:"schemaVersion"`
	BundleVersion         string                `json:"bundleVersion"`
	CatalogRevision       string                `json:"catalogRevision"`
	CatalogSHA256         string                `json:"catalogSha256"`
	Entrypoint            string                `json:"entrypoint"`
	Files                 []ManifestFile        `json:"files"`
	Dependencies          Dependencies          `json:"dependencies"`
	NetworkHosts          []string              `json:"networkHosts"`
	NetworkRedirectPolicy NetworkRedirectPolicy `json:"networkRedirectPolicy"`
}

type ManifestFile struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	RequiredAtRuntime bool   `json:"requiredAtRuntime"`
}

type Dependencies struct {
	Python      string   `json:"python"`
	Bash        string   `json:"bash"`
	Commands    []string `json:"commands"`
	PerlModules []string `json:"perlModules"`
}

// NetworkRedirectPolicy is a frozen security property of the vendored
// downloader. In particular, the helper may follow HTTPS redirects selected
// by an upstream, but every network connection must stay IPv4-only and every
// downloaded image remains protected by the catalog/checksum chain.
type NetworkRedirectPolicy struct {
	Allowed         bool     `json:"allowed"`
	Schemes         []string `json:"schemes"`
	AddressFamily   string   `json:"addressFamily"`
	HostPolicy      string   `json:"hostPolicy"`
	IntegrityPolicy string   `json:"integrityPolicy"`
}

type Runner struct {
	Root           string
	Python         string
	MaxOutputBytes int64
}

type Result struct {
	ExitCode int
	Stdout   []byte
	Manifest Manifest
}

func (r Runner) Verify() (Manifest, error) {
	manifest, _, err := r.verify()
	return manifest, err
}

func (r Runner) verify() (Manifest, string, error) {
	root, err := resolveRoot(r.Root)
	if err != nil {
		return Manifest{}, "", err
	}
	manifestPath, err := secureRegularPath(root, ManifestFilename)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("template bundle manifest is unsafe: %w", err)
	}
	raw, err := readBounded(manifestPath, 1<<20)
	if err != nil {
		return Manifest{}, "", errors.New("template bundle manifest cannot be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, "", errors.New("template bundle manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, "", errors.New("template bundle manifest must contain one object")
	}
	if manifest.SchemaVersion != ManifestSchema || !safeVersion.MatchString(manifest.BundleVersion) || !safeRevision.MatchString(manifest.CatalogRevision) || !digestValue.MatchString(manifest.CatalogSHA256) || manifest.Entrypoint != "tools/ppflight-template-bootstrap.py" || len(manifest.Files) < 3 || len(manifest.Files) > 32 {
		return Manifest{}, "", errors.New("template bundle manifest identity is invalid")
	}
	policy := manifest.NetworkRedirectPolicy
	if !policy.Allowed || len(policy.Schemes) != 1 || policy.Schemes[0] != "https" || policy.AddressFamily != "ipv4-only" || policy.HostPolicy != "upstream-selected" || policy.IntegrityPolicy != "catalog-sha256-and-official-checksum" {
		return Manifest{}, "", errors.New("template bundle network redirect policy is invalid")
	}
	seen := make(map[string]bool, len(manifest.Files))
	entrypointFound, catalogFound := false, false
	for _, item := range manifest.Files {
		if !validRelativePath(item.Path) || !digestValue.MatchString(item.SHA256) || seen[item.Path] {
			return Manifest{}, "", errors.New("template bundle file manifest is invalid")
		}
		seen[item.Path] = true
		path, err := secureRegularPath(root, item.Path)
		if err != nil {
			return Manifest{}, "", fmt.Errorf("template bundle file %s is unsafe", item.Path)
		}
		actual, err := fileSHA256(path)
		if err != nil || actual != item.SHA256 {
			return Manifest{}, "", fmt.Errorf("template bundle file %s failed SHA-256 verification", item.Path)
		}
		entrypointFound = entrypointFound || item.Path == manifest.Entrypoint && item.RequiredAtRuntime
		catalogFound = catalogFound || item.Path == "catalog/template-catalog.v1.json" && item.RequiredAtRuntime && item.SHA256 == manifest.CatalogSHA256
	}
	if !entrypointFound || !catalogFound {
		return Manifest{}, "", errors.New("template bundle runtime files are incomplete")
	}
	return manifest, root, nil
}

// Run verifies every bundled file before each privileged invocation and then
// calls only the fixed Python entrypoint. A helper exit code is returned with
// its typed JSON stdout; infrastructure failures are returned as Go errors.
func (r Runner) Run(ctx context.Context, args []string, stderr io.Writer) (Result, error) {
	if ctx == nil || len(args) == 0 {
		return Result{}, errors.New("template bootstrap command is required")
	}
	manifest, root, err := r.verify()
	if err != nil {
		return Result{}, err
	}
	entrypoint := filepath.Join(root, filepath.FromSlash(manifest.Entrypoint))
	python := r.Python
	if python == "" {
		python = "/usr/bin/python3"
		if runtime.GOOS == "windows" {
			python = "python"
		}
	}
	limit := r.MaxOutputBytes
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	if limit > 64<<20 {
		return Result{}, errors.New("template bootstrap output limit is invalid")
	}
	output := &boundedBuffer{remaining: limit}
	// Isolated mode ignores PYTHON* environment variables, the user site and
	// the current working directory when resolving imports. The helper is a
	// self-contained, hash-verified script and must not inherit root's Python
	// customization during a privileged template operation.
	commandArgs := append([]string{"-I", entrypoint}, args...)
	command := exec.CommandContext(ctx, python, commandArgs...)
	command.Dir = root
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PYTHONNOUSERSITE=1"}
	command.Stdin = nil
	command.Stdout = output
	if stderr == nil {
		stderr = io.Discard
	}
	command.Stderr = stderr
	err = command.Run()
	result := Result{ExitCode: 0, Stdout: append([]byte(nil), output.Bytes()...), Manifest: manifest}
	if output.exceeded {
		return Result{}, errors.New("template bootstrap output exceeded maximum size")
	}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return Result{}, errors.New("template bootstrap process could not start")
}

func resolveRoot(configured string) (string, error) {
	managed := configured == ""
	root := configured
	if managed {
		root = DefaultRoot
	}
	absolute, err := filepath.Abs(root)
	if err != nil || absolute == filepath.VolumeName(absolute)+string(filepath.Separator) {
		return "", errors.New("template bundle root is invalid")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", errors.New("template bundle root cannot be read")
	}
	if info.Mode()&os.ModeSymlink == 0 {
		if !info.IsDir() || unsafeWritable(info.Mode()) {
			return "", errors.New("template bundle root is not a protected directory")
		}
		return absolute, nil
	}
	if !managed {
		return "", errors.New("custom template bundle root must not be a symlink")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.New("managed template bundle link cannot be resolved")
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", errors.New("managed template bundle target is invalid")
	}
	relative, err := filepath.Rel(managedRoot, resolved)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) || strings.ContainsRune(relative, filepath.Separator) {
		return "", errors.New("managed template bundle target is outside the version store")
	}
	targetInfo, err := os.Lstat(resolved)
	if err != nil || !targetInfo.IsDir() || targetInfo.Mode()&os.ModeSymlink != 0 || unsafeWritable(targetInfo.Mode()) {
		return "", errors.New("managed template bundle target is not protected")
	}
	return resolved, nil
}

func validRelativePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && !strings.HasPrefix(clean, "../")
}

func secureRegularPath(root, relative string) (string, error) {
	if !validRelativePath(relative) {
		return "", errors.New("relative path is invalid")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || unsafeWritable(rootInfo.Mode()) {
		return "", errors.New("bundle root is not a real directory")
	}
	current := root
	parts := strings.Split(filepath.ToSlash(relative), "/")
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || unsafeWritable(info.Mode()) {
			return "", errors.New("bundle path contains a symlink or missing component")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", errors.New("bundle path parent is not a directory")
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return "", errors.New("bundle file is not regular")
		}
	}
	return current, nil
}

func unsafeWritable(mode os.FileMode) bool {
	return runtime.GOOS != "windows" && mode.Perm()&0o022 != 0
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("file exceeds maximum size")
	}
	return value, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > maximumFileBytes {
		return "", errors.New("bundle file size is invalid")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type boundedBuffer struct {
	bytes.Buffer
	remaining int64
	exceeded  bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if int64(len(value)) > b.remaining {
		allowed := int(b.remaining)
		if allowed > 0 {
			_, _ = b.Buffer.Write(value[:allowed])
		}
		b.remaining = 0
		b.exceeded = true
		return len(value), nil
	}
	b.remaining -= int64(len(value))
	return b.Buffer.Write(value)
}
