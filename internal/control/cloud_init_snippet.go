package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

const (
	snippetPhaseValidated       = "validated"
	snippetPhaseReferenceProven = "reference_proven"
	snippetPhaseDetached        = "detached"
	snippetPhaseDeleteSubmitted = "delete_submitted"
	snippetPhaseDeleted         = "deleted"
	snippetPhaseVerified        = "verified"
	snippetPhaseSucceeded       = "succeeded"
)

var snippetPhaseOrder = map[string]int{
	"": 0, snippetPhaseValidated: 1, snippetPhaseReferenceProven: 2,
	snippetPhaseDetached: 3, snippetPhaseDeleteSubmitted: 4,
	snippetPhaseDeleted: 5, snippetPhaseVerified: 6, snippetPhaseSucceeded: 7,
}

var pveConfigDigestRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

type cloudInitSnippetDeleteP struct {
	Volume             string `json:"volume"`
	Attachment         string `json:"attachment"`
	DeleteUnreferenced *bool  `json:"deleteUnreferenced"`
}

type CloudInitSnippetDeleteResult struct {
	Detached      bool `json:"detached"`
	Deleted       bool `json:"deleted"`
	AlreadyAbsent bool `json:"alreadyAbsent"`
}

type CloudInitSnippetDeleteProgress struct {
	Phase   string
	Resumed bool
}

type snippetActionError struct {
	code string
}

func (e *snippetActionError) Error() string { return "Cloud-Init snippet action failed" }

func snippetFailure(code string) error { return &snippetActionError{code: code} }

func snippetErrorCode(err error) string {
	var actionErr *snippetActionError
	if errors.As(err, &actionErr) {
		return actionErr.code
	}
	return "CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE"
}

func validSnippetVolume(volume string) bool {
	if volume == "" || strings.TrimSpace(volume) != volume || strings.Count(volume, ":") != 1 ||
		strings.ContainsAny(volume, "\\%\x00") {
		return false
	}
	for _, r := range volume {
		if unicode.IsControl(r) {
			return false
		}
	}
	storage, suffix, ok := strings.Cut(volume, ":")
	if !ok || !storageRE.MatchString(storage) || !strings.HasPrefix(suffix, "snippets/") {
		return false
	}
	filename := strings.TrimPrefix(suffix, "snippets/")
	if filename == "" || filename == "." || filename == ".." || strings.Contains(filename, "/") ||
		strings.HasPrefix(filename, ".") || strings.HasSuffix(filename, ".") || len(filename) > 255 {
		return false
	}
	for _, r := range filename {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func snippetVolumeIdentity(volume string) (storage, digest string, err error) {
	if !validSnippetVolume(volume) {
		return "", "", errors.New("invalid snippet volume")
	}
	storage, _, _ = strings.Cut(volume, ":")
	sum := sha256.Sum256([]byte(volume))
	return storage, hex.EncodeToString(sum[:]), nil
}

type cicustomConfig struct {
	values map[string]string
}

var cicustomOrder = []string{"user", "network", "vendor", "meta"}

func parseCICustom(value string) (cicustomConfig, error) {
	result := cicustomConfig{values: map[string]string{}}
	if value == "" {
		return result, nil
	}
	for _, component := range strings.Split(value, ",") {
		key, volume, ok := strings.Cut(component, "=")
		if !ok || key == "" || volume == "" || strings.Contains(volume, "=") {
			return cicustomConfig{}, errors.New("invalid cicustom")
		}
		switch key {
		case "user", "network", "vendor", "meta":
		default:
			return cicustomConfig{}, errors.New("unknown cicustom component")
		}
		if _, duplicate := result.values[key]; duplicate || !validSnippetVolume(volume) {
			return cicustomConfig{}, errors.New("invalid cicustom component")
		}
		result.values[key] = volume
	}
	return result, nil
}

func (c cicustomConfig) withoutNetwork() string {
	parts := make([]string, 0, len(c.values))
	for _, key := range cicustomOrder {
		if key == "network" {
			continue
		}
		if value := c.values[key]; value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, ",")
}

func executeCloudInitSnippetDelete(ctx context.Context, client *pve.Client, journal CloudInitSnippetJournal, command Command, now time.Time) (json.RawMessage, string, string, error) {
	var parameters cloudInitSnippetDeleteP
	if strictParameters(command.Parameters, &parameters) != nil || !validSnippetVolume(parameters.Volume) {
		err := snippetFailure("CLOUD_INIT_SNIPPET_VOLUME_INVALID")
		return nil, "", snippetErrorCode(err), err
	}
	storage, volumeDigest, _ := snippetVolumeIdentity(parameters.Volume)
	progress, err := journal.BeginCloudInitSnippetDelete(command, storage, volumeDigest, now)
	if err != nil {
		err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
		return nil, "", snippetErrorCode(err), err
	}

	config, custom, err := readSnippetTarget(ctx, client, command)
	if err != nil {
		err = snippetFailure("CLOUD_INIT_SNIPPET_REFERENCE_MISMATCH")
		return nil, "", snippetErrorCode(err), err
	}
	phase := progress.Phase
	networkVolume := custom.values["network"]
	if snippetPhaseOrder[phase] < snippetPhaseOrder[snippetPhaseDetached] {
		if networkVolume != parameters.Volume {
			// A crash can occur after PVE accepted the digest-protected detach but
			// before the local phase fsync. A prior reference proof plus an exact
			// absent readback is sufficient to finish that one command safely.
			if phase != snippetPhaseReferenceProven || networkVolume != "" {
				err = snippetFailure("CLOUD_INIT_SNIPPET_REFERENCE_MISMATCH")
				return nil, "", snippetErrorCode(err), err
			}
			if err = scanSnippetReferences(ctx, client, command, parameters.Volume, false); err != nil {
				return nil, "", snippetErrorCode(err), err
			}
			if err = journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseDetached, time.Now().UTC()); err != nil {
				err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
				return nil, "", snippetErrorCode(err), err
			}
			phase = snippetPhaseDetached
		} else {
			if err = scanSnippetReferences(ctx, client, command, parameters.Volume, true); err != nil {
				return nil, "", snippetErrorCode(err), err
			}
			if err = journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseReferenceProven, time.Now().UTC()); err != nil {
				err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
				return nil, "", snippetErrorCode(err), err
			}
			remaining := custom.withoutNetwork()
			form := url.Values{"digest": {config.Digest}}
			if !pveConfigDigestRE.MatchString(config.Digest) {
				err = snippetFailure("CLOUD_INIT_SNIPPET_CONFIG_CONFLICT")
				return nil, "", snippetErrorCode(err), err
			}
			if remaining == "" {
				form.Set("delete", "cicustom")
			} else {
				form.Set("cicustom", remaining)
			}
			path := fmt.Sprintf("/nodes/%s/qemu/%d/config", command.Identity.NodeRef, command.Identity.VMID)
			var response json.RawMessage
			if putErr := client.Do(ctx, http.MethodPut, path, nil, form, &response); putErr != nil {
				var httpErr *pve.HTTPError
				if errors.As(putErr, &httpErr) {
					err = snippetFailure("CLOUD_INIT_SNIPPET_CONFIG_CONFLICT")
				} else {
					err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
				}
				return nil, "", snippetErrorCode(err), err
			}
			if err = journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseDetached, time.Now().UTC()); err != nil {
				err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
				return nil, "", snippetErrorCode(err), err
			}
			phase = snippetPhaseDetached
		}
	} else if networkVolume != "" {
		err = snippetFailure("CLOUD_INIT_SNIPPET_CONFIG_CONFLICT")
		return nil, "", snippetErrorCode(err), err
	}

	if snippetPhaseOrder[phase] >= snippetPhaseOrder[snippetPhaseDeleted] {
		return finishSnippetDeleteRecovery(ctx, client, journal, command, storage, volumeDigest, true)
	}
	if err = scanSnippetReferences(ctx, client, command, parameters.Volume, false); err != nil {
		return nil, "", snippetErrorCode(err), err
	}
	present, listErr := snippetVolumePresent(ctx, client, command.Identity.NodeRef, storage, volumeDigest)
	if listErr != nil {
		err = snippetFailure("CLOUD_INIT_SNIPPET_VERIFY_FAILED")
		return nil, "", snippetErrorCode(err), err
	}
	if !present {
		if err = journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseDeleted, time.Now().UTC()); err != nil {
			err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
			return nil, "", snippetErrorCode(err), err
		}
		return finishSnippetDeleteRecovery(ctx, client, journal, command, storage, volumeDigest, progress.Resumed)
	}

	var deleteResponse json.RawMessage
	if deleteErr := client.DeleteSnippetVolume(ctx, command.Identity.NodeRef, storage, parameters.Volume, &deleteResponse); deleteErr != nil {
		var httpErr *pve.HTTPError
		if errors.As(deleteErr, &httpErr) {
			err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_FAILED")
		} else {
			err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
		}
		return nil, "", snippetErrorCode(err), err
	}
	upid := ""
	var responseText string
	if json.Unmarshal(deleteResponse, &responseText) == nil && responseText != "" {
		if !upidRE.MatchString(responseText) {
			err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
			return nil, "", snippetErrorCode(err), err
		}
		upid = responseText
	}
	if upid != "" {
		return nil, upid, "", nil
	}
	if err = journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseDeleted, time.Now().UTC()); err != nil {
		err = snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
		return nil, "", snippetErrorCode(err), err
	}
	return finishSnippetDeleteRecovery(ctx, client, journal, command, storage, volumeDigest, false)
}

func readSnippetTarget(ctx context.Context, client *pve.Client, command Command) (pve.GuestConfig, cicustomConfig, error) {
	config, err := client.GuestConfig(ctx, "qemu", command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return pve.GuestConfig{}, cicustomConfig{}, err
	}
	ostype, ok := configString(config.Raw, "ostype")
	if !ok || (ostype != "l24" && ostype != "l26") {
		return pve.GuestConfig{}, cicustomConfig{}, errors.New("target is not a supported Linux QEMU guest")
	}
	value, ok := configString(config.Raw, "cicustom")
	if !ok {
		value = ""
	}
	custom, err := parseCICustom(value)
	return config, custom, err
}

func scanSnippetReferences(ctx context.Context, client *pve.Client, command Command, volume string, requireTarget bool) error {
	permissions, err := client.EffectivePermissions(ctx)
	if err != nil || permissions.Paths["/"]["VM.Audit"] != 1 || permissions.Paths["/"]["Datastore.Audit"] != 1 {
		return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
	}
	resources, err := client.ClusterResources(ctx)
	if err != nil || len(resources) == 0 {
		return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
	}
	seen := map[string]struct{}{}
	targetSeen := false
	for _, resource := range resources {
		if (resource.Type != "qemu" && resource.Type != "lxc") || !nodeRE.MatchString(resource.Node) || resource.VMID < 1 {
			return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
		}
		key := fmt.Sprintf("%s:%d", resource.Type, resource.VMID)
		if _, duplicate := seen[key]; duplicate {
			return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
		}
		seen[key] = struct{}{}
		config, readErr := client.GuestConfig(ctx, resource.Type, resource.Node, resource.VMID)
		if readErr != nil {
			return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
		}
		value, ok := configString(config.Raw, "cicustom")
		if !ok {
			value = ""
		}
		custom, parseErr := parseCICustom(value)
		if parseErr != nil {
			return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
		}
		isTarget := resource.Type == "qemu" && resource.Node == command.Identity.NodeRef && resource.VMID == command.Identity.VMID
		if isTarget {
			targetSeen = true
		}
		targetNetworkSeen := false
		for component, referenced := range custom.values {
			if referenced != volume {
				continue
			}
			if isTarget && component == "network" {
				targetNetworkSeen = true
				if !requireTarget {
					return snippetFailure("CLOUD_INIT_SNIPPET_CONFIG_CONFLICT")
				}
				continue
			}
			if !isTarget || component != "network" {
				return snippetFailure("CLOUD_INIT_SNIPPET_SHARED")
			}
		}
		if isTarget && requireTarget && !targetNetworkSeen {
			return snippetFailure("CLOUD_INIT_SNIPPET_CONFIG_CONFLICT")
		}
	}
	if !targetSeen {
		return snippetFailure("CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE")
	}
	return nil
}

func snippetVolumePresent(ctx context.Context, client *pve.Client, node, storage, volumeDigest string) (bool, error) {
	path := fmt.Sprintf("/nodes/%s/storage/%s/content", node, storage)
	var rows []struct {
		Volume  string `json:"volid"`
		Content string `json:"content"`
	}
	if err := client.Do(ctx, http.MethodGet, path, url.Values{"content": {"snippets"}}, nil, &rows); err != nil {
		return false, err
	}
	seen := map[string]struct{}{}
	for _, row := range rows {
		if row.Content != "snippets" || !validSnippetVolume(row.Volume) || !strings.HasPrefix(row.Volume, storage+":") {
			return false, errors.New("invalid snippets inventory")
		}
		if _, duplicate := seen[row.Volume]; duplicate {
			return false, errors.New("duplicate snippets inventory")
		}
		seen[row.Volume] = struct{}{}
		_, digest, _ := snippetVolumeIdentity(row.Volume)
		if digest == volumeDigest {
			return true, nil
		}
	}
	return false, nil
}

func verifySnippetAbsentByDigest(ctx context.Context, client *pve.Client, node string, vmid int, storage, volumeDigest string) error {
	config, err := client.GuestConfig(ctx, "qemu", node, vmid)
	if err != nil {
		return err
	}
	value, ok := configString(config.Raw, "cicustom")
	if !ok {
		value = ""
	}
	custom, err := parseCICustom(value)
	if err != nil {
		return err
	}
	for _, volume := range custom.values {
		_, digest, digestErr := snippetVolumeIdentity(volume)
		if digestErr != nil || digest == volumeDigest {
			return errors.New("snippet remains attached")
		}
	}
	present, err := snippetVolumePresent(ctx, client, node, storage, volumeDigest)
	if err != nil || present {
		return errors.New("snippet remains in storage")
	}
	return nil
}

func finishSnippetDeleteRecovery(ctx context.Context, client *pve.Client, journal CloudInitSnippetJournal, command Command, storage, volumeDigest string, alreadyAbsent bool) (json.RawMessage, string, string, error) {
	if err := verifySnippetAbsentByDigest(ctx, client, command.Identity.NodeRef, command.Identity.VMID, storage, volumeDigest); err != nil {
		actionErr := snippetFailure("CLOUD_INIT_SNIPPET_VERIFY_FAILED")
		return nil, "", snippetErrorCode(actionErr), actionErr
	}
	if err := journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseVerified, time.Now().UTC()); err != nil {
		actionErr := snippetFailure("CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE")
		return nil, "", snippetErrorCode(actionErr), actionErr
	}
	result, _ := json.Marshal(CloudInitSnippetDeleteResult{Detached: true, Deleted: true, AlreadyAbsent: alreadyAbsent})
	return result, "", "", nil
}

func sortedSnippetPhases() []string {
	phases := make([]string, 0, len(snippetPhaseOrder)-1)
	for phase := range snippetPhaseOrder {
		if phase != "" {
			phases = append(phases, phase)
		}
	}
	sort.Slice(phases, func(i, j int) bool { return snippetPhaseOrder[phases[i]] < snippetPhaseOrder[phases[j]] })
	return phases
}
