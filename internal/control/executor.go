package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

type Executor struct {
	Client              *pve.Client
	Mode                string
	ProductionExecution bool
}

func (e Executor) Execute(ctx context.Context, command Command, now time.Time) (Receipt, error) {
	started := now.UTC()
	receiptID, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{SchemaVersion: SchemaVersion, ReceiptID: receiptID, CommandID: command.CommandID, AgentRef: command.AgentRef, ExecutionMode: e.Mode, StartedAt: started, OperatorRef: command.OperatorRef}
	if err := validateParameters(command); err != nil {
		receipt.State, receipt.Code, receipt.DryRun, receipt.FinishedAt = "rejected", "INVALID_PARAMETERS", e.Mode != "production" || !e.ProductionExecution, time.Now().UTC()
		return receipt, err
	}
	if e.Mode != "production" || !e.ProductionExecution {
		receipt.State, receipt.Code, receipt.DryRun, receipt.FinishedAt = "dry_run", "DRY_RUN", true, time.Now().UTC()
		return receipt, nil
	}
	if e.Client == nil {
		receipt.State, receipt.Code, receipt.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
		return receipt, errors.New("PVE control client is unavailable")
	}
	upid, result, err := executePVE(ctx, e.Client, command)
	receipt.PVETaskUPID, receipt.FinishedAt = upid, time.Now().UTC()
	if err != nil {
		var httpErr *pve.HTTPError
		if errors.As(err, &httpErr) {
			receipt.State, receipt.Code = "failed", "PVE_ACTION_REJECTED"
		} else {
			// A transport or response-decoding failure can occur after PVE has
			// accepted a mutation. Mark it indeterminate so operators never treat
			// the absence of an acknowledgement as proof that nothing happened.
			receipt.State, receipt.Code = "indeterminate", "PVE_RESULT_INDETERMINATE"
		}
		return receipt, err
	}
	if upid != "" {
		// A UPID proves submission, not task success. Final task reconciliation
		// is deliberately a later control-plane capability.
		receipt.State, receipt.Code = "submitted", "PVE_TASK_SUBMITTED"
	} else {
		receipt.State, receipt.Code = "succeeded", "SUCCEEDED"
	}
	receipt.Result = result
	return receipt, nil
}

func validateParameters(command Command) error {
	switch command.Action {
	case "vm.start", "vm.shutdown", "vm.stop", "vm.reboot", "vm.delete":
		return requireEmptyObject(command.Parameters)
	case "vm.update":
		if command.Identity.GuestType != "qemu" {
			return errors.New("advanced LXC update is reserved")
		}
		_, err := parameterFields(command.Parameters, updateFieldAllowed)
		return err
	case "vm.create":
		if command.Identity.GuestType != "qemu" {
			return errors.New("LXC create is reserved")
		}
		_, err := parameterFields(command.Parameters, createFieldAllowed)
		return err
	case "vm.clone":
		if command.Identity.GuestType != "qemu" {
			return errors.New("LXC clone is reserved")
		}
		var parameters struct {
			SourceVMID int    `json:"sourceVmid"`
			Name       string `json:"name"`
			Target     string `json:"target,omitempty"`
			Storage    string `json:"storage,omitempty"`
			Pool       string `json:"pool,omitempty"`
			Full       bool   `json:"full"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || parameters.SourceVMID < 1 || parameters.Name == "" {
			return errors.New("invalid clone parameters")
		}
		return nil
	case "vm.resize":
		if command.Identity.GuestType != "qemu" {
			return errors.New("LXC resize is reserved")
		}
		var parameters struct {
			Disk string `json:"disk"`
			Size string `json:"size"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || !regexp.MustCompile(`^(scsi|virtio|sata|ide)\d{1,2}$`).MatchString(parameters.Disk) || !regexp.MustCompile(`^\+[1-9][0-9]*(K|M|G|T)$`).MatchString(parameters.Size) {
			return errors.New("invalid grow-only resize parameters")
		}
		return nil
	case "vm.set-rate":
		var parameters struct {
			Interface string `json:"interface"`
			RateMbps  string `json:"rateMbps"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || !regexp.MustCompile(`^net([0-9]|[12][0-9]|3[01])$`).MatchString(parameters.Interface) || !validRate(parameters.RateMbps) {
			return errors.New("invalid network rate parameters")
		}
		return nil
	case "vm.reset-password":
		if command.Identity.GuestType != "qemu" {
			return errors.New("QGA password reset supports qemu guests only")
		}
		var parameters struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Crypted  bool   `json:"crypted"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || parameters.Username == "" || parameters.Password == "" || len(parameters.Password) > 1024 {
			return errors.New("invalid password reset parameters")
		}
		return nil
	default:
		return errors.New("action is not implemented")
	}
}

func executePVE(ctx context.Context, client *pve.Client, command Command) (string, json.RawMessage, error) {
	base := fmt.Sprintf("/nodes/%s/%s/%d", safeSegment(command.Identity.NodeRef), command.Identity.GuestType, command.Identity.VMID)
	var method, apiPath string
	var form url.Values
	switch command.Action {
	case "vm.start", "vm.shutdown", "vm.stop", "vm.reboot":
		if err := requireEmptyObject(command.Parameters); err != nil {
			return "", nil, err
		}
		method, apiPath = http.MethodPost, base+"/status/"+strings.TrimPrefix(command.Action, "vm.")
	case "vm.update":
		fields, err := parameterFields(command.Parameters, updateFieldAllowed)
		if err != nil {
			return "", nil, err
		}
		method, apiPath, form = http.MethodPut, base+"/config", fields
	case "vm.create":
		fields, err := parameterFields(command.Parameters, createFieldAllowed)
		if err != nil {
			return "", nil, err
		}
		fields.Set("vmid", strconv.Itoa(command.Identity.VMID))
		method, apiPath, form = http.MethodPost, fmt.Sprintf("/nodes/%s/%s", safeSegment(command.Identity.NodeRef), command.Identity.GuestType), fields
	case "vm.clone":
		var parameters struct {
			SourceVMID int    `json:"sourceVmid"`
			Name       string `json:"name"`
			Target     string `json:"target,omitempty"`
			Storage    string `json:"storage,omitempty"`
			Pool       string `json:"pool,omitempty"`
			Full       bool   `json:"full"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || parameters.SourceVMID < 1 || parameters.Name == "" {
			return "", nil, errors.New("invalid clone parameters")
		}
		form = url.Values{"newid": {strconv.Itoa(command.Identity.VMID)}, "name": {safeValue(parameters.Name, 128)}, "full": {boolText(parameters.Full)}}
		for key, value := range map[string]string{"target": parameters.Target, "storage": parameters.Storage, "pool": parameters.Pool} {
			if value != "" {
				form.Set(key, safeValue(value, 128))
			}
		}
		method, apiPath = http.MethodPost, fmt.Sprintf("/nodes/%s/%s/%d/clone", safeSegment(command.Identity.NodeRef), command.Identity.GuestType, parameters.SourceVMID)
	case "vm.resize":
		var parameters struct {
			Disk string `json:"disk"`
			Size string `json:"size"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || !regexp.MustCompile(`^(scsi|virtio|sata|ide)\d{1,2}$`).MatchString(parameters.Disk) || !regexp.MustCompile(`^\+[1-9][0-9]*(K|M|G|T)$`).MatchString(parameters.Size) {
			return "", nil, errors.New("invalid grow-only resize parameters")
		}
		method, apiPath, form = http.MethodPut, base+"/resize", url.Values{"disk": {parameters.Disk}, "size": {parameters.Size}}
	case "vm.delete":
		if err := requireEmptyObject(command.Parameters); err != nil {
			return "", nil, err
		}
		method, apiPath, form = http.MethodDelete, base, url.Values{"purge": {"0"}, "destroy-unreferenced-disks": {"0"}}
	case "vm.set-rate":
		var parameters struct {
			Interface string `json:"interface"`
			RateMbps  string `json:"rateMbps"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || !regexp.MustCompile(`^net([0-9]|[12][0-9]|3[01])$`).MatchString(parameters.Interface) || !validRate(parameters.RateMbps) {
			return "", nil, errors.New("invalid network rate parameters")
		}
		current, err := client.GuestConfig(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
		if err != nil {
			return "", nil, err
		}
		var network string
		if raw, ok := current.Raw[parameters.Interface]; !ok || json.Unmarshal(raw, &network) != nil || network == "" {
			return "", nil, errors.New("target network interface does not exist")
		}
		updated, err := replaceRate(network, parameters.RateMbps)
		if err != nil {
			return "", nil, err
		}
		form = url.Values{parameters.Interface: {updated}}
		if current.Digest != "" {
			form.Set("digest", current.Digest)
		}
		method, apiPath = http.MethodPut, base+"/config"
	case "vm.reset-password":
		if command.Identity.GuestType != "qemu" {
			return "", nil, errors.New("QGA password reset supports qemu guests only")
		}
		var parameters struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Crypted  bool   `json:"crypted"`
		}
		if err := strictParameters(command.Parameters, &parameters); err != nil || parameters.Username == "" || parameters.Password == "" || len(parameters.Password) > 1024 {
			return "", nil, errors.New("invalid password reset parameters")
		}
		method, apiPath, form = http.MethodPost, base+"/agent/set-user-password", url.Values{"username": {safeValue(parameters.Username, 128)}, "password": {parameters.Password}, "crypted": {boolText(parameters.Crypted)}}
	default:
		return "", nil, errors.New("action is not implemented")
	}
	var response json.RawMessage
	if err := client.Do(ctx, method, apiPath, nil, form, &response); err != nil {
		return "", nil, err
	}
	upid := ""
	var responseText string
	if json.Unmarshal(response, &responseText) == nil && strings.HasPrefix(responseText, "UPID:") {
		upid = responseText
	}
	if len(response) > 4096 {
		response = nil
	}
	return upid, response, nil
}

func strictParameters(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("multiple parameter values")
	}
	return nil
}
func requireEmptyObject(raw json.RawMessage) error {
	var value map[string]any
	if err := strictParameters(raw, &value); err != nil {
		return err
	}
	if len(value) != 0 {
		return errors.New("action accepts no parameters")
	}
	return nil
}
func parameterFields(raw json.RawMessage, allowed func(string) bool) (url.Values, error) {
	var input struct {
		Fields map[string]string `json:"fields"`
	}
	if err := strictParameters(raw, &input); err != nil || len(input.Fields) == 0 || len(input.Fields) > 64 {
		return nil, errors.New("invalid fields parameters")
	}
	result := url.Values{}
	for key, value := range input.Fields {
		if !allowed(key) || value == "" {
			return nil, fmt.Errorf("field %q is not allowed", key)
		}
		result.Set(key, safeValue(value, 4096))
	}
	return result, nil
}
func updateFieldAllowed(key string) bool {
	switch key {
	case "name", "description", "tags", "cores", "sockets", "memory", "balloon", "onboot", "agent", "cpu", "shares", "startup":
		return true
	}
	return false
}
func createFieldAllowed(key string) bool {
	if updateFieldAllowed(key) {
		return true
	}
	switch key {
	case "ostype", "scsihw", "bios", "machine", "boot", "pool", "template", "password", "ssh-public-keys", "unprivileged", "swap", "rootfs":
		return true
	}
	return regexp.MustCompile(`^(net|scsi|virtio|sata|ide|mp)([0-9]|[12][0-9]|3[01])$`).MatchString(key)
}
func safeSegment(value string) string { return value }
func safeValue(value string, max int) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", "")
	if len(value) > max {
		return value[:max]
	}
	return value
}
func boolText(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func validRate(value string) bool {
	if !regexp.MustCompile(`^(0|[1-9][0-9]{0,5})(\.[0-9]{1,3})?$`).MatchString(value) {
		return false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	return err == nil && parsed >= 0 && parsed <= 100000
}

func replaceRate(network, rate string) (string, error) {
	if strings.ContainsAny(network, "\r\n\x00") || len(network) > 4096 {
		return "", errors.New("unsafe existing network configuration")
	}
	parts := strings.Split(network, ",")
	result := parts[:0]
	for _, part := range parts {
		if !strings.HasPrefix(strings.TrimSpace(part), "rate=") {
			result = append(result, part)
		}
	}
	if rate != "0" {
		result = append(result, "rate="+rate)
	}
	return strings.Join(result, ","), nil
}
