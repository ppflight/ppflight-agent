package admincli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

func (m *pveTemplateBridgeManager) createSafely(ctx context.Context, name string) (templateBridgeState, error) {
	ctx, cancel := context.WithTimeout(ctx, templateBridgeOperationTimeout)
	defer cancel()
	if !safeTemplateBridgeName(name) || !localPVENodeNamePattern.MatchString(m.node) {
		return templateBridgeState{}, errors.New("PVE 节点或网桥名称无效")
	}
	activePath, pendingPath, lockPath := m.templateNetworkPaths()

	// PVE serializes every network create/update/delete with this same lock. The
	// baseline must be captured while holding it, otherwise an administrator's
	// already-pending edit could be mistaken for part of our bridge creation.
	baselineLock, err := acquireTemplateBridgeNetworkLock(ctx, lockPath, m.requireRootFiles)
	if err != nil {
		return templateBridgeState{}, fmt.Errorf("获取 PVE network 配置锁失败: %w", err)
	}
	if err := requireTemplateBridgeFileAbsent(pendingPath); err != nil {
		_ = baselineLock.Close()
		return templateBridgeState{}, err
	}
	baseline, err := m.captureStableNetworkBaseline(ctx, activePath)
	if err == nil {
		if _, exists := templateBridgeSemanticIface(baseline.semantic, name); exists {
			err = fmt.Errorf("active network 中接口 %s 已存在，拒绝自动创建", name)
		}
	}
	if err == nil {
		if present, probeErr := m.kernelInterfaceExists(name); probeErr != nil {
			err = fmt.Errorf("检查同名内核接口失败: %w", probeErr)
		} else if present {
			err = fmt.Errorf("内核接口 %s 已存在，拒绝覆盖手工或其他管理器创建的网络", name)
		}
	}
	if closeErr := baselineLock.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("释放 PVE network 配置锁失败: %w", closeErr)
	}
	if err != nil {
		return templateBridgeState{}, err
	}

	path := "/nodes/" + m.node + "/network"
	if _, err := m.runner.Run(ctx, templateBridgePVESh, "create", path,
		"--iface", name,
		"--type", "bridge",
		"--autostart", "1",
		"--bridge_ports", "none",
		"--comments", templateBridgeOwnershipComment); err != nil {
		return templateBridgeState{}, err
	}

	// POST itself takes the PVE lock, but we intentionally did not hold it while
	// invoking POST (that would self-deadlock). Reacquire the exact same lock and
	// prove that no other active or pending change entered the gap.
	applyLock, err := acquireTemplateBridgeNetworkLock(ctx, lockPath, m.requireRootFiles)
	if err != nil {
		return templateBridgeState{}, fmt.Errorf("安全网桥已写入 pending network，但无法重新获取 PVE network 配置锁: %w；未自动应用，请在 PVE 检查 pending 配置", err)
	}
	lockHeld := true
	releaseApplyLock := func() error {
		if !lockHeld {
			return nil
		}
		lockHeld = false
		return applyLock.Close()
	}
	defer func() { _ = releaseApplyLock() }()

	if err := m.verifyUnchangedActiveBaseline(ctx, activePath, baseline); err != nil {
		return templateBridgeState{}, fmt.Errorf("安全网桥已写入 pending network，但 active network 在创建窗口发生变化: %w；为避免应用管理员变更，未执行 reload 或自动回滚", err)
	}
	if _, err := m.verifyOwnedBridgePending(ctx, pendingPath, baseline, name); err != nil {
		return templateBridgeState{}, fmt.Errorf("安全网桥已写入 pending network，但无法证明 pending 仅新增自有隔离桥: %w；为避免应用管理员变更，未执行 reload 或自动回滚", err)
	}
	if present, err := m.kernelInterfaceExists(name); err != nil {
		return templateBridgeState{}, fmt.Errorf("安全网桥已写入 pending network，但同名内核接口复核失败: %w；未自动应用", err)
	} else if present {
		return templateBridgeState{}, fmt.Errorf("安全网桥已写入 pending network，但创建窗口出现同名内核接口 %s；未自动应用", name)
	}

	staged, err := m.Inspect(ctx, name)
	if err != nil {
		return templateBridgeState{}, fmt.Errorf("安全网桥配置已提交但 staged PVE 回读失败: %w；未自动应用或进入模板计划", err)
	}
	if !staged.Exists || staged.Iface != name || staged.Type != "bridge" {
		return templateBridgeState{}, errors.New("安全网桥配置已提交但 staged PVE 身份回读不一致；未自动应用或进入模板计划")
	}
	if err := validateCreatedTemplateBridgeConfig(staged); err != nil {
		return templateBridgeState{}, fmt.Errorf("安全网桥配置已提交但 staged PVE 回读不安全: %w；未自动应用或进入模板计划", err)
	}
	if strings.TrimSpace(staged.Comments) != templateBridgeOwnershipComment {
		return templateBridgeState{}, errors.New("安全网桥配置已提交但 staged ownership comment 回读不一致；未自动应用或进入模板计划")
	}

	// This is the final recheck. The PVE lock stays held from here until the
	// asynchronous reload task has stopped, closing the verify-to-rename window.
	if err := m.verifyUnchangedActiveBaseline(ctx, activePath, baseline); err != nil {
		return templateBridgeState{}, fmt.Errorf("PVE active network 在最终 reload 前发生变化: %w；未自动应用", err)
	}
	if _, err := m.verifyOwnedBridgePending(ctx, pendingPath, baseline, name); err != nil {
		return templateBridgeState{}, fmt.Errorf("PVE pending network 在最终 reload 前发生变化: %w；未自动应用", err)
	}
	if present, err := m.kernelInterfaceExists(name); err != nil {
		return templateBridgeState{}, fmt.Errorf("最终 reload 前同名内核接口复核失败: %w；未自动应用", err)
	} else if present {
		return templateBridgeState{}, fmt.Errorf("最终 reload 前出现同名内核接口 %s；未自动应用", name)
	}
	applyRaw, err := m.runner.Run(ctx, templateBridgePVESh, "set", path, "--output-format", "json")
	if err != nil {
		cause := fmt.Errorf("提交 PVE network reload 失败: %w", err)
		if releaseErr := releaseApplyLock(); releaseErr != nil {
			return templateBridgeState{}, fmt.Errorf("%w；且释放 PVE network 配置锁失败: %v；为避免竞态误删管理员网络，未自动回滚，请检查接口 %s 与 pending network", cause, releaseErr, name)
		}
		return templateBridgeState{}, templateBridgeManualRecoveryError(name, cause)
	}
	upid, err := parseTemplateBridgeUPID(applyRaw)
	if err != nil {
		_ = releaseApplyLock()
		return templateBridgeState{}, fmt.Errorf("%w；reload 任务可能已经启动但状态无法跟踪，未自动回滚；请检查 PVE 任务与接口 %s", err, name)
	}
	if !strings.HasPrefix(upid, "UPID:"+m.node+":") {
		_ = releaseApplyLock()
		return templateBridgeState{}, fmt.Errorf("PVE network apply 返回了其他节点的 UPID；reload 任务可能已经启动但状态无法跟踪，未自动回滚；请检查 PVE 任务与接口 %s", name)
	}
	stopped, waitErr := m.waitForTask(ctx, upid)
	if waitErr != nil {
		if releaseErr := releaseApplyLock(); releaseErr != nil {
			return templateBridgeState{}, fmt.Errorf("%w；且释放 PVE network 配置锁失败: %v；为避免竞态误删管理员网络，未自动回滚，请检查接口 %s 与 pending network", waitErr, releaseErr, name)
		}
		if stopped {
			return templateBridgeState{}, templateBridgeManualRecoveryError(name, waitErr)
		}
		return templateBridgeState{}, fmt.Errorf("%w；PVE reload 最终状态不确定，未自动回滚；请检查任务 %s", waitErr, upid)
	}

	if err := requireTemplateBridgeFileAbsent(pendingPath); err != nil {
		if releaseErr := releaseApplyLock(); releaseErr != nil {
			return templateBridgeState{}, fmt.Errorf("PVE reload 后校验失败: %v；释放 network 锁也失败: %v", err, releaseErr)
		}
		return templateBridgeState{}, templateBridgeManualRecoveryError(name, fmt.Errorf("PVE reload 后校验失败: %w", err))
	}
	activeAfter, err := m.captureStableNetworkBaseline(ctx, activePath)
	if err == nil {
		err = verifyTemplateBridgeOnlyAddition(baseline.semantic, activeAfter.semantic, name)
	}
	if err != nil {
		if releaseErr := releaseApplyLock(); releaseErr != nil {
			return templateBridgeState{}, fmt.Errorf("PVE reload 后 active network 校验失败: %v；释放 network 锁也失败: %v", err, releaseErr)
		}
		return templateBridgeState{}, templateBridgeManualRecoveryError(name, fmt.Errorf("PVE reload 后 active network 校验失败: %w", err))
	}
	state, err := m.Inspect(ctx, name)
	if err == nil {
		err = validateCreatedTemplateBridge(name, state)
	}
	if err != nil {
		if releaseErr := releaseApplyLock(); releaseErr != nil {
			return templateBridgeState{}, fmt.Errorf("PVE reload 后严格回读失败: %v；释放 network 锁也失败: %v", err, releaseErr)
		}
		return templateBridgeState{}, templateBridgeManualRecoveryError(name, fmt.Errorf("PVE reload 后严格回读失败: %w", err))
	}
	if err := releaseApplyLock(); err != nil {
		return templateBridgeState{}, fmt.Errorf("网桥已创建但释放 PVE network 配置锁失败: %w；未进入模板计划", err)
	}
	return state, nil
}

func templateBridgeManualRecoveryError(name string, cause error) error {
	return fmt.Errorf("%w；为避免释放 PVE network 锁后竞态误删管理员网络，未自动回滚；未进入模板计划，请检查接口 %s 与 /etc/network/interfaces.new", cause, name)
}

func (m *pveTemplateBridgeManager) templateNetworkPaths() (string, string, string) {
	active := m.activeNetworkPath
	if active == "" {
		active = "/etc/network/interfaces"
	}
	pending := m.pendingNetworkPath
	if pending == "" {
		pending = "/etc/network/interfaces.new"
	}
	lock := m.networkLockPath
	if lock == "" {
		lock = "/etc/network/.pve-interfaces.lock"
	}
	return active, pending, lock
}

func acquireTemplateBridgeNetworkLock(ctx context.Context, path string, requireRoot bool) (*fsutil.Lock, error) {
	deadline := time.NewTimer(templateBridgeNetworkLockTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || requireRoot && !templateBridgeFileOwnedByRoot(info) || !templateBridgeFileModeSecure(info) {
				return nil, errors.New("PVE network lock 不是 root-only 普通文件")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		lock, err := fsutil.AcquireExclusive(path)
		if err == nil {
			info, statErr := os.Lstat(path)
			if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || requireRoot && !templateBridgeFileOwnedByRoot(info) || !templateBridgeFileModeSecure(info) {
				_ = lock.Close()
				if statErr != nil {
					return nil, statErr
				}
				return nil, errors.New("获取后的 PVE network lock 身份或权限不安全")
			}
			return lock, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("等待 PVE network lock 超时: %w", err)
		case <-ticker.C:
		}
	}
}

func requireTemplateBridgeFileAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("检测到 PVE 尚未应用的网络配置；为避免一并应用管理员变更，已拒绝继续")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("检查 PVE pending 网络配置失败: %w", err)
	}
	return nil
}

func captureTemplateBridgeSecureFile(path string, requireRoot bool) (templateBridgeFileSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return templateBridgeFileSnapshot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return templateBridgeFileSnapshot{}, errors.New("network 配置不是普通文件或为软链接")
	}
	if requireRoot && !templateBridgeFileOwnedByRoot(info) {
		return templateBridgeFileSnapshot{}, errors.New("network 配置不属于 root")
	}
	if !templateBridgeFileModeSecure(info) {
		return templateBridgeFileSnapshot{}, errors.New("network 配置可被 group/other 修改")
	}
	if info.Size() < 0 || info.Size() > templateBridgeNetworkFileMaxSize {
		return templateBridgeFileSnapshot{}, fmt.Errorf("network 配置大小 %d 超出安全上限", info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return templateBridgeFileSnapshot{}, err
	}
	if len(raw) > templateBridgeNetworkFileMaxSize {
		return templateBridgeFileSnapshot{}, errors.New("network 配置读取结果超出安全上限")
	}
	return templateBridgeFileSnapshot{SHA256: sha256Sum(raw), Size: int64(len(raw))}, nil
}

func sha256Sum(raw []byte) [32]byte {
	// Kept local so the transaction file does not expose the network contents.
	return sha256.Sum256(raw)
}

func (m *pveTemplateBridgeManager) captureStableNetworkBaseline(ctx context.Context, path string) (templateBridgeNetworkBaseline, error) {
	before, err := captureTemplateBridgeSecureFile(path, m.requireRootFiles)
	if err != nil {
		return templateBridgeNetworkBaseline{}, err
	}
	raw, err := m.runner.Run(ctx, templateBridgePerl,
		"-MPVE::INotify", "-MJSON::PP", "-e", templateBridgePerlParser, "--", path)
	if err != nil {
		return templateBridgeNetworkBaseline{}, fmt.Errorf("PVE network parser 失败: %w", err)
	}
	semantic, err := decodeTemplateBridgeNetworkSemantic(raw)
	if err != nil {
		return templateBridgeNetworkBaseline{}, err
	}
	after, err := captureTemplateBridgeSecureFile(path, m.requireRootFiles)
	if err != nil {
		return templateBridgeNetworkBaseline{}, err
	}
	if before != after {
		return templateBridgeNetworkBaseline{}, errors.New("network 配置在解析期间发生变化")
	}
	return templateBridgeNetworkBaseline{file: before, semantic: semantic}, nil
}

func (m *pveTemplateBridgeManager) verifyUnchangedActiveBaseline(ctx context.Context, path string, baseline templateBridgeNetworkBaseline) error {
	current, err := m.captureStableNetworkBaseline(ctx, path)
	if err != nil {
		return err
	}
	if current.file != baseline.file || !bytes.Equal(current.semantic.canonical, baseline.semantic.canonical) {
		return errors.New("active interfaces 文件哈希或规范化语义已变化")
	}
	return nil
}

func (m *pveTemplateBridgeManager) verifyOwnedBridgePending(ctx context.Context, path string, baseline templateBridgeNetworkBaseline, name string) (templateBridgeNetworkBaseline, error) {
	pending, err := m.captureStableNetworkBaseline(ctx, path)
	if err != nil {
		return templateBridgeNetworkBaseline{}, err
	}
	if err := verifyTemplateBridgeOnlyAddition(baseline.semantic, pending.semantic, name); err != nil {
		return templateBridgeNetworkBaseline{}, err
	}
	return pending, nil
}

func decodeTemplateBridgeNetworkSemantic(raw []byte) (templateBridgeNetworkSemantic, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return templateBridgeNetworkSemantic{}, fmt.Errorf("PVE network parser 输出不是有效 JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return templateBridgeNetworkSemantic{}, errors.New("PVE network parser 输出包含额外 JSON")
		}
		return templateBridgeNetworkSemantic{}, fmt.Errorf("PVE network parser 输出尾部无效: %w", err)
	}
	root, ok := normalizeTemplateBridgeSemanticValue(value).(map[string]any)
	if !ok {
		return templateBridgeNetworkSemantic{}, errors.New("PVE network parser 顶层不是对象")
	}
	ifaces, ok := root["ifaces"].(map[string]any)
	if !ok {
		return templateBridgeNetworkSemantic{}, errors.New("PVE network parser 缺少 ifaces 对象")
	}
	root["ifaces"] = ifaces
	options, ok := root["options"].([]any)
	if !ok {
		return templateBridgeNetworkSemantic{}, errors.New("PVE network parser 缺少 options 数组")
	}
	normalizedOptions := make([]any, 0, len(options))
	for _, option := range options {
		pair, ok := option.([]any)
		if !ok || len(pair) != 2 {
			return templateBridgeNetworkSemantic{}, errors.New("PVE network parser options 形状无效")
		}
		normalizedOptions = append(normalizedOptions, pair[1])
	}
	root["options"] = normalizedOptions
	canonical, err := json.Marshal(root)
	if err != nil {
		return templateBridgeNetworkSemantic{}, err
	}
	return templateBridgeNetworkSemantic{root: root, canonical: canonical}, nil
}

func normalizeTemplateBridgeSemanticValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			if key == "priority" {
				continue
			}
			result[key] = normalizeTemplateBridgeSemanticValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = normalizeTemplateBridgeSemanticValue(child)
		}
		return result
	default:
		return value
	}
}

func templateBridgeSemanticIface(semantic templateBridgeNetworkSemantic, name string) (map[string]any, bool) {
	ifaces, ok := semantic.root["ifaces"].(map[string]any)
	if !ok {
		return nil, false
	}
	value, exists := ifaces[name]
	if !exists {
		return nil, false
	}
	iface, ok := value.(map[string]any)
	return iface, ok
}

func verifyTemplateBridgeOnlyAddition(baseline, candidate templateBridgeNetworkSemantic, name string) error {
	if _, exists := templateBridgeSemanticIface(baseline, name); exists {
		return fmt.Errorf("原始基线已包含接口 %s", name)
	}
	iface, exists := templateBridgeSemanticIface(candidate, name)
	if !exists {
		return fmt.Errorf("candidate 缺少接口 %s", name)
	}
	if err := validateOwnedTemplateBridgeSemantic(iface); err != nil {
		return err
	}
	clone, ok := cloneTemplateBridgeSemanticValue(candidate.root).(map[string]any)
	if !ok {
		return errors.New("candidate 规范化根对象无效")
	}
	ifaces, ok := clone["ifaces"].(map[string]any)
	if !ok {
		return errors.New("candidate 规范化 ifaces 无效")
	}
	delete(ifaces, name)
	without, err := json.Marshal(clone)
	if err != nil {
		return err
	}
	if !bytes.Equal(without, baseline.canonical) {
		return errors.New("candidate 除自有网桥外还包含其他接口、网关或全局网络变更")
	}
	return nil
}

func cloneTemplateBridgeSemanticValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = cloneTemplateBridgeSemanticValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = cloneTemplateBridgeSemanticValue(child)
		}
		return result
	default:
		return value
	}
}

func validateOwnedTemplateBridgeSemantic(iface map[string]any) error {
	allowed := map[string]bool{
		"autostart": true, "bridge_fd": true, "bridge_ports": true, "bridge_stp": true,
		"comments": true, "families": true, "method": true, "method6": true, "type": true,
	}
	if len(iface) != len(allowed) {
		return fmt.Errorf("自有网桥规范字段数量为 %d，预期 %d", len(iface), len(allowed))
	}
	for key := range iface {
		if !allowed[key] {
			return fmt.Errorf("自有网桥包含未授权字段 %s", key)
		}
	}
	if !templateBridgeSemanticTruthy(iface["autostart"]) || templateBridgeSemanticScalar(iface["bridge_fd"]) != "0" || templateBridgeSemanticScalar(iface["bridge_ports"]) != "" || strings.ToLower(templateBridgeSemanticScalar(iface["bridge_stp"])) != "off" || strings.TrimSpace(templateBridgeSemanticScalar(iface["comments"])) != templateBridgeOwnershipComment || templateBridgeSemanticScalar(iface["method"]) != "manual" || templateBridgeSemanticScalar(iface["method6"]) != "manual" || templateBridgeSemanticScalar(iface["type"]) != "bridge" {
		return errors.New("自有网桥规范不是 exact 无端口、无地址、无网关隔离配置")
	}
	families, ok := iface["families"].([]any)
	if !ok || len(families) != 1 || templateBridgeSemanticScalar(families[0]) != "inet" {
		return errors.New("自有网桥 families 不是 exact [inet]")
	}
	return nil
}

func templateBridgeSemanticScalar(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case bool:
		if typed {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func templateBridgeSemanticTruthy(value any) bool {
	switch strings.ToLower(strings.TrimSpace(templateBridgeSemanticScalar(value))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
