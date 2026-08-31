//go:build !windows

package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	readPrivileges    = "Sys.Audit VM.Audit VM.Monitor Datastore.Audit"
	controlPrivileges = "Sys.Modify VM.Allocate VM.Audit VM.Backup VM.Clone VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Console VM.Monitor VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback Datastore.Allocate Datastore.AllocateSpace Datastore.Audit SDN.Use"
)

type bootstrapFixture struct {
	root        string
	state       string
	log         string
	mock        string
	script      string
	environment string
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is unavailable")
	}
	bash := testBash(t)
	uid := shellNumber(t, bash, "id -u")
	gid := shellNumber(t, bash, "id -g")
	root := t.TempDir()
	state := filepath.Join(root, "state")
	for _, directory := range []string{
		filepath.Join(state, "roles"),
		filepath.Join(state, "users"),
		filepath.Join(state, "tokens"),
		filepath.Join(root, "secure"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "acls"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile("create-pve-tokens.sh")
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(raw), "readonly EXPECTED_OWNER_UID=0", fmt.Sprintf("readonly EXPECTED_OWNER_UID=%d", uid), 1)
	patched = strings.Replace(patched, "readonly EXPECTED_OWNER_GID=0", fmt.Sprintf("readonly EXPECTED_OWNER_GID=%d", gid), 1)
	script := filepath.Join(root, "create-pve-tokens.sh")
	if err := os.WriteFile(script, []byte(patched), 0o700); err != nil {
		t.Fatal(err)
	}

	mock := filepath.Join(root, "mock-pveum")
	if err := os.WriteFile(mock, []byte(mockPVEUM), 0o700); err != nil {
		t.Fatal(err)
	}
	return &bootstrapFixture{
		root:        root,
		state:       state,
		log:         filepath.Join(root, "pveum.log"),
		mock:        mock,
		script:      script,
		environment: filepath.Join(root, "secure", "agent.env"),
	}
}

func shellNumber(t *testing.T, bash, command string) int {
	t.Helper()
	output, err := exec.Command(bash, "-lc", command).Output()
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func (fixture *bootstrapFixture) run(t *testing.T, extraEnvironment []string, arguments ...string) (string, error) {
	t.Helper()
	command := exec.Command(testBash(t), append([]string{fixture.script}, arguments...)...)
	command.Env = append(os.Environ(),
		"PVEUM_BIN="+fixture.mock,
		"MOCK_STATE="+fixture.state,
		"MOCK_LOG="+fixture.log,
	)
	command.Env = append(command.Env, extraEnvironment...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (fixture *bootstrapFixture) logText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(fixture.log)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (fixture *bootstrapFixture) putRole(t *testing.T, name, privileges string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.state, "roles", name), []byte(privileges), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture *bootstrapFixture) putUser(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.state, "users", name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture *bootstrapFixture) putToken(t *testing.T, user, token string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.state, "tokens", user+"!"+token), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture *bootstrapFixture) putACL(t *testing.T, path, kind, identity, role string) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(fixture.state, "acls"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "%s\t%s\t%s\t%s\n", path, kind, identity, role); err != nil {
		t.Fatal(err)
	}
}

func (fixture *bootstrapFixture) aclText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture.state, "acls"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (fixture *bootstrapFixture) injectWriteEnvFailureAfterReplace(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(fixture.script)
	if err != nil {
		t.Fatal(err)
	}
	const original = "    mark_restore_needed()\n    os.replace(temp_name, base, src_dir_fd=directory, dst_dir_fd=directory)\n    os.fsync(directory)\nexcept (OSError, ValueError):"
	const replacement = "    mark_restore_needed()\n    os.replace(temp_name, base, src_dir_fd=directory, dst_dir_fd=directory)\n    raise OSError('injected post-replace failure')\nexcept (OSError, ValueError):"
	patched := strings.Replace(string(raw), original, replacement, 1)
	if patched == string(raw) {
		t.Fatal("could not inject post-replace environment failure")
	}
	if err := os.WriteFile(fixture.script, []byte(patched), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestPVEBootstrapFreshNotFoundCreatesBothTokensWithoutLeakingSecrets(t *testing.T) {
	fixture := newBootstrapFixture(t)
	output, err := fixture.run(t, nil, "--write-env", fixture.environment, "--control-pool", "production")
	if err != nil {
		t.Fatalf("fresh bootstrap failed: %v\n%s\nlog:\n%s", err, output, fixture.logText(t))
	}
	if strings.Contains(output, "SECRET-") {
		t.Fatalf("one-time token secret leaked to process output: %q", output)
	}
	raw, err := os.ReadFile(fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	environment := string(raw)
	for _, required := range []string{
		"PVE_READ_TOKEN_ID=ppflight-agent@pve!collector\n",
		"PVE_READ_TOKEN_SECRET=SECRET-collector\n",
		"PVE_CONTROL_TOKEN_ID=ppflight-control@pve!executor\n",
		"PVE_CONTROL_TOKEN_SECRET=SECRET-executor\n",
	} {
		if !strings.Contains(environment, required) {
			t.Fatalf("environment file is missing %q: %q", required, environment)
		}
	}
	info, err := os.Stat(fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("environment mode = %o, want 0600", info.Mode().Perm())
	}
	log := fixture.logText(t)
	if strings.Contains(log, "SECRET-") {
		t.Fatalf("one-time token secret leaked to pveum argv log: %q", log)
	}
	for _, required := range []string{
		"user\ttoken\tadd\tppflight-agent@pve\tcollector",
		"user\ttoken\tadd\tppflight-control@pve\texecutor",
		"acl\tmodify\t/pool/production\t--users\tppflight-control@pve",
		"acl\tmodify\t/pool/production\t--tokens\tppflight-control@pve!executor",
	} {
		if !strings.Contains(log, required) {
			t.Fatalf("mock pveum log is missing %q:\n%s", required, log)
		}
	}
}

func TestPVEBootstrapFreshGlobalControlCreatesExactDedicatedACLs(t *testing.T) {
	fixture := newBootstrapFixture(t)
	output, err := fixture.run(t, nil, "--write-env", fixture.environment, "--control-global-acl")
	if err != nil {
		t.Fatalf("fresh global bootstrap failed: %v\n%s\nlog:\n%s", err, output, fixture.logText(t))
	}
	if strings.Contains(output, "SECRET-") {
		t.Fatalf("bootstrap leaked one-time token secret: %q", output)
	}
	for _, required := range []string{
		"acl\tmodify\t/\t--users\tppflight-agent@pve\t--roles\tPPFlightAgentAudit",
		"acl\tmodify\t/\t--tokens\tppflight-agent@pve!collector\t--roles\tPPFlightAgentAudit",
		"acl\tmodify\t/\t--users\tppflight-control@pve\t--roles\tPPFlightAgentControl",
		"acl\tmodify\t/\t--tokens\tppflight-control@pve!executor\t--roles\tPPFlightAgentControl",
	} {
		if !strings.Contains(fixture.logText(t), required) {
			t.Fatalf("global bootstrap log is missing %q:\n%s", required, fixture.logText(t))
		}
	}
	raw, err := os.ReadFile(fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"PVE_READ_TOKEN_ID=", "PVE_READ_TOKEN_SECRET=", "PVE_CONTROL_TOKEN_ID=", "PVE_CONTROL_TOKEN_SECRET="} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("private environment is missing %q", required)
		}
	}
}

func TestPVEBootstrapAllowsRootOwnedParentWithNonRootGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a directory group requires root")
	}
	fixture := newBootstrapFixture(t)
	parent := filepath.Dir(fixture.environment)
	group := 1
	if shellNumber(t, testBash(t), "id -g") == group {
		group = 2
	}
	if err := os.Chown(parent, 0, group); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run(t, nil, "--write-env", fixture.environment)
	if err != nil {
		t.Fatalf("root-owned 0750 parent with non-root group was rejected: %v\n%s", err, output)
	}
	info, err := os.Stat(fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("environment mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestPVEBootstrapRejectsExistingRolePrivilegeMismatchBeforeMutation(t *testing.T) {
	fixture := newBootstrapFixture(t)
	fixture.putRole(t, "PPFlightAgentControl", "Sys.Audit")
	output, err := fixture.run(t, nil, "--write-env", fixture.environment)
	if err == nil {
		t.Fatalf("role mismatch unexpectedly succeeded: %s", output)
	}
	if !strings.Contains(output, "does not exactly match") {
		t.Fatalf("missing role mismatch diagnostic: %s", output)
	}
	log := fixture.logText(t)
	for _, forbidden := range []string{"\tadd\t", "acl\tmodify", "token\tremove"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("role mismatch performed mutation %q:\n%s", forbidden, log)
		}
	}
}

func TestPVEBootstrapSecondTokenFailureRollsBackOnlyCreatedObjects(t *testing.T) {
	fixture := newBootstrapFixture(t)
	output, err := fixture.run(t, []string{"MOCK_FAIL_SECOND_TOKEN=1"}, "--write-env", fixture.environment)
	if err == nil {
		t.Fatalf("second token failure unexpectedly succeeded: %s", output)
	}
	if strings.Contains(output, "SECRET-") {
		t.Fatalf("one-time token secret leaked to process output: %q", output)
	}
	log := fixture.logText(t)
	if !strings.Contains(log, "user\ttoken\tremove\tppflight-agent@pve\tcollector") {
		t.Fatalf("first token was not rolled back:\n%s", log)
	}
	if strings.Contains(log, "user\ttoken\tremove\tppflight-control@pve\texecutor") {
		t.Fatalf("script tried to remove the token whose creation failed:\n%s", log)
	}
	if _, err := os.Stat(fixture.environment); !os.IsNotExist(err) {
		t.Fatalf("environment should not exist after rollback, stat error=%v", err)
	}
}

func TestPVEBootstrapEnvironmentCommitFailureRollsBackBothTokens(t *testing.T) {
	fixture := newBootstrapFixture(t)
	output, err := fixture.run(t, []string{
		"MOCK_REPLACE_ENV_WITH_SYMLINK=1",
		"MOCK_ENV_PATH=" + fixture.environment,
	}, "--write-env", fixture.environment)
	if err == nil {
		t.Fatalf("environment commit race unexpectedly succeeded: %s", output)
	}
	if strings.Contains(output, "SECRET-") {
		t.Fatalf("one-time token secret leaked to process output: %q", output)
	}
	log := fixture.logText(t)
	for _, required := range []string{
		"user\ttoken\tremove\tppflight-control@pve\texecutor",
		"user\ttoken\tremove\tppflight-agent@pve\tcollector",
		"acl\tdelete\t/\t--tokens\tppflight-agent@pve!collector\t--roles\tPPFlightAgentAudit",
		"acl\tdelete\t/\t--users\tppflight-agent@pve\t--roles\tPPFlightAgentAudit",
	} {
		if !strings.Contains(log, required) {
			t.Fatalf("environment failure did not roll back %q:\n%s", required, log)
		}
	}
	if got := fixture.aclText(t); got != "" {
		t.Fatalf("environment failure left ACLs created by this run:\n%s", got)
	}
}

func TestPVEBootstrapPostReplaceFailureRestoresExistingEnvironment(t *testing.T) {
	fixture := newBootstrapFixture(t)
	const originalEnvironment = "KEEP_EXISTING_VALUE=unchanged\n"
	if err := os.WriteFile(fixture.environment, []byte(originalEnvironment), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.injectWriteEnvFailureAfterReplace(t)
	output, err := fixture.run(t, nil, "--write-env", fixture.environment)
	if err == nil {
		t.Fatalf("post-replace environment failure unexpectedly succeeded: %s", output)
	}
	if strings.Contains(output, "SECRET-") {
		t.Fatalf("one-time token secret leaked to process output: %q", output)
	}
	raw, err := os.ReadFile(fixture.environment)
	if err != nil {
		t.Fatalf("rollback did not restore the original environment: %v", err)
	}
	if got := string(raw); got != originalEnvironment {
		t.Fatalf("environment after post-replace rollback = %q, want %q", got, originalEnvironment)
	}
	for _, required := range []string{
		"user\ttoken\tremove\tppflight-control@pve\texecutor",
		"user\ttoken\tremove\tppflight-agent@pve\tcollector",
		"acl\tdelete\t/\t--tokens\tppflight-agent@pve!collector\t--roles\tPPFlightAgentAudit",
		"acl\tdelete\t/\t--users\tppflight-agent@pve\t--roles\tPPFlightAgentAudit",
	} {
		if !strings.Contains(fixture.logText(t), required) {
			t.Fatalf("post-replace failure did not roll back %q:\n%s", required, fixture.logText(t))
		}
	}
	if got := fixture.aclText(t); got != "" {
		t.Fatalf("post-replace failure left ACLs created by this run:\n%s", got)
	}
}

func TestPVEBootstrapRollbackPreservesExistingACLAndObjects(t *testing.T) {
	fixture := newBootstrapFixture(t)
	fixture.putRole(t, "PPFlightAgentControl", controlPrivileges)
	fixture.putUser(t, "ppflight-control@pve")
	fixture.putACL(t, "/pool/production", "user", "ppflight-control@pve", "PPFlightAgentControl")

	output, err := fixture.run(t, []string{
		"MOCK_REPLACE_ENV_WITH_SYMLINK=1",
		"MOCK_ENV_PATH=" + fixture.environment,
	}, "--write-env", fixture.environment, "--control-pool", "production")
	if err == nil {
		t.Fatalf("environment commit race unexpectedly succeeded: %s", output)
	}
	for _, required := range []string{
		"role\tdelete\tPPFlightAgentAudit",
		"user\tdelete\tppflight-agent@pve",
		"acl\tdelete\t/pool/production\t--tokens\tppflight-control@pve!executor\t--roles\tPPFlightAgentControl",
	} {
		if !strings.Contains(fixture.logText(t), required) {
			t.Fatalf("rollback log is missing %q:\n%s", required, fixture.logText(t))
		}
	}
	if _, err := os.Stat(filepath.Join(fixture.state, "roles", "PPFlightAgentControl")); err != nil {
		t.Fatalf("rollback deleted existing control role: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.state, "users", "ppflight-control@pve")); err != nil {
		t.Fatalf("rollback deleted existing control user: %v", err)
	}
	if got := fixture.aclText(t); got != "/pool/production\tuser\tppflight-control@pve\tPPFlightAgentControl\n" {
		t.Fatalf("rollback did not preserve precisely the pre-existing ACL: %q", got)
	}
}

func TestPVEBootstrapACLOnlyUsesExistingDedicatedIdentityAndNeverRoot(t *testing.T) {
	fixture := newBootstrapFixture(t)
	fixture.putRole(t, "PPFlightAgentControl", controlPrivileges)
	fixture.putUser(t, "ppflight-control@pve")
	fixture.putToken(t, "ppflight-control@pve", "executor")
	output, err := fixture.run(t, nil, "--acl-only", "--control-pool", "production", "--control-scope", "/vms/101")
	if err != nil {
		t.Fatalf("ACL-only update failed: %v\n%s\nlog:\n%s", err, output, fixture.logText(t))
	}
	log := fixture.logText(t)
	for _, forbidden := range []string{"role\tadd", "user\tadd", "token\tadd", "acl\tmodify\t/\t"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("ACL-only mode performed forbidden operation %q:\n%s", forbidden, log)
		}
	}
	for _, required := range []string{
		"acl\tmodify\t/pool/production\t--users\tppflight-control@pve",
		"acl\tmodify\t/pool/production\t--tokens\tppflight-control@pve!executor",
		"acl\tmodify\t/vms/101\t--users\tppflight-control@pve",
		"acl\tmodify\t/vms/101\t--tokens\tppflight-control@pve!executor",
	} {
		if !strings.Contains(log, required) {
			t.Fatalf("ACL-only log is missing %q:\n%s", required, log)
		}
	}
	if _, err := os.Stat(fixture.environment); !os.IsNotExist(err) {
		t.Fatalf("ACL-only mode must not write an environment file, stat error=%v", err)
	}
}

func TestPVEBootstrapACLOnlyCanGrantDedicatedGlobalControlWithoutSecrets(t *testing.T) {
	fixture := newBootstrapFixture(t)
	fixture.putRole(t, "PPFlightAgentControl", controlPrivileges)
	fixture.putUser(t, "ppflight-control@pve")
	fixture.putToken(t, "ppflight-control@pve", "executor")
	output, err := fixture.run(t, nil, "--acl-only", "--control-global-acl")
	if err != nil {
		t.Fatalf("global ACL-only update failed: %v\n%s\nlog:\n%s", err, output, fixture.logText(t))
	}
	log := fixture.logText(t)
	for _, forbidden := range []string{"role\tadd", "user\tadd", "token\tadd", "SECRET-"} {
		if strings.Contains(log+output, forbidden) {
			t.Fatalf("global ACL-only mode performed forbidden operation %q:\n%s", forbidden, log)
		}
	}
	for _, required := range []string{
		"acl\tmodify\t/\t--users\tppflight-control@pve",
		"acl\tmodify\t/\t--tokens\tppflight-control@pve!executor",
	} {
		if !strings.Contains(log, required) {
			t.Fatalf("global ACL-only log is missing %q:\n%s", required, log)
		}
	}
	if _, err := os.Stat(fixture.environment); !os.IsNotExist(err) {
		t.Fatalf("global ACL-only mode must not write an environment file, stat error=%v", err)
	}
}

func TestPVEBootstrapEnvironmentSymlinkFailsBeforeRBACMutation(t *testing.T) {
	fixture := newBootstrapFixture(t)
	if err := os.Symlink("/dev/null", fixture.environment); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run(t, nil, "--write-env", fixture.environment)
	if err == nil {
		t.Fatalf("symlink environment unexpectedly succeeded: %s", output)
	}
	if !strings.Contains(output, "no-follow/owner/mode/atomic-write/fsync preflight") {
		t.Fatalf("missing secure preflight diagnostic: %s", output)
	}
	log := fixture.logText(t)
	for _, forbidden := range []string{"\tadd\t", "acl\tmodify", "token\tremove"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("failed environment preflight performed mutation %q:\n%s", forbidden, log)
		}
	}
}

const mockPVEUM = `#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
: "${MOCK_STATE:?}"
: "${MOCK_LOG:?}"
{
  first_argument=1
  for argument in "$@"; do
    if [[ $first_argument -eq 1 ]]; then
      printf '%s' "$argument"
      first_argument=0
    else
      printf '\t%s' "$argument"
    fi
  done
  printf '\n'
} >>"$MOCK_LOG"

emit_roles() {
  local first=1 file name privileges
  printf '['
  for file in "$MOCK_STATE"/roles/*; do
    [[ -f $file ]] || continue
    name=${file##*/}; privileges=$(<"$file")
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"roleid":"%s","privs":"%s"}' "$name" "$privileges"
  done
  printf ']\n'
}
emit_users() {
  local first=1 file name
  printf '['
  for file in "$MOCK_STATE"/users/*; do
    [[ -f $file ]] || continue
    name=${file##*/}
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"userid":"%s"}' "$name"
  done
  printf ']\n'
}
emit_tokens() {
  local user=$1 first=1 file identity token
  printf '['
  for file in "$MOCK_STATE"/tokens/"$user"'!'*; do
    [[ -f $file ]] || continue
    identity=${file##*/}; token=${identity#*!}
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"tokenid":"%s"}' "$token"
  done
  printf ']\n'
}
emit_acls() {
  local first=1 path kind identity role
  printf '['
  while IFS=$'\t' read -r path kind identity role; do
    [[ -n $path ]] || continue
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"path":"%s","type":"%s","ugid":"%s","roleid":"%s"}' "$path" "$kind" "$identity" "$role"
  done <"$MOCK_STATE/acls"
  printf ']\n'
}

add_acl() {
  local path=$1 kind=$2 identity=$3 role=$4 record
  record=$(printf '%s\t%s\t%s\t%s' "$path" "$kind" "$identity" "$role")
  grep -Fqx -- "$record" "$MOCK_STATE/acls" || printf '%s\n' "$record" >>"$MOCK_STATE/acls"
}

remove_acl() {
  local path=$1 kind=$2 identity=$3 role=$4 record temporary
  record=$(printf '%s\t%s\t%s\t%s' "$path" "$kind" "$identity" "$role")
  temporary="$MOCK_STATE/acls.next"
  { grep -Fvx -- "$record" "$MOCK_STATE/acls" || true; } >"$temporary"
  mv -- "$temporary" "$MOCK_STATE/acls"
}

case "${1:-} ${2:-} ${3:-}" in
  'role list '*) emit_roles ;;
  'role add '*) printf '%s' "$5" >"$MOCK_STATE/roles/$3" ;;
  'role delete '*) rm -f -- "$MOCK_STATE/roles/$3" ;;
  'user list '*) emit_users ;;
  'user add '*) : >"$MOCK_STATE/users/$3" ;;
  'user delete '*) rm -f -- "$MOCK_STATE/users/$3" ;;
  'user token list') emit_tokens "$4" ;;
  'user token add')
    if [[ ${MOCK_FAIL_SECOND_TOKEN:-0} == 1 && $5 == executor ]]; then exit 9; fi
    : >"$MOCK_STATE/tokens/$4!$5"
    printf '{"full-tokenid":"%s!%s","value":"SECRET-%s"}\n' "$4" "$5" "$5"
    if [[ ${MOCK_REPLACE_ENV_WITH_SYMLINK:-0} == 1 && $5 == executor ]]; then
      ln -s -- /dev/null "${MOCK_ENV_PATH:?}"
    fi
    ;;
  'user token remove') rm -f -- "$MOCK_STATE/tokens/$4!$5" ;;
  'acl list '*) emit_acls ;;
  'acl modify '*)
    case "$4" in
      --users) add_acl "$3" user "$5" "$7" ;;
      --tokens) add_acl "$3" token "$5" "$7" ;;
      *) printf 'unexpected ACL subject option\n' >&2; exit 97 ;;
    esac
    ;;
  'acl delete '*)
    case "$4" in
      --users) remove_acl "$3" user "$5" "$7" ;;
      --tokens) remove_acl "$3" token "$5" "$7" ;;
      *) printf 'unexpected ACL subject option\n' >&2; exit 97 ;;
    esac
    ;;
  *) printf 'unexpected mock pveum invocation\n' >&2; exit 97 ;;
esac
`
