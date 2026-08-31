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
	removeReadUser     = "ppflight-agent@pve"
	removeReadToken    = "collector"
	removeControlUser  = "ppflight-control@pve"
	removeControlToken = "executor"
	removeReadRole     = "PPFlightAgentAudit"
	removeControlRole  = "PPFlightAgentControl"
)

type removeCredentialsFixture struct {
	root   string
	state  string
	log    string
	mock   string
	script string
}

func newRemoveCredentialsFixture(t *testing.T) *removeCredentialsFixture {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is unavailable")
	}
	bash := testBash(t)
	uid := removeShellNumber(t, bash, "id -u")
	root := t.TempDir()
	state := filepath.Join(root, "state")
	for _, directory := range []string{
		filepath.Join(state, "roles"),
		filepath.Join(state, "users"),
		filepath.Join(state, "tokens"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "acls"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	raw := readDeploymentFile(t, "remove-pve-credentials.sh")
	patched := strings.Replace(raw, "readonly EXPECTED_OWNER_UID=0", fmt.Sprintf("readonly EXPECTED_OWNER_UID=%d", uid), 1)
	if patched == raw {
		t.Fatal("could not patch root guard for isolated fixture")
	}
	script := filepath.Join(root, "remove-pve-credentials.sh")
	if err := os.WriteFile(script, []byte(patched), 0o700); err != nil {
		t.Fatal(err)
	}
	mock := filepath.Join(root, "mock-pveum")
	if err := os.WriteFile(mock, []byte(removeCredentialsMockPVEUM), 0o700); err != nil {
		t.Fatal(err)
	}
	return &removeCredentialsFixture{
		root:   root,
		state:  state,
		log:    filepath.Join(root, "pveum.log"),
		mock:   mock,
		script: script,
	}
}

func removeShellNumber(t *testing.T, bash, command string) int {
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

func (fixture *removeCredentialsFixture) run(t *testing.T, extraEnvironment ...string) (string, error) {
	t.Helper()
	command := exec.Command(testBash(t), fixture.script)
	command.Env = append(os.Environ(),
		"PVEUM_BIN="+fixture.mock,
		"MOCK_REMOVE_STATE="+fixture.state,
		"MOCK_REMOVE_LOG="+fixture.log,
	)
	command.Env = append(command.Env, extraEnvironment...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (fixture *removeCredentialsFixture) logText(t *testing.T) string {
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

func (fixture *removeCredentialsFixture) putRole(t *testing.T, role string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.state, "roles", role), []byte("privileges"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture *removeCredentialsFixture) putUser(t *testing.T, user string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.state, "users", user), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture *removeCredentialsFixture) putToken(t *testing.T, user, token string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.state, "tokens", user+"!"+token), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture *removeCredentialsFixture) putACL(t *testing.T, path, kind, identity, role string) {
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

func (fixture *removeCredentialsFixture) hasState(t *testing.T, kind, name string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(fixture.state, kind, name))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatal(err)
	return false
}

func (fixture *removeCredentialsFixture) aclText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture.state, "acls"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (fixture *removeCredentialsFixture) seedCompletePPFlightState(t *testing.T) {
	t.Helper()
	fixture.putRole(t, removeReadRole)
	fixture.putRole(t, removeControlRole)
	fixture.putUser(t, removeReadUser)
	fixture.putUser(t, removeControlUser)
	fixture.putToken(t, removeReadUser, removeReadToken)
	fixture.putToken(t, removeControlUser, removeControlToken)
	fixture.putACL(t, "/", "user", removeReadUser, removeReadRole)
	fixture.putACL(t, "/", "token", removeReadUser+"!"+removeReadToken, removeReadRole)
	fixture.putACL(t, "/pool/production", "user", removeControlUser, removeControlRole)
	fixture.putACL(t, "/pool/production", "token", removeControlUser+"!"+removeControlToken, removeControlRole)
}

func TestRemovePVECredentialsFullyRevokesOnlyFixedPPFlightIdentity(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	fixture.putUser(t, "operator@pve")
	fixture.putRole(t, "OperatorRole")
	fixture.putACL(t, "/vms/100", "user", "operator@pve", "OperatorRole")

	output, err := fixture.run(t)
	if err != nil {
		t.Fatalf("complete credential removal failed: %v\n%s\nlog:\n%s", err, output, fixture.logText(t))
	}
	for _, state := range []struct {
		kind string
		name string
	}{
		{"users", removeReadUser},
		{"users", removeControlUser},
		{"tokens", removeReadUser + "!" + removeReadToken},
		{"tokens", removeControlUser + "!" + removeControlToken},
		{"roles", removeReadRole},
		{"roles", removeControlRole},
	} {
		if fixture.hasState(t, state.kind, state.name) {
			t.Fatalf("PPFlight state %s/%s remains after removal", state.kind, state.name)
		}
	}
	for _, state := range []struct {
		kind string
		name string
	}{
		{"users", "operator@pve"},
		{"roles", "OperatorRole"},
	} {
		if !fixture.hasState(t, state.kind, state.name) {
			t.Fatalf("unrelated PVE state %s/%s was removed", state.kind, state.name)
		}
	}
	if got, want := fixture.aclText(t), "/vms/100\tuser\toperator@pve\tOperatorRole\n"; got != want {
		t.Fatalf("unexpected ACL cleanup:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(output, "credentials have been revoked") {
		t.Fatalf("missing successful credential-revocation confirmation: %s", output)
	}

	log := fixture.logText(t)
	assertRemovalOrder(t, log,
		"user\ttoken\tremove\t"+removeReadUser+"\t"+removeReadToken,
		"user\ttoken\tremove\t"+removeControlUser+"\t"+removeControlToken,
		"user\tdelete\t"+removeReadUser,
		"user\tdelete\t"+removeControlUser,
		"role\tdelete\t"+removeReadRole,
		"role\tdelete\t"+removeControlRole,
	)
	assertNoOutOfBoundaryPVEUMCommands(t, log)
}

func TestRemovePVECredentialsIsIdempotentAfterCompleteRemoval(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	firstOutput, err := fixture.run(t)
	if err != nil {
		t.Fatalf("initial credential removal failed: %v\n%s", err, firstOutput)
	}
	firstLog := fixture.logText(t)
	secondOutput, err := fixture.run(t)
	if err != nil {
		t.Fatalf("idempotent second removal failed: %v\n%s", err, secondOutput)
	}
	allLog := fixture.logText(t)
	if !strings.HasPrefix(allLog, firstLog) {
		t.Fatal("could not isolate second-run pveum calls")
	}
	log := strings.TrimPrefix(allLog, firstLog)
	for _, forbidden := range []string{"\tremove\t", "\tdelete\t"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("idempotent second removal issued mutation %q:\n%s", forbidden, log)
		}
	}
}

func TestRemovePVECredentialsSharedRoleWarnsAndIsRetainedWithoutBlockingCredentialRevocation(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	fixture.putUser(t, "auditor@pve")
	fixture.putACL(t, "/", "user", "auditor@pve", removeReadRole)

	output, err := fixture.run(t)
	if err != nil {
		t.Fatalf("shared-role removal must preserve the role but succeed: %v\n%s\nlog:\n%s", err, output, fixture.logText(t))
	}
	if !strings.Contains(output, "warning: preserving PVE role "+removeReadRole) {
		t.Fatalf("missing shared-role warning: %s", output)
	}
	if !fixture.hasState(t, "roles", removeReadRole) {
		t.Fatal("shared PPFlight role was force-deleted")
	}
	if fixture.hasState(t, "roles", removeControlRole) {
		t.Fatal("unshared PPFlight control role was not deleted")
	}
	for _, name := range []string{
		removeReadUser,
		removeControlUser,
		removeReadUser + "!" + removeReadToken,
		removeControlUser + "!" + removeControlToken,
	} {
		kind := "users"
		if strings.Contains(name, "!") {
			kind = "tokens"
		}
		if fixture.hasState(t, kind, name) {
			t.Fatalf("credential %s/%s was not revoked when a role was shared", kind, name)
		}
	}
	if got, want := fixture.aclText(t), "/\tuser\tauditor@pve\t"+removeReadRole+"\n"; got != want {
		t.Fatalf("shared role ACL was changed:\n got %q\nwant %q", got, want)
	}
	log := fixture.logText(t)
	if strings.Contains(log, "role\tdelete\t"+removeReadRole) {
		t.Fatalf("script attempted to delete shared role:\n%s", log)
	}
}

func TestRemovePVECredentialsStopsBeforeUserWhenExistingTokenDeletionFails(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	output, err := fixture.run(t, "MOCK_REMOVE_FAIL=user-token-remove:"+removeControlUser+"!"+removeControlToken)
	if err == nil {
		t.Fatalf("token deletion failure unexpectedly succeeded: %s", output)
	}
	if !fixture.hasState(t, "users", removeControlUser) {
		t.Fatal("control user was deleted after its token deletion failed")
	}
	if strings.Contains(fixture.logText(t), "user\tdelete\t"+removeControlUser) {
		t.Fatalf("script proceeded to control user deletion after token failure:\n%s", fixture.logText(t))
	}
}

func TestRemovePVECredentialsReturnsNonzeroForOwnedACLDeleteFailureAfterRevokingCredentials(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	output, err := fixture.run(t, "MOCK_REMOVE_FAIL=acl-delete:/:token:"+removeReadUser+"!"+removeReadToken+":"+removeReadRole)
	if err == nil {
		t.Fatalf("ACL deletion failure unexpectedly succeeded: %s", output)
	}
	for _, name := range []string{removeReadUser, removeControlUser} {
		if fixture.hasState(t, "users", name) {
			t.Fatalf("user %s remained after an ACL deletion failure", name)
		}
	}
	for _, role := range []string{removeReadRole, removeControlRole} {
		if !fixture.hasState(t, "roles", role) {
			t.Fatalf("role %s was deleted after an earlier ACL deletion failure", role)
		}
	}
	log := fixture.logText(t)
	if strings.Contains(log, "role\tdelete\t") {
		t.Fatalf("script attempted role deletion after an ACL deletion failure:\n%s", log)
	}
	assertRemovalOrder(t, log,
		"acl\tdelete\t/\t--tokens\t"+removeReadUser+"!"+removeReadToken+"\t--roles\t"+removeReadRole,
		"user\ttoken\tremove\t"+removeControlUser+"\t"+removeControlToken,
		"user\tdelete\t"+removeControlUser,
	)
}

func TestRemovePVECredentialsReturnsNonzeroForExistingUserDeleteFailure(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	output, err := fixture.run(t, "MOCK_REMOVE_FAIL=user-delete:"+removeControlUser)
	if err == nil {
		t.Fatalf("user deletion failure unexpectedly succeeded: %s", output)
	}
	if !fixture.hasState(t, "users", removeControlUser) {
		t.Fatal("failed user delete did not leave the control user in place")
	}
	log := fixture.logText(t)
	if strings.Contains(log, "role\tdelete\t") {
		t.Fatalf("script proceeded to role deletion after user deletion failure:\n%s", log)
	}
	assertRemovalOrder(t, log,
		"user\ttoken\tremove\t"+removeControlUser+"\t"+removeControlToken,
		"user\tdelete\t"+removeControlUser,
	)
}

func TestRemovePVECredentialsReturnsNonzeroForExistingRoleDeleteFailureAfterCredentials(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	output, err := fixture.run(t, "MOCK_REMOVE_FAIL=role-delete:"+removeControlRole)
	if err == nil {
		t.Fatalf("role deletion failure unexpectedly succeeded: %s", output)
	}
	for _, name := range []string{removeReadUser, removeControlUser} {
		if fixture.hasState(t, "users", name) {
			t.Fatalf("user %s remained after later role deletion failure", name)
		}
	}
	if !fixture.hasState(t, "roles", removeControlRole) {
		t.Fatal("failed role delete did not leave the role in place")
	}
	log := fixture.logText(t)
	if !strings.Contains(log, "role\tdelete\t"+removeControlRole) {
		t.Fatalf("missing failed role delete invocation:\n%s", log)
	}
	assertRemovalOrder(t, log,
		"user\ttoken\tremove\t"+removeControlUser+"\t"+removeControlToken,
		"user\tdelete\t"+removeControlUser,
		"role\tdelete\t"+removeControlRole,
	)
}

func TestRemovePVECredentialsRejectsMalformedExistenceJSONBeforeMutation(t *testing.T) {
	fixture := newRemoveCredentialsFixture(t)
	fixture.seedCompletePPFlightState(t)
	output, err := fixture.run(t, "MOCK_REMOVE_MALFORMED=users")
	if err == nil {
		t.Fatalf("malformed JSON unexpectedly succeeded: %s", output)
	}
	for _, forbidden := range []string{"\tremove\t", "\tdelete\t"} {
		if strings.Contains(fixture.logText(t), forbidden) {
			t.Fatalf("malformed existence JSON performed mutation %q:\n%s", forbidden, fixture.logText(t))
		}
	}
}

func assertRemovalOrder(t *testing.T, log string, commands ...string) {
	t.Helper()
	last := -1
	for _, command := range commands {
		position := strings.Index(log, command)
		if position < 0 {
			t.Fatalf("missing command %q:\n%s", command, log)
		}
		if position <= last {
			t.Fatalf("removal ordering violated at %q:\n%s", command, log)
		}
		last = position
	}
}

func assertNoOutOfBoundaryPVEUMCommands(t *testing.T, log string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if line == "" {
			continue
		}
		command := strings.SplitN(line, "\t", 2)[0]
		switch command {
		case "role", "user", "acl":
			// The only permitted pveum command families for this helper.
		default:
			t.Fatalf("credential remover invoked out-of-bound pveum command %q:\n%s", command, log)
		}
	}
	for _, forbidden := range []string{"acl\tmodify", "role\tadd", "user\tadd", "token\tadd"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("credential remover issued forbidden mutation %q:\n%s", forbidden, log)
		}
	}
}

const removeCredentialsMockPVEUM = `#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
: "${MOCK_REMOVE_STATE:?}"
: "${MOCK_REMOVE_LOG:?}"

log() {
  local first=1 argument
  for argument in "$@"; do
    if [[ $first -eq 1 ]]; then
      printf '%s' "$argument"
      first=0
    else
      printf '\t%s' "$argument"
    fi
  done
  printf '\n'
}
log "$@" >>"$MOCK_REMOVE_LOG"

should_fail() {
  local key=$1
  [[ ${MOCK_REMOVE_FAIL:-} == "$key" ]]
}

emit_roles() {
  local first=1 file name
  if [[ ${MOCK_REMOVE_MALFORMED:-} == roles ]]; then printf '{bad json\n'; return; fi
  printf '['
  for file in "$MOCK_REMOVE_STATE"/roles/*; do
    [[ -f $file ]] || continue
    name=${file##*/}
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"roleid":"%s"}' "$name"
  done
  printf ']\n'
}

emit_users() {
  local first=1 file name
  if [[ ${MOCK_REMOVE_MALFORMED:-} == users ]]; then printf '{bad json\n'; return; fi
  printf '['
  for file in "$MOCK_REMOVE_STATE"/users/*; do
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
  if [[ ${MOCK_REMOVE_MALFORMED:-} == tokens ]]; then printf '{bad json\n'; return; fi
  printf '['
  for file in "$MOCK_REMOVE_STATE"/tokens/"$user"'!'*; do
    [[ -f $file ]] || continue
    identity=${file##*/}
    token=${identity#*!}
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"tokenid":"%s"}' "$token"
  done
  printf ']\n'
}

emit_acls() {
  local first=1 path kind identity role
  if [[ ${MOCK_REMOVE_MALFORMED:-} == acls ]]; then printf '{bad json\n'; return; fi
  printf '['
  while IFS=$'\t' read -r path kind identity role; do
    [[ -n $path ]] || continue
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '{"path":"%s","type":"%s","ugid":"%s","roleid":"%s"}' "$path" "$kind" "$identity" "$role"
  done <"$MOCK_REMOVE_STATE/acls"
  printf ']\n'
}

remove_acl() {
  local path=$1 kind=$2 identity=$3 role=$4 record next
  record=$(printf '%s\t%s\t%s\t%s' "$path" "$kind" "$identity" "$role")
  next="$MOCK_REMOVE_STATE/acls.next"
  { grep -Fvx -- "$record" "$MOCK_REMOVE_STATE/acls" || true; } >"$next"
  mv -- "$next" "$MOCK_REMOVE_STATE/acls"
}

remove_subject_acls() {
  local kind=$1 identity=$2 next
  next="$MOCK_REMOVE_STATE/acls.next"
  awk -F '\t' -v kind="$kind" -v identity="$identity" '!($2 == kind && $3 == identity)' "$MOCK_REMOVE_STATE/acls" >"$next"
  mv -- "$next" "$MOCK_REMOVE_STATE/acls"
}

case "${1:-} ${2:-} ${3:-}" in
  'role list '*) emit_roles ;;
  'role delete '*)
    should_fail "role-delete:$3" && exit 42
    rm -f -- "$MOCK_REMOVE_STATE/roles/$3"
    ;;
  'user list '*) emit_users ;;
  'user delete '*)
    should_fail "user-delete:$3" && exit 43
    remove_subject_acls user "$3"
    rm -f -- "$MOCK_REMOVE_STATE/users/$3"
    ;;
  'user token list') emit_tokens "$4" ;;
  'user token remove')
    should_fail "user-token-remove:$4!$5" && exit 44
    remove_subject_acls token "$4!$5"
    rm -f -- "$MOCK_REMOVE_STATE/tokens/$4!$5"
    ;;
  'acl list '*) emit_acls ;;
  'acl delete '*)
    case "$4" in
      --users)
        should_fail "acl-delete:$3:user:$5:$7" && exit 45
        remove_acl "$3" user "$5" "$7"
        ;;
      --tokens)
        should_fail "acl-delete:$3:token:$5:$7" && exit 45
        remove_acl "$3" token "$5" "$7"
        ;;
      *) printf 'unexpected ACL subject option\n' >&2; exit 97 ;;
    esac
    ;;
  *) printf 'unexpected mock pveum invocation: %s\n' "$*" >&2; exit 97 ;;
esac
`
