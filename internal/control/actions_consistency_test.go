package control

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// TestKnownActionsHaveValidationAndExecutorDispatch keeps the three control
// action surfaces in lockstep. A protocol action is not real until it has both
// a strict parameter branch and an executor branch; conversely, an executor
// branch must never expose an action that KnownAction rejects.
func TestKnownActionsHaveValidationAndExecutorDispatch(t *testing.T) {
	validatorCases := actionSwitchCases(t, "validateParameters")
	executorCases := actionSwitchCases(t, "executePVE")
	executeChecks := actionEqualityCases(t, "Execute")

	known, knownWrites, knownReads := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for action, spec := range protocolActions {
		known[action] = true
		if spec.readOnly {
			knownReads[action] = true
		} else if action == "agent.upgrade" {
			// Host upgrades are dispatched to the separately privileged helper,
			// never to the PVE API write switch.
		} else {
			knownWrites[action] = true
		}
	}
	assertSameActions(t, "parameter validator", known, validatorCases)
	assertSameActions(t, "PVE write executor", knownWrites, executorCases)
	for action := range knownReads {
		if !executeChecks[action] {
			t.Errorf("read-only action %q has no Executor.Execute dispatch", action)
		}
	}
	if !executeChecks["agent.upgrade"] {
		t.Error("agent.upgrade has no Executor.Execute dispatch")
	}
	for action := range executeChecks {
		if !known[action] {
			t.Errorf("Executor.Execute references unregistered action %q", action)
		}
	}

	fixtures := validActionParameterFixtures()
	assertSameActions(t, "valid parameter fixture", known, fixtureActions(fixtures))
	for action, parameters := range fixtures {
		if err := validateParameters(controlCommand(action, "qemu", parameters)); err != nil {
			t.Errorf("known action %q has no accepting parameter path: %v", action, err)
		}
	}
}

func validActionParameterFixtures() map[string]string {
	return map[string]string{
		"pve.discover":                        `{"operationId":"operation-1","phase":"version","limit":1}`,
		"task.status":                         `{"upid":"UPID:pve1:1:2:3:task:101:root@pam!api:"}`,
		"vm.start":                            `{}`,
		"vm.shutdown":                         `{}`,
		"vm.stop":                             `{}`,
		"vm.reboot":                           `{}`,
		"vm.create":                           `{"name":"vm101","cores":2,"memoryMiB":1024,"storage":"local-lvm","diskGiB":8,"start":false}`,
		"vm.clone":                            `{"sourceVmid":100,"templateRef":"ubuntu-24.04","name":"vm101","full":true,"target":"pve1","storage":"local-lvm","sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		"vm.set-initial-resources":            `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-clone","templateRef":"ubuntu-24.04","sourceVmid":100,"vmGeneration":"1","templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		"vm.migrate-legacy-journal":           `{"legacyAssignmentRevision":"3","legacyCloneCommandId":"command-clone","legacyCloneOperationId":"operation-clone","legacyCloneDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","templateRef":"ubuntu-24.04","sourceVmid":100,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retireIndeterminateCommandIds":[]}`,
		"vm.reinstall":                        reinstallFixture(),
		"vm.set-resources":                    `{"cores":4}`,
		"vm.resize":                           `{"disk":"scsi0","size":"+1G"}`,
		"vm.set-disk-io":                      `{"disk":"scsi0","limits":{"iopsRead":1000,"iopsWrite":1000,"iopsReadMax":null,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":100,"mbpsWrite":100,"mbpsReadMax":null,"mbpsWriteMax":null}}`,
		"vm.set-network":                      `{"interface":"net0","bridge":"vmbr1"}`,
		"vm.set-rate":                         `{"interface":"net0","rateMbps":"10"}`,
		"vm.set-cloud-init":                   `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":["ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="],"qgaEnabled":true}`,
		"vm.cloud-init-snippet.delete":        `{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`,
		"vm.set-timezone":                     `{"timezone":"UTC"}`,
		"vm.verify-delivery":                  `{"notBefore":"2026-01-01T00:00:00Z","expected":{"cores":2,"sockets":1,"memoryMiB":1024,"disk":{"interface":"scsi0","minimumGiB":20,"limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":null,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":100,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}},"networks":[{"interface":"net0","bridge":"vmbr0","mac":"AA:BB:CC:DD:EE:FF","vlan":null,"mtu":1500,"firewall":true,"rateMbps":"100","ipv4":"192.0.2.10/24","ipv6":"2001:db8::10/64","ipFilterCidrs":["192.0.2.10/32","2001:db8::10/128"]}],"timezone":"UTC"}}`,
		"vm.delete":                           `{"purge":true,"destroyUnreferencedDisks":false}`,
		"vm.reset-password":                   `{"username":"root","password":"secret-value","crypted":false}`,
		"vm.suspend":                          `{}`,
		"vm.resume":                           `{}`,
		"vm.console.create-session":           `{"ttlSeconds":60,"webSocket":true}`,
		"vm.console.revoke-session":           `{"sessionRef":"session-1"}`,
		"snapshot.create":                     `{"name":"before","includeRam":false}`,
		"snapshot.delete":                     `{"name":"before"}`,
		"snapshot.rollback":                   `{"name":"before"}`,
		"snapshot.list":                       `{"limit":50}`,
		"snapshot.get":                        `{"name":"before"}`,
		"backup.create":                       `{"storage":"backup1","mode":"snapshot","notesTemplate":""}`,
		"backup.delete":                       `{"storage":"backup1","volume":"backup1:backup/vzdump-qemu-101.vma.zst"}`,
		"backup.restore":                      `{"storage":"backup1","volume":"backup1:backup/vzdump-qemu-101.vma.zst","force":false}`,
		"backup.list":                         `{"storage":"backup1","limit":50}`,
		"backup.get":                          `{"storage":"backup1","volume":"backup1:backup/vzdump-qemu-101.vma.zst"}`,
		"firewall.cluster.set-options":        `{"enable":true}`,
		"firewall.node.set-options":           `{"enable":true}`,
		"firewall.guest.set-options":          `{"enable":true,"policyIn":"ACCEPT","policyOut":"ACCEPT","macFilter":true}`,
		"firewall.guest.verify-ipfilter":      `{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32","2001:db8::10/128"]}]}`,
		"firewall.guest.verify-ipfilter-sets": `{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32","2001:db8::10/128"]}]}`,
		"firewall.guest.rules.list":           `{}`,
		"firewall.guest.rules.get":            `{"position":0}`,
		"firewall.guest.rules.verify":         `{"expectedDigest":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945","rules":[]}`,
		"firewall.rule.create":                `{"direction":"in","action":"ACCEPT","enable":true}`,
		"firewall.rule.update":                `{"position":0,"direction":"out","action":"DROP","enable":true}`,
		"firewall.rule.delete":                `{"position":0}`,
		"firewall.ipset.create":               `{"name":"trusted"}`,
		"firewall.ipset.update":               `{"name":"trusted","comment":"office"}`,
		"firewall.ipset.delete":               `{"name":"trusted"}`,
		"firewall.ipset.entry.create":         `{"name":"trusted","cidr":"10.0.0.0/24","noSubnet":false}`,
		"firewall.ipset.entry.update":         `{"name":"trusted","cidr":"10.0.0.0/24","comment":"office"}`,
		"firewall.ipset.entry.delete":         `{"name":"trusted","cidr":"10.0.0.0/24"}`,
		"agent.upgrade":                       upgradeFixture(),
	}
}

func reinstallFixture() string {
	return `{"templateRef":"ubuntu-24.04","templateVersion":"24.04","templateNode":"pve1","templateGuestType":"qemu","templateVmid":9001,"templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmGeneration":1,"temporaryVmid":800101,"storage":"local-lvm","notBefore":"2026-01-01T00:00:00Z","expected":{"cores":2,"sockets":1,"memoryMiB":1024,"disk":{"interface":"scsi0","minimumGiB":20,"limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":null,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":100,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}},"networks":[{"interface":"net0","bridge":"vmbr0","mac":"AA:BB:CC:DD:EE:FF","vlan":null,"mtu":1500,"firewall":true,"rateMbps":"100","ipv4":"192.0.2.10/24","ipv6":"2001:db8::10/64","ipFilterCidrs":["192.0.2.10/32","2001:db8::10/128"]}],"timezone":"UTC"},"expectedOs":{"family":"linux","name":"ubuntu","versionId":"24.04"},"networks":[{"interface":"net0","bridge":"vmbr0","mac":"AA:BB:CC:DD:EE:FF","vlan":null,"mtu":1500,"firewall":true,"rateMbps":"100","ipv4":"192.0.2.10/24","ipv6":"2001:db8::10/64","gateway4":"192.0.2.1","gateway6":"2001:db8::1"}],"cloudInit":{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":[],"qgaEnabled":true},"start":true}`
}

func upgradeFixture() string {
	arch := runtime.GOARCH
	name := "ppflight-agent-0.1.0-rc.9-linux-" + arch + ".tar.gz"
	return `{"schemaVersion":1,"releaseTag":"v0.1.0-rc.9","agentCommitSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":{"architecture":"` + arch + `","assetName":"` + name + `","sizeBytes":"1048576","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","downloadUrl":"https://www.ppflight.com/api/pve-agent/v1/releases/artifacts/v0.1.0-rc.9/` + arch + `"}}`
}

func fixtureActions(fixtures map[string]string) map[string]bool {
	result := make(map[string]bool, len(fixtures))
	for action := range fixtures {
		result[action] = true
	}
	return result
}

func assertSameActions(t *testing.T, name string, want, got map[string]bool) {
	t.Helper()
	for action := range want {
		if !got[action] {
			t.Errorf("%s is missing known action %q", name, action)
		}
	}
	for action := range got {
		if !want[action] {
			t.Errorf("%s contains unregistered action %q", name, action)
		}
	}
}

func actionSwitchCases(t *testing.T, function string) map[string]bool {
	t.Helper()
	declaration := parseExecutorFunction(t, function)
	result := map[string]bool{}
	ast.Inspect(declaration.Body, func(node ast.Node) bool {
		switchStatement, ok := node.(*ast.SwitchStmt)
		if !ok || !isActionSelector(switchStatement.Tag) {
			return true
		}
		for _, statement := range switchStatement.Body.List {
			clause := statement.(*ast.CaseClause)
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				result[value] = true
			}
		}
		return false
	})
	return result
}

func actionEqualityCases(t *testing.T, function string) map[string]bool {
	t.Helper()
	declaration := parseExecutorFunction(t, function)
	result := map[string]bool{}
	ast.Inspect(declaration.Body, func(node ast.Node) bool {
		comparison, ok := node.(*ast.BinaryExpr)
		if !ok || comparison.Op != token.EQL {
			return true
		}
		var literal *ast.BasicLit
		if isActionSelector(comparison.X) {
			literal, _ = comparison.Y.(*ast.BasicLit)
		} else if isActionSelector(comparison.Y) {
			literal, _ = comparison.X.(*ast.BasicLit)
		}
		if literal == nil || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		result[value] = true
		return true
	})
	return result
}

func isActionSelector(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Action"
}

func parseExecutorFunction(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate control test source")
	}
	filename := filepath.Join(filepath.Dir(currentFile), "executor.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name {
			return function
		}
	}
	t.Fatalf("executor function %s was not found", name)
	return nil
}
