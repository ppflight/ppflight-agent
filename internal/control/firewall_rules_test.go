package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGuestFirewallRulesListGetVerifyCanonicalState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/firewall/rules" {
			t.Fatalf("unexpected firewall read: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[` +
			`{"pos":2,"type":"group","action":"trusted-web","enable":1,"comment":"managed group","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},` +
			`{"pos":0,"type":"in","action":"ACCEPT","enable":1,"proto":"tcp","source":"192.0.2.0/24","sport":"1024-65535","dest":"198.51.100.10/32","dport":"443","iface":"net0","ipversion":4,"log":"info","comment":"HTTPS","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","errors":{}},` +
			`{"pos":1,"type":"out","action":"DROP","enable":0,"macro":"SMTP","ipversion":6,"icmp-type":"echo-request","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` +
			`]}`))
	}))
	defer server.Close()
	executor := Executor{ReadClient: controlTestClient(t, server), Mode: "test"}
	listed, err := executor.Execute(context.Background(), controlCommand("firewall.guest.rules.list", "qemu", `{}`), time.Now())
	if err != nil || listed.State != "succeeded" {
		t.Fatalf("list receipt=%#v err=%v", listed, err)
	}
	var projection GuestFirewallRulesResult
	if err := json.Unmarshal(listed.Result, &projection); err != nil || len(projection.Rules) != 3 ||
		projection.Rules[0].Position != 0 || projection.Rules[1].Position != 1 || projection.Rules[2].Position != 2 ||
		projection.Rules[1].Enabled || projection.Rules[1].Macro != "SMTP" || projection.Rules[2].Type != "group" ||
		!bodyHashRE.MatchString(projection.Digest) {
		t.Fatalf("projection=%#v err=%v", projection, err)
	}
	got, err := executor.Execute(context.Background(), controlCommand("firewall.guest.rules.get", "qemu", `{"position":1}`), time.Now())
	if err != nil || !strings.Contains(string(got.Result), `"position":1`) || !strings.Contains(string(got.Result), `"enabled":false`) {
		t.Fatalf("get=%s err=%v", got.Result, err)
	}
	verifyRaw, _ := json.Marshal(guestFirewallRulesVerifyP{ExpectedDigest: projection.Digest, Rules: projection.Rules})
	verified, err := executor.Execute(context.Background(), controlCommand("firewall.guest.rules.verify", "qemu", string(verifyRaw)), time.Now())
	if err != nil || !strings.Contains(string(verified.Result), `"verified":true`) || !strings.Contains(string(verified.Result), projection.Digest) {
		t.Fatalf("verify=%s err=%v", verified.Result, err)
	}
	projection.Rules[0].Enabled = false
	wrongDigest, _ := guestFirewallRulesDigest(projection.Rules)
	wrongRaw, _ := json.Marshal(guestFirewallRulesVerifyP{ExpectedDigest: wrongDigest, Rules: projection.Rules})
	if receipt, err := executor.Execute(context.Background(), controlCommand("firewall.guest.rules.verify", "qemu", string(wrongRaw)), time.Now()); err == nil || receipt.Code != "GUEST_FIREWALL_RULES_NOT_READY" {
		t.Fatalf("mismatched verify receipt=%#v err=%v", receipt, err)
	}
}

func TestGuestFirewallRulesFailClosedOnUnknownOrAmbiguousPVEState(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":       `{"data":[{"pos":0,"type":"in","action":"ACCEPT","enable":1,"unsafe":"value"}]}`,
		"duplicate positions": `{"data":[{"pos":0,"type":"in","action":"ACCEPT","enable":1},{"pos":0,"type":"out","action":"DROP","enable":1}]}`,
		"PVE rule errors":     `{"data":[{"pos":0,"type":"in","action":"ACCEPT","enable":1,"errors":{"action":"invalid"}}]}`,
		"invalid control":     "{\"data\":[{\"pos\":0,\"type\":\"in\",\"action\":\"ACCEPT\",\"enable\":1,\"comment\":\"bad\\u000aentry\"}]}",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), controlCommand("firewall.guest.rules.list", "qemu", `{}`), time.Now())
			if err == nil || receipt.Code != "GUEST_FIREWALL_RULES_NOT_READY" {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
		})
	}
}

func TestGuestFirewallRulesVerifyRejectsNonCanonicalSignedProjection(t *testing.T) {
	invalid := []string{
		`{"expectedDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rules":[{"position":1,"type":"in","action":"ACCEPT","enabled":true},{"position":0,"type":"out","action":"DROP","enabled":true}]}`,
		`{"expectedDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rules":[{"position":0,"type":"in","action":"ACCEPT","enabled":true,"unknown":true}]}`,
		`{"expectedDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rules":[{"position":0,"type":"group","action":"../../unsafe","enabled":true}]}`,
	}
	for _, parameters := range invalid {
		if err := validateParameters(controlCommand("firewall.guest.rules.verify", "qemu", parameters)); err == nil {
			t.Fatalf("invalid firewall verification accepted: %s", parameters)
		}
	}
}
