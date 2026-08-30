package collector

import (
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/config"
)

func TestDisabledPVEConfigurationCannotCreateACollector(t *testing.T) {
	cfg, err := config.Parse([]byte(`{
      "schemaVersion":1,"mode":"production",
      "identity":{"agentRef":"agent-test","collectorRef":"collector-test","sourceRef":"source-test","clusterRef":"cluster-test","nodeRef":"node-test","site":"lab"},
      "runtime":{"stateDirectory":"/tmp/ppflight-test","listenAddress":"127.0.0.1:19745","shutdownGrace":"5s","logLevel":"debug"},
      "pve":{"source":"disabled"},
      "destinations":{"websiteMetering":{"enabled":false},"websiteTelemetry":{"enabled":false},"monitoring":{"enabled":false}},
      "control":{"enabled":false}
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, config.Secrets{}); err == nil || !strings.Contains(err.Error(), "collection is disabled") {
		t.Fatalf("disabled PVE source created a collector: %v", err)
	}
}
