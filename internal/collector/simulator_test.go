package collector

import (
	"context"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
)

func TestSimulatorKeepsPVEAndQGASeparate(t *testing.T) {
	cfg, err := config.Parse([]byte(`{
      "schemaVersion":1,"mode":"test",
      "identity":{"agentRef":"agent-test","collectorRef":"collector-test","sourceRef":"source-test","clusterRef":"cluster-test","nodeRef":"auto","site":"lab"},
      "runtime":{"stateDirectory":"/tmp/ppflight-test","listenAddress":"127.0.0.1:19745","shutdownGrace":"5s","logLevel":"debug"},
      "pve":{"source":"simulator"},
      "destinations":{"websiteMetering":{"enabled":false},"websiteTelemetry":{"enabled":false},"monitoring":{"enabled":false}},
      "control":{"enabled":true,"productionExecution":false}
    }`))
	if err != nil {
		t.Fatal(err)
	}
	source := NewSimulator(cfg)
	first, err := source.Collect(context.Background(), time.Now(), Due{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Collect(context.Background(), time.Now().Add(10*time.Second), Due{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Guests) != 2 || !second.Guests[0].QGA.Availability.Available || second.Guests[1].QGA.Availability.Available {
		t.Fatalf("unexpected guest views: %#v", second.Guests)
	}
	if *second.Guests[0].PVE.IngressBytes <= *first.Guests[0].PVE.IngressBytes {
		t.Fatal("simulated PVE counters did not grow")
	}
	if second.Guests[0].QGA.Interfaces[0].Statistics.RxBytes == second.Guests[0].PVE.IngressBytes {
		t.Fatal("QGA and PVE observations were aliased")
	}
}
