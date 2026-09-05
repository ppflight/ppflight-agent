package collector

import (
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

func TestGuestDetailBatchSpreadsFiveHundredGuestsAcrossSweep(t *testing.T) {
	resources := make([]pve.Resource, 0, 502)
	for vmid := 500; vmid >= 1; vmid-- {
		resources = append(resources, pve.Resource{Type: "qemu", Node: "pve", VMID: vmid})
	}
	resources = append(resources,
		pve.Resource{Type: "qemu", Node: "pve", VMID: 9000, Template: 1},
		pve.Resource{Type: "node", Node: "pve"},
	)

	cursor := 0
	seen := map[int]bool{}
	for cycle := 0; cycle < 12; cycle++ {
		batch, next := guestDetailBatch(resources, 10*time.Second, 2*time.Minute, cursor)
		if len(batch) != 42 {
			t.Fatalf("cycle %d batch size=%d want 42", cycle, len(batch))
		}
		for _, resource := range batch {
			if resource.Template != 0 || resource.Type != "qemu" {
				t.Fatalf("ineligible resource included: %#v", resource)
			}
			seen[resource.VMID] = true
		}
		cursor = next
	}
	if len(seen) != 500 {
		t.Fatalf("full sweep observed %d guests want 500", len(seen))
	}
}

func TestGuestDetailBatchIsDeterministicAndHandlesInventoryChanges(t *testing.T) {
	resources := []pve.Resource{
		{Type: "lxc", Node: "pve-b", VMID: 3},
		{Type: "qemu", Node: "pve-a", VMID: 2},
		{Type: "qemu", Node: "pve-a", VMID: 1},
	}
	batch, cursor := guestDetailBatch(resources, 10*time.Second, time.Minute, 99)
	if len(batch) != 1 || batch[0].VMID != 1 || cursor != 1 {
		t.Fatalf("unexpected normalized batch: %#v cursor=%d", batch, cursor)
	}
	batch, cursor = guestDetailBatch(resources[:1], 10*time.Second, time.Minute, cursor)
	if len(batch) != 1 || batch[0].VMID != 3 || cursor != 0 {
		t.Fatalf("inventory shrink was not normalized: %#v cursor=%d", batch, cursor)
	}
	batch, cursor = guestDetailBatch(nil, 10*time.Second, time.Minute, cursor)
	if len(batch) != 0 || cursor != 0 {
		t.Fatalf("empty inventory returned work: %#v cursor=%d", batch, cursor)
	}
}
