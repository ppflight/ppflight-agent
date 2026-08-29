package exporter

import (
	"strings"
	"testing"
	"time"
)

func TestParseAndNormalizeHost(t *testing.T) {
	metrics := "# HELP node_load1 Load\nnode_load1 0.42\nnode_memory_MemTotal_bytes 100\nnode_memory_MemAvailable_bytes 55\nnode_filesystem_size_bytes{device=\"/dev/sda1\",mountpoint=\"/\",fstype=\"ext4\"} 99\nnode_filesystem_avail_bytes{device=\"/dev/sda1\",mountpoint=\"/\",fstype=\"ext4\"} 49\nnode_network_receive_bytes_total{device=\"eth0\"} 11\nnode_network_transmit_bytes_total{device=\"eth0\"} 12\n"
	samples, err := Parse(strings.NewReader(metrics), 4096)
	if err != nil {
		t.Fatal(err)
	}
	result := NormalizeHost(samples, time.Unix(10, 0))
	if result.Load1.Value == nil || *result.Load1.Value != .42 {
		t.Fatalf("load %#v", result.Load1)
	}
	if len(result.Filesystems) != 1 || result.Filesystems[0].AvailableBytes.Value == nil {
		t.Fatalf("filesystems %#v", result.Filesystems)
	}
	if len(result.Interfaces) != 1 || *result.Interfaces[0].TransmitBytes.Value != 12 {
		t.Fatalf("interfaces %#v", result.Interfaces)
	}
}
func TestMissingMetricIsUnavailable(t *testing.T) {
	result := NormalizeHost(nil, time.Time{})
	if result.MemoryTotalBytes.Value != nil || result.Load1.Value != nil {
		t.Fatalf("missing metrics must be nil: %#v", result)
	}
}
func TestParserRejectsBadInput(t *testing.T) {
	for _, input := range []string{"bad", "metric{a=\"bad\\q\"} 1", "metric NaN", "metric{a=\"1\",a=\"2\"} 1"} {
		if _, err := Parse(strings.NewReader(input+"\n"), 1024); err == nil {
			t.Fatalf("expected malformed input error for %q", input)
		}
	}
}
func TestParserEnforcesBodyLimit(t *testing.T) {
	if _, err := Parse(strings.NewReader("metric 12345\n"), 5); err == nil {
		t.Fatal("expected limit error")
	}
}
func TestNormalizeSMART(t *testing.T) {
	samples := []Sample{{Name: "smartctl_device_smart_status", Labels: map[string]string{"device": "/dev/sda"}, Value: 1}, {Name: "smartctl_device_temperature", Labels: map[string]string{"device": "/dev/sda"}, Value: 34}}
	result := NormalizeSMART(samples, time.Time{})
	if len(result.Devices) != 1 || result.Devices[0].Healthy.Value == nil || *result.Devices[0].TemperatureCelsius.Value != 34 {
		t.Fatalf("unexpected SMART result %#v", result)
	}
}

func TestNormalizeHostExtendedMetrics(t *testing.T) {
	samples := []Sample{
		{Name: "node_cpu_seconds_total", Labels: map[string]string{"cpu": "0", "mode": "idle"}, Value: 7},
		{Name: "node_memory_SwapTotal_bytes", Value: 100},
		{Name: "node_memory_SwapFree_bytes", Value: 30},
		{Name: "node_network_receive_errs_total", Labels: map[string]string{"device": "eth0"}, Value: 2},
		{Name: "node_network_up", Labels: map[string]string{"device": "eth0"}, Value: 1},
		{Name: "node_pressure_io_stalled_seconds_total", Value: 3},
		{Name: "node_hwmon_temp_celsius", Labels: map[string]string{"chip": "coretemp", "sensor": "Package id 0"}, Value: 44},
		{Name: "node_zfs_zpool_state", Labels: map[string]string{"zpool": "rpool", "state": "ONLINE"}, Value: 1},
	}
	r := NormalizeHost(samples, time.Time{})
	if len(r.CPUSeconds) != 1 || r.SwapFreeBytes.Value == nil || len(r.Pressure) != 1 || len(r.HardwareTemperatures) != 1 || len(r.ZFSPools) != 1 || r.Interfaces[0].ReceiveErrors.Value == nil {
		t.Fatalf("extended metrics missing: %#v", r)
	}
}

func TestNormalizeSMARTExtendedMetrics(t *testing.T) {
	r := NormalizeSMART([]Sample{
		{Name: "smartctl_device_info", Labels: map[string]string{"device": "/dev/nvme0", "model_name": "Disk", "serial_number": "abc", "protocol_type": "NVMe"}, Value: 1},
		{Name: "smartctl_device_media_errors", Labels: map[string]string{"device": "/dev/nvme0"}, Value: 2},
		{Name: "smartctl_device_percentage_used", Labels: map[string]string{"device": "/dev/nvme0"}, Value: 4},
		{Name: "smartctl_device_capacity", Labels: map[string]string{"device": "/dev/nvme0"}, Value: 500},
	}, time.Time{})
	if len(r.Devices) != 1 || r.Devices[0].Model != "Disk" || r.Devices[0].MediaErrors.Value == nil || r.Devices[0].CapacityBytes.Value == nil {
		t.Fatalf("SMART metadata missing: %#v", r)
	}
}
