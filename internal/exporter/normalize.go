package exporter

import (
	"sort"
	"strings"
	"time"
)

// Value is present only when the exporter emitted a valid sample. A nil Value
// means unavailable, never a measured zero.
type Value struct {
	Value *float64 `json:"value,omitempty"`
	// Raw is the exact Prometheus text value. It is intentionally not exposed in
	// the legacy observation JSON; monitoring-v1 uses it to string-encode large
	// byte/cumulative metrics without first rounding them through float64.
	Raw string `json:"-"`
}

func number(v float64, raw ...string) Value {
	value := Value{Value: &v}
	if len(raw) > 0 {
		value.Raw = raw[0]
	}
	return value
}

type FilesystemObservation struct {
	Device         string `json:"device"`
	Mountpoint     string `json:"mountpoint"`
	FSType         string `json:"fsType,omitempty"`
	SizeBytes      Value  `json:"sizeBytes"`
	AvailableBytes Value  `json:"availableBytes"`
	ReadOnly       Value  `json:"readOnly"`
}
type InterfaceObservation struct {
	Device         string `json:"device"`
	ReceiveBytes   Value  `json:"receiveBytes"`
	TransmitBytes  Value  `json:"transmitBytes"`
	ReceiveErrors  Value  `json:"receiveErrors"`
	TransmitErrors Value  `json:"transmitErrors"`
	ReceiveDrops   Value  `json:"receiveDrops"`
	TransmitDrops  Value  `json:"transmitDrops"`
	LinkUp         Value  `json:"linkUp"`
}
type DiskObservation struct {
	Device          string `json:"device"`
	ReadBytes       Value  `json:"readBytes"`
	WrittenBytes    Value  `json:"writtenBytes"`
	ReadsCompleted  Value  `json:"readsCompleted"`
	WritesCompleted Value  `json:"writesCompleted"`
	IOTimeSeconds   Value  `json:"ioTimeSeconds"`
}
type CPUSecondsObservation struct {
	CPU     string `json:"cpu"`
	Mode    string `json:"mode"`
	Seconds Value  `json:"seconds"`
}
type PressureObservation struct {
	Resource     string `json:"resource"`
	State        string `json:"state"`
	SecondsTotal Value  `json:"secondsTotal"`
}
type HardwareTemperatureObservation struct {
	Chip    string `json:"chip"`
	Sensor  string `json:"sensor"`
	Celsius Value  `json:"celsius"`
}
type ZFSPoolObservation struct {
	Pool           string `json:"pool"`
	SizeBytes      Value  `json:"sizeBytes"`
	AllocatedBytes Value  `json:"allocatedBytes"`
	FreeBytes      Value  `json:"freeBytes"`
	Healthy        Value  `json:"healthy"`
}
type HostObservation struct {
	ObservedAt           time.Time                        `json:"observedAt"`
	Load1                Value                            `json:"load1"`
	MemoryTotalBytes     Value                            `json:"memoryTotalBytes"`
	MemoryAvailableBytes Value                            `json:"memoryAvailableBytes"`
	SwapTotalBytes       Value                            `json:"swapTotalBytes"`
	SwapFreeBytes        Value                            `json:"swapFreeBytes"`
	CPUSeconds           []CPUSecondsObservation          `json:"cpuSeconds,omitempty"`
	Filesystems          []FilesystemObservation          `json:"filesystems,omitempty"`
	Interfaces           []InterfaceObservation           `json:"interfaces,omitempty"`
	Disks                []DiskObservation                `json:"disks,omitempty"`
	Pressure             []PressureObservation            `json:"pressure,omitempty"`
	HardwareTemperatures []HardwareTemperatureObservation `json:"hardwareTemperatures,omitempty"`
	ZFSPools             []ZFSPoolObservation             `json:"zfsPools,omitempty"`
}
type SmartDeviceObservation struct {
	Device             string `json:"device"`
	Healthy            Value  `json:"healthy"`
	TemperatureCelsius Value  `json:"temperatureCelsius"`
	PowerOnHours       Value  `json:"powerOnHours"`
	DataUnitsRead      Value  `json:"dataUnitsRead"`
	DataUnitsWritten   Value  `json:"dataUnitsWritten"`
	MediaErrors        Value  `json:"mediaErrors"`
	PercentageUsed     Value  `json:"percentageUsed"`
	CapacityBytes      Value  `json:"capacityBytes"`
	Model              string `json:"model,omitempty"`
	Serial             string `json:"serial,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
}
type SmartObservation struct {
	ObservedAt time.Time                `json:"observedAt"`
	Devices    []SmartDeviceObservation `json:"devices,omitempty"`
}

// NormalizeHost extracts only stable node_exporter metrics. Multiple samples of
// a scalar use the first valid occurrence; this avoids silently aggregating
// unrelated labels. Filesystems and interfaces are keyed by their identity.
func NormalizeHost(samples []Sample, observedAt time.Time) HostObservation {
	o := HostObservation{ObservedAt: observedAt}
	fs := map[string]*FilesystemObservation{}
	nic := map[string]*InterfaceObservation{}
	disks := map[string]*DiskObservation{}
	pressure := map[string]*PressureObservation{}
	hwmon := map[string]*HardwareTemperatureObservation{}
	zfs := map[string]*ZFSPoolObservation{}
	for _, s := range samples {
		switch s.Name {
		case "node_load1":
			if o.Load1.Value == nil {
				o.Load1 = number(s.Value, s.RawValue)
			}
		case "node_memory_MemTotal_bytes":
			if o.MemoryTotalBytes.Value == nil {
				o.MemoryTotalBytes = number(s.Value, s.RawValue)
			}
		case "node_memory_MemAvailable_bytes":
			if o.MemoryAvailableBytes.Value == nil {
				o.MemoryAvailableBytes = number(s.Value, s.RawValue)
			}
		case "node_memory_SwapTotal_bytes":
			if o.SwapTotalBytes.Value == nil {
				o.SwapTotalBytes = number(s.Value, s.RawValue)
			}
		case "node_memory_SwapFree_bytes":
			if o.SwapFreeBytes.Value == nil {
				o.SwapFreeBytes = number(s.Value, s.RawValue)
			}
		case "node_cpu_seconds_total":
			cpu, mode := s.Labels["cpu"], s.Labels["mode"]
			if cpu != "" && mode != "" {
				o.CPUSeconds = append(o.CPUSeconds, CPUSecondsObservation{CPU: cpu, Mode: mode, Seconds: number(s.Value, s.RawValue)})
			}
		case "node_filesystem_size_bytes", "node_filesystem_avail_bytes", "node_filesystem_readonly":
			device, mount := s.Labels["device"], s.Labels["mountpoint"]
			if device == "" || mount == "" {
				continue
			}
			key := device + "\x00" + mount
			v := fs[key]
			if v == nil {
				v = &FilesystemObservation{Device: device, Mountpoint: mount, FSType: s.Labels["fstype"]}
				fs[key] = v
			}
			if s.Name == "node_filesystem_size_bytes" {
				v.SizeBytes = number(s.Value, s.RawValue)
			} else if s.Name == "node_filesystem_avail_bytes" {
				v.AvailableBytes = number(s.Value, s.RawValue)
			} else {
				v.ReadOnly = number(s.Value, s.RawValue)
			}
		case "node_network_receive_bytes_total", "node_network_transmit_bytes_total", "node_network_receive_errs_total", "node_network_transmit_errs_total", "node_network_receive_drop_total", "node_network_transmit_drop_total", "node_network_up":
			device := s.Labels["device"]
			if device == "" {
				continue
			}
			v := nic[device]
			if v == nil {
				v = &InterfaceObservation{Device: device}
				nic[device] = v
			}
			switch s.Name {
			case "node_network_receive_bytes_total":
				v.ReceiveBytes = number(s.Value, s.RawValue)
			case "node_network_transmit_bytes_total":
				v.TransmitBytes = number(s.Value, s.RawValue)
			case "node_network_receive_errs_total":
				v.ReceiveErrors = number(s.Value, s.RawValue)
			case "node_network_transmit_errs_total":
				v.TransmitErrors = number(s.Value, s.RawValue)
			case "node_network_receive_drop_total":
				v.ReceiveDrops = number(s.Value, s.RawValue)
			case "node_network_transmit_drop_total":
				v.TransmitDrops = number(s.Value, s.RawValue)
			case "node_network_up":
				v.LinkUp = number(s.Value, s.RawValue)
			}
		case "node_disk_read_bytes_total", "node_disk_written_bytes_total", "node_disk_reads_completed_total", "node_disk_writes_completed_total", "node_disk_io_time_seconds_total":
			device := s.Labels["device"]
			if device == "" {
				continue
			}
			v := disks[device]
			if v == nil {
				v = &DiskObservation{Device: device}
				disks[device] = v
			}
			switch s.Name {
			case "node_disk_read_bytes_total":
				v.ReadBytes = number(s.Value, s.RawValue)
			case "node_disk_written_bytes_total":
				v.WrittenBytes = number(s.Value, s.RawValue)
			case "node_disk_reads_completed_total":
				v.ReadsCompleted = number(s.Value, s.RawValue)
			case "node_disk_writes_completed_total":
				v.WritesCompleted = number(s.Value, s.RawValue)
			case "node_disk_io_time_seconds_total":
				v.IOTimeSeconds = number(s.Value, s.RawValue)
			}
		case "node_pressure_cpu_waiting_seconds_total", "node_pressure_io_waiting_seconds_total", "node_pressure_io_stalled_seconds_total", "node_pressure_memory_waiting_seconds_total", "node_pressure_memory_stalled_seconds_total":
			parts := strings.Split(strings.TrimPrefix(strings.TrimSuffix(s.Name, "_seconds_total"), "node_pressure_"), "_")
			if len(parts) == 2 {
				key := parts[0] + "\x00" + parts[1]
				pressure[key] = &PressureObservation{Resource: parts[0], State: parts[1], SecondsTotal: number(s.Value, s.RawValue)}
			}
		case "node_hwmon_temp_celsius":
			chip, sensor := s.Labels["chip"], s.Labels["sensor"]
			if chip != "" && sensor != "" {
				hwmon[chip+"\x00"+sensor] = &HardwareTemperatureObservation{Chip: chip, Sensor: sensor, Celsius: number(s.Value, s.RawValue)}
			}
		case "node_zfs_zpool_size", "node_zfs_zpool_allocated", "node_zfs_zpool_free", "node_zfs_zpool_state":
			pool := s.Labels["zpool"]
			if pool == "" {
				pool = s.Labels["pool"]
			}
			if pool == "" {
				pool = s.Labels["name"]
			}
			if pool == "" {
				continue
			}
			v := zfs[pool]
			if v == nil {
				v = &ZFSPoolObservation{Pool: pool}
				zfs[pool] = v
			}
			switch s.Name {
			case "node_zfs_zpool_size":
				v.SizeBytes = number(s.Value, s.RawValue)
			case "node_zfs_zpool_allocated":
				v.AllocatedBytes = number(s.Value, s.RawValue)
			case "node_zfs_zpool_free":
				v.FreeBytes = number(s.Value, s.RawValue)
			case "node_zfs_zpool_state":
				if s.Labels["state"] == "ONLINE" {
					v.Healthy = number(s.Value, s.RawValue)
				}
			}
		}
	}
	for _, v := range fs {
		o.Filesystems = append(o.Filesystems, *v)
	}
	for _, v := range nic {
		o.Interfaces = append(o.Interfaces, *v)
	}
	for _, v := range disks {
		o.Disks = append(o.Disks, *v)
	}
	for _, v := range pressure {
		o.Pressure = append(o.Pressure, *v)
	}
	for _, v := range hwmon {
		o.HardwareTemperatures = append(o.HardwareTemperatures, *v)
	}
	for _, v := range zfs {
		o.ZFSPools = append(o.ZFSPools, *v)
	}
	sortHost(o.Filesystems, o.Interfaces, o.Disks, o.CPUSeconds, o.Pressure, o.HardwareTemperatures, o.ZFSPools)
	return o
}

// NormalizeSMART accepts the metric names emitted by Prometheus community
// smartctl_exporter releases. Unknown metrics are ignored safely.
func NormalizeSMART(samples []Sample, observedAt time.Time) SmartObservation {
	o := SmartObservation{ObservedAt: observedAt}
	devices := map[string]*SmartDeviceObservation{}
	for _, s := range samples {
		if s.Name != "smartctl_device_smart_status" && s.Name != "smartctl_device_temperature" && s.Name != "smartctl_device_power_on_hours" && s.Name != "smartctl_device_data_units_read" && s.Name != "smartctl_device_data_units_written" && s.Name != "smartctl_device_media_errors" && s.Name != "smartctl_device_percentage_used" && s.Name != "smartctl_device_capacity" && s.Name != "smartctl_device_info" {
			continue
		}
		device := s.Labels["device"]
		if device == "" {
			device = s.Labels["name"]
		}
		if device == "" {
			continue
		}
		d := devices[device]
		if d == nil {
			d = &SmartDeviceObservation{Device: device}
			devices[device] = d
		}
		switch s.Name {
		case "smartctl_device_smart_status":
			d.Healthy = number(s.Value, s.RawValue)
		case "smartctl_device_temperature":
			d.TemperatureCelsius = number(s.Value, s.RawValue)
		case "smartctl_device_power_on_hours":
			d.PowerOnHours = number(s.Value, s.RawValue)
		case "smartctl_device_data_units_read":
			d.DataUnitsRead = number(s.Value, s.RawValue)
		case "smartctl_device_data_units_written":
			d.DataUnitsWritten = number(s.Value, s.RawValue)
		case "smartctl_device_media_errors":
			d.MediaErrors = number(s.Value, s.RawValue)
		case "smartctl_device_percentage_used":
			d.PercentageUsed = number(s.Value, s.RawValue)
		case "smartctl_device_capacity":
			d.CapacityBytes = number(s.Value, s.RawValue)
		case "smartctl_device_info":
			if d.Model == "" {
				d.Model = firstLabel(s.Labels, "model_name", "model")
			}
			if d.Serial == "" {
				d.Serial = firstLabel(s.Labels, "serial_number", "serial")
			}
			if d.Protocol == "" {
				d.Protocol = firstLabel(s.Labels, "protocol", "protocol_type")
			}
		}
	}
	for _, d := range devices {
		o.Devices = append(o.Devices, *d)
	}
	sortSmart(o.Devices)
	return o
}

func firstLabel(labels map[string]string, names ...string) string {
	for _, name := range names {
		if value := labels[name]; value != "" {
			return value
		}
	}
	return ""
}

func sortHost(filesystems []FilesystemObservation, interfaces []InterfaceObservation, disks []DiskObservation, cpus []CPUSecondsObservation, pressure []PressureObservation, temperatures []HardwareTemperatureObservation, pools []ZFSPoolObservation) {
	sort.Slice(filesystems, func(i, j int) bool {
		if filesystems[i].Device == filesystems[j].Device {
			return filesystems[i].Mountpoint < filesystems[j].Mountpoint
		}
		return filesystems[i].Device < filesystems[j].Device
	})
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Device < interfaces[j].Device })
	sort.Slice(disks, func(i, j int) bool { return disks[i].Device < disks[j].Device })
	sort.Slice(cpus, func(i, j int) bool {
		if cpus[i].CPU == cpus[j].CPU {
			return cpus[i].Mode < cpus[j].Mode
		}
		return cpus[i].CPU < cpus[j].CPU
	})
	sort.Slice(pressure, func(i, j int) bool {
		if pressure[i].Resource == pressure[j].Resource {
			return pressure[i].State < pressure[j].State
		}
		return pressure[i].Resource < pressure[j].Resource
	})
	sort.Slice(temperatures, func(i, j int) bool {
		if temperatures[i].Chip == temperatures[j].Chip {
			return temperatures[i].Sensor < temperatures[j].Sensor
		}
		return temperatures[i].Chip < temperatures[j].Chip
	})
	sort.Slice(pools, func(i, j int) bool { return pools[i].Pool < pools[j].Pool })
}
func sortSmart(devices []SmartDeviceObservation) {
	sort.Slice(devices, func(i, j int) bool { return devices[i].Device < devices[j].Device })
}
