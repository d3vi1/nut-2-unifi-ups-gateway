package gateway

import (
	"encoding/hex"
	"math"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/model"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

func projectPowerDevice(
	configuration config.Config,
	persistent state.State,
	network NetworkIdentity,
	mac [6]byte,
	observation model.State,
	now, started, lastInform time.Time,
) inform.PowerDeviceReport {
	uptime := now.Sub(started)
	if uptime < 0 {
		uptime = 0
	}
	hashID, anonID := deriveDiscoveryIDs(persistent.Identity.GUID, mac, configuration.UniFi.Model)
	report := inform.PowerDeviceReport{
		Profile: inform.DeviceProfile{
			Model:           configuration.UniFi.Model,
			FirmwareVersion: configuration.UniFi.Version,
		},
		Identity: inform.DeviceIdentity{
			MAC:      persistent.Identity.MAC,
			Serial:   persistent.Identity.Serial,
			Hostname: configuration.Device.Hostname,
			IP:       network.DeviceIP,
			InformIP: network.InformIP,
			GUID:     persistent.Identity.GUID,
			HashID:   hex.EncodeToString(hashID[:]),
			AnonID:   uuidText(anonID),
		},
		Adoption: inform.AdoptionState{
			AuthKey:    persistent.Adoption.AuthKey,
			InformURL:  persistent.Adoption.InformURL,
			CfgVersion: persistent.Adoption.CfgVersion,
			Adopted:    persistent.Adoption.Adopted,
			UseAESGCM:  persistent.Adoption.UseAESGCM,
		},
		ObservedAt:   now,
		Uptime:       uptime,
		LastInformAt: lastInform,
		Interface: inform.InterfaceTelemetry{
			MAC:     persistent.Identity.MAC,
			IP:      network.DeviceIP,
			Netmask: network.Netmask,
		},
	}

	report.Outlets = projectOutletTopology(configuration.UniFi.Model, observation)
	if observation.Availability != model.AvailabilityAvailable {
		// model.State intentionally retains last diagnostic measurements when a
		// snapshot becomes stale. Never project those values as current.
		return report
	}

	report.Interface.Up = boolPointer(true)
	if observation.Battery.ChargePercent.Known {
		level := roundedInt(observation.Battery.ChargePercent.Value)
		report.VBMS.Battery.LevelPercent = &level
		count := 1
		report.VBMS.Battery.AvailableCount = &count
		report.VBMS.Battery.ReadyCount = &count
	}
	if observation.Battery.RuntimeSeconds.Known {
		runtime := roundedUint64(observation.Battery.RuntimeSeconds.Value)
		report.VBMS.Battery.RuntimeSeconds = &runtime
	}
	if observation.Electrical.OutputPowerW.Known {
		report.VBMS.Battery.TotalPowerOutputW = floatPointer(observation.Electrical.OutputPowerW.Value)
	}
	if observation.Electrical.OutputPowerFactor.Known && observation.Electrical.OutputPowerFactor.Value <= 1 {
		report.VBMS.Battery.TotalPowerFactor = floatPointer(observation.Electrical.OutputPowerFactor.Value)
	}
	if observation.Electrical.OutputVoltage.Known {
		report.VBMS.Battery.OutputVoltageV = floatPointer(observation.Electrical.OutputVoltage.Value)
	}
	if observation.Electrical.InputVoltage.Known {
		report.VBMS.Battery.InputVoltageV = floatPointer(observation.Electrical.InputVoltage.Value)
	}
	if observation.Electrical.OutputCurrent.Known {
		report.VBMS.Battery.OutputCurrentA = floatPointer(observation.Electrical.OutputCurrent.Value)
	}
	if observation.Status.Charging.Known {
		report.VBMS.Battery.Charging = boolPointer(observation.Status.Charging.Value)
	}
	if observation.Status.OnBattery.Known {
		report.VBMS.BatteryMode = boolPointer(observation.Status.OnBattery.Value)
	}

	projectAvailableOutletTelemetry(report.Outlets, observation, configuration.UniFi.Model)
	return report
}

// uuidText encodes the opaque 16-byte device identity in the same canonical
// textual form used by firmware inform while discovery carries the raw bytes.
func uuidText(value [16]byte) string {
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func projectOutletTopology(profile string, observation model.State) []inform.OutletTelemetry {
	count := 8
	if profile == inform.ModelUPS2UProEU {
		count = 9
	}
	outlets := make([]inform.OutletTelemetry, count)
	for index := range outlets {
		group := index/4 + 1
		buttonGroup := 0
		if index < 4 {
			buttonGroup = 1
		}
		name := "Outlet " + integerString(index+1)
		if index < len(observation.Outlets) {
			group = observation.Outlets[index].RelayGroup
			name = observation.Outlets[index].Name
		}
		if profile == inform.ModelUPS2UProEU {
			// The Pro profile exposes nine independently identified outlet rows.
			group = index + 1
			buttonGroup = index + 1
		}
		outlets[index] = inform.OutletTelemetry{
			Name:        name,
			RelayGroup:  group,
			ButtonGroup: buttonGroup,
		}
	}
	return outlets
}

func projectAvailableOutletTelemetry(outlets []inform.OutletTelemetry, observation model.State, profile string) {
	for index := range outlets {
		if index >= len(observation.Outlets) {
			continue
		}
		source := observation.Outlets[index]
		relay := source.RelayState
		if relay == model.RelayUnknown && source.RelayGroup >= 1 && source.RelayGroup <= len(observation.Zones) {
			relay = observation.Zones[source.RelayGroup-1].RelayState
		}
		switch relay {
		case model.RelayOn:
			outlets[index].RelayState = boolPointer(true)
		case model.RelayOff:
			outlets[index].RelayState = boolPointer(false)
		}
		if profile == inform.ModelUPS2UEU {
			// The firmware-proven USWDA26 callback reports topology and relay
			// state only; it has no per-outlet electrical/energy fields.
			continue
		}
		if source.Voltage.Known {
			outlets[index].VoltageV = floatPointer(source.Voltage.Value)
		}
		if source.Current.Known {
			outlets[index].CurrentA = floatPointer(source.Current.Value)
		}
		if source.PowerW.Known {
			power := roundedInt(source.PowerW.Value)
			outlets[index].PowerW = &power
		}
		if source.PowerFactor.Known && source.PowerFactor.Value <= 1 {
			outlets[index].PowerFactor = floatPointer(source.PowerFactor.Value)
		}
	}
}

func roundedInt(value float64) int {
	return int(math.Round(value))
}

func roundedUint64(value float64) uint64 {
	return uint64(math.Round(value))
}

func boolPointer(value bool) *bool        { return &value }
func floatPointer(value float64) *float64 { return &value }

func integerString(value int) string {
	if value >= 0 && value <= 9 {
		return string(rune('0' + value))
	}
	return "unknown"
}
