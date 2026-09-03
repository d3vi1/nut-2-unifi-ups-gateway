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
		OutletTopologySource: inform.OutletTopologyCarrierFallback,
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
	if smartPower, err := inform.ReadOnlySmartPowerCapabilities(report.Profile); err == nil {
		if !configuration.UniFi.NUTServer.Enabled {
			smartPower &^= inform.SmartPowerCapabilityNUTInformationAccess
		}
		report.Capabilities.SmartPower = int64Pointer(smartPower)
	}
	if configuration.UniFi.NUTServer.Enabled {
		report.NUTServer = &inform.NUTServerAdvertisement{
			Enabled: true,
			ID:      configuration.UniFi.NUTServer.ID,
			Port:    configuration.UniFi.NUTServer.Port,
		}
	}
	if observation.TopologyObserved {
		report.OutletTopologySource = inform.OutletTopologyObservedNUT
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
	if observation.Electrical.OutputPowerNominalW.Known && observation.Electrical.OutputPowerNominalW.Value > 0 {
		budget := roundedInt(observation.Electrical.OutputPowerNominalW.Value)
		report.VBMS.Battery.TotalPowerBudgetW = &budget
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
	switch observation.BeeperStatus {
	case model.BeeperStatusEnabled:
		report.BeepEnabled = boolPointer(true)
	case model.BeeperStatusDisabled:
		report.BeepEnabled = boolPointer(false)
	}

	projectAvailableOutletTelemetry(report.Outlets, observation)
	return report
}

// uuidText encodes the opaque 16-byte device identity in the same canonical
// textual form used by firmware inform while discovery carries the raw bytes.
func uuidText(value [16]byte) string {
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func projectOutletTopology(profile string, observation model.State) []inform.OutletTelemetry {
	if observation.TopologyObserved {
		outlets := make([]inform.OutletTelemetry, len(observation.Outlets))
		for offset, source := range observation.Outlets {
			capabilities := inform.OutletCapabilityAC
			if source.Type == model.OutletTypeUSB {
				capabilities = inform.OutletCapabilityUSB
			}
			if source.Switchable.Known && source.Switchable.Value {
				capabilities |= inform.OutletCapabilityHasRelay
			}
			if source.PowerMeter {
				capabilities |= inform.OutletCapabilityPowerMeter
			}
			outlets[offset] = inform.OutletTelemetry{
				Index:        source.Index,
				Name:         source.Name,
				Capabilities: intPointer(capabilities),
				RelayGroup:   source.RelayGroup,
			}
		}
		return outlets
	}

	count := 8
	if profile == inform.ModelUPS2UProEU {
		count = 9
	}
	outlets := make([]inform.OutletTelemetry, count)
	for index := range outlets {
		group := index/4 + 1
		name := "Outlet " + integerString(index+1)
		if index < len(observation.Outlets) {
			group = observation.Outlets[index].RelayGroup
			name = observation.Outlets[index].Name
		}
		if profile == inform.ModelUPS2UProEU {
			// Preserve only its nine-row structural fallback. Physical buttons and
			// firmware capabilities are not facts about the NUT source.
			group = index + 1
		}
		outlets[index] = inform.OutletTelemetry{
			Index:        index + 1,
			Name:         name,
			Capabilities: intPointer(inform.OutletCapabilityAC),
			RelayGroup:   group,
		}
	}
	return outlets
}

func projectAvailableOutletTelemetry(outlets []inform.OutletTelemetry, observation model.State) {
	if !observation.TopologyObserved {
		// The carrier fallback supplies layout only. Without outlet.count there is
		// no trustworthy NUT row/group mapping for relay or electrical state.
		return
	}
	for index := range outlets {
		if index >= len(observation.Outlets) {
			continue
		}
		source := observation.Outlets[index]
		relay := source.RelayState
		if source.RelayGroup >= 1 && source.RelayGroup <= len(observation.Groups) {
			// A shared relay must be represented consistently on every member.
			// Conflicting or incomplete member evidence makes the whole group
			// unknown rather than emitting impossible per-row states.
			relay = observation.Groups[source.RelayGroup-1].RelayState
		}
		switch relay {
		case model.RelayOn:
			outlets[index].RelayState = boolPointer(true)
		case model.RelayOff:
			outlets[index].RelayState = boolPointer(false)
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
func intPointer(value int) *int           { return &value }
func int64Pointer(value int64) *int64     { return &value }

func integerString(value int) string {
	if value >= 0 && value <= 9 {
		return string(rune('0' + value))
	}
	return "unknown"
}
