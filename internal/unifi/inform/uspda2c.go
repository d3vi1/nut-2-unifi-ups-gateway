package inform

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	ModelUPS2UProEU = "USPDA2C"
	ModelUPS2UEU    = "USWDA26"

	DeviceStatePending = 0
	DeviceStateAdopted = 2
	maxRuntimeSeconds  = 31 * 24 * 60 * 60
	maxOutletCount     = 64

	// Outlet capability bits are reverse-engineered wire values. Dynamic NUT
	// projection deliberately uses only the directly supportable subset.
	OutletCapabilityHasRelay   = 1 << 0
	OutletCapabilityPowerMeter = 1 << 1
	OutletCapabilityAutoRelay  = 1 << 2
	OutletCapabilityAC         = 1 << 16
	OutletCapabilityUSB        = 1 << 17

	// Smart-power capability bits are a separate controller bitmap from
	// outlet_caps. A compatibility gateway may advertise a strict subset of a
	// firmware profile when it deliberately does not implement a control path.
	SmartPowerCapabilityNUTInformationAccess     int64 = 1 << 0
	SmartPowerCapabilityCycleOnACRecovery        int64 = 1 << 1
	SmartPowerCapabilityBuzzerControl            int64 = 1 << 2
	SmartPowerCapabilitySafeShutdownAndCycleTime int64 = 1 << 3
	SmartPowerCapabilityEmergencyPowerOff        int64 = 1 << 4
)

// OutletTopologySource is local projection policy and is never serialized as
// a model. The zero value is reserved for exact firmware-reference fixtures;
// the runtime chooses either a conservative carrier fallback or observed NUT
// topology explicitly.
type OutletTopologySource string

const (
	OutletTopologyProfile         OutletTopologySource = ""
	OutletTopologyCarrierFallback OutletTopologySource = "carrier-fallback"
	OutletTopologyObservedNUT     OutletTopologySource = "nut-observed"
)

// DeviceProfile selects one controller-known power-device identity. The
// firmware version is explicit because the two profiles do not share a release
// history. BuildPowerDevicePayload derives display name and sysid from Model;
// observed NUT topology may independently supply outlet rows.
type DeviceProfile struct {
	Model           string
	FirmwareVersion string
}

type profileSpec struct {
	metadata          ProfileMetadata
	capabilitiesKnown bool
	requiredVersion   string
	fwCaps            int64
	hwCaps            int64
	sysErrorCaps      int64
	adoptionCaps      int64
	smartPowerCaps    int64
	outletCaps        []int
}

// ProfileMetadata contains the immutable fingerprint needed by both inform and
// discovery. Both profiles are pinned to the exact 1.6.1 firmware images used
// for reverse engineering; the public model selectors are not copied blindly
// into controller-facing fields.
type ProfileMetadata struct {
	DeviceModel  string
	ModelDisplay string
	Platform     string
	// ProfileGUID is the immutable board-profile identity emitted in inform.
	// It is distinct from per-device opaque identifiers and adoption state.
	ProfileGUID     string
	FirmwareVersion string
	// DiscoveryVersion is the value of discovery TLVs 0x03 and 0x16.
	DiscoveryVersion string
	// FullVersion is the longer embedded build identifier, not a substitute
	// for the discovery version fields.
	FullVersion string
	SysID       int
	OutletCount int
}

// ResolveProfile validates a profile and returns its immutable wire identity.
func ResolveProfile(profile DeviceProfile) (ProfileMetadata, error) {
	spec, err := specForProfile(profile)
	if err != nil {
		return ProfileMetadata{}, err
	}
	return spec.metadata, nil
}

// ReadOnlySmartPowerCapabilities returns the small, understood allowlist that
// this read-only gateway can truthfully expose. Genuine firmware masks also
// contain unresolved high bits; retaining unknown capabilities on the wire
// would be fail-open. Their exact masks remain reference metadata in profileSpec.
func ReadOnlySmartPowerCapabilities(profile DeviceProfile) (int64, error) {
	spec, err := specForProfile(profile)
	if err != nil {
		return 0, err
	}
	return spec.smartPowerCaps & (SmartPowerCapabilityNUTInformationAccess |
		SmartPowerCapabilitySafeShutdownAndCycleTime), nil
}

func specForProfile(profile DeviceProfile) (profileSpec, error) {
	switch profile.Model {
	case ModelUPS2UProEU:
		const version = "1.6.1.4933"
		if profile.FirmwareVersion != "" && profile.FirmwareVersion != "1.6.1" && profile.FirmwareVersion != version {
			return profileSpec{}, errors.New("inform: USPDA2C profile requires firmware 1.6.1.4933")
		}
		return profileSpec{
			metadata: ProfileMetadata{
				DeviceModel: "UPS-2U-Pro", ModelDisplay: "UPS Pro", Platform: "USPDA2x",
				FirmwareVersion:  version,
				DiscoveryVersion: version,
				FullVersion:      "USPDA2x.esp32s3.v1.6.1.4933.a9814b.260723.1639",
				SysID:            0xda2c, OutletCount: 9,
			},
			capabilitiesKnown: true,
			requiredVersion:   "0.0.0",
			fwCaps:            16779264, hwCaps: 136, sysErrorCaps: 0, adoptionCaps: 2, smartPowerCaps: 223,
			outletCaps: []int{65539, 65539, 65539, 65539, 65539, 65539, 65539, 65539, 65539},
		}, nil
	case ModelUPS2UEU:
		const version = "1.6.1.413"
		if profile.FirmwareVersion != "1.6.1" && profile.FirmwareVersion != version {
			return profileSpec{}, errors.New("inform: USWDA26 profile requires firmware 1.6.1.413")
		}
		return profileSpec{
			metadata: ProfileMetadata{
				DeviceModel: "UPS26", ModelDisplay: "UPS26", Platform: "UPS26",
				ProfileGUID:      "317875ca-ad3e-47e9-9430-47e3e2e1ab3d",
				FirmwareVersion:  version,
				DiscoveryVersion: version,
				FullVersion:      "UPS2U.esp32.v1.6.1.g5457.260723.0556",
				SysID:            0xda26, OutletCount: 8,
			},
			capabilitiesKnown: true,
			requiredVersion:   "1.3.4",
			fwCaps:            16779264,
			hwCaps:            128,
			sysErrorCaps:      0,
			adoptionCaps:      2,
			smartPowerCaps:    143,
			outletCaps:        []int{65549, 65549, 65549, 65549, 65541, 65541, 65541, 65541},
		}, nil
	default:
		return profileSpec{}, errors.New("inform: unsupported power-device profile")
	}
}

// PowerDeviceReport is the complete typed input for one emulated UniFi power
// device inform. Profile owns the controller-known wire identity, while
// OutletTopologySource distinguishes exact firmware reference data, the
// runtime's conservative carrier fallback, and a NUT observation.
type PowerDeviceReport struct {
	Profile              DeviceProfile
	OutletTopologySource OutletTopologySource
	Identity             DeviceIdentity
	Adoption             AdoptionState
	ObservedAt           time.Time
	Uptime               time.Duration
	LastInformAt         time.Time
	Capabilities         Capabilities
	System               SystemStats
	VBMS                 VBMSTelemetry
	Interface            InterfaceTelemetry
	Outlets              []OutletTelemetry
	BeepEnabled          *bool
	NUTServer            *NUTServerAdvertisement
}

func (r PowerDeviceReport) String() string {
	return fmt.Sprintf("power-device report profile=%s outlets=%d", r.Profile.Model, len(r.Outlets))
}

func (r PowerDeviceReport) GoString() string { return r.String() }

type DeviceIdentity struct {
	MAC               string
	Serial            string
	Hostname          string
	IP                string
	InformIP          string
	GUID              string
	HashID            string
	AnonID            string
	BoardRevision     *int
	ManufacturerID    *int
	RequiredVersion   string
	SelfRunBeacon     bool
	DiscoveryResponse bool
	Locating          bool
}

func (i DeviceIdentity) String() string   { return "power-device identity" }
func (i DeviceIdentity) GoString() string { return i.String() }

type Capabilities struct {
	Firmware   *int64
	Hardware   *int64
	SysError   *int64
	Adoption   *int64
	SmartPower *int64
}

type SystemStats struct {
	MemoryPercent *float64
	CPUPercent    *float64
}

type BatteryPool struct {
	AvailableCount    *int
	LevelPercent      *int
	TotalPowerBudgetW *int
	TotalPowerOutputW *float64
	TotalPowerFactor  *float64
	OutputVoltageV    *float64
	InputVoltageV     *float64
	OutputCurrentA    *float64
	Charging          *bool
	ReadyCount        *int
	RuntimeSeconds    *uint64
}

// AVRMode is the exact string representation observed in the UPS firmware.
type AVRMode string

const (
	AVRInactive AVRMode = "false"
	AVRBoost    AVRMode = "boost"
	AVRBuck     AVRMode = "buck"
)

type VBMSTelemetry struct {
	Battery       BatteryPool
	EPOEnabled    *bool
	InputTHDLevel *int
	BatteryMode   *bool
	AVRMode       *AVRMode
	BMSCount      *int
	BMSRunAnomaly *uint64
	BMSVersion    *string
	BMSLogFile    *string
}

type InterfaceTelemetry struct {
	MAC     string
	IP      string
	Netmask string
	Up      *bool
}

// NUTServerAdvertisement is an explicit operator assertion that a separate,
// unauthenticated NUT server is reachable at this emulated device's LAN IP.
// Credentials are intentionally not representable or serialized.
type NUTServerAdvertisement struct {
	Enabled bool
	ID      string
	Port    int
}

type OutletTelemetry struct {
	Index             int
	Name              string
	Capabilities      *int
	RelayGroup        int
	RelayState        *bool
	ButtonGroup       int
	ButtonState       *bool
	VoltageV          *float64
	CurrentA          *float64
	PowerW            *int
	PowerFactor       *float64
	EnergyOneDayWh    *float64
	EnergySevenDayWh  *float64
	EnergyThirtyDayWh *float64
}

type powerDevicePayload struct {
	MAC               string           `json:"mac"`
	Hostname          string           `json:"hostname"`
	Serial            string           `json:"serial"`
	Model             string           `json:"model"`
	ModelDisplay      string           `json:"model_display"`
	BoardRevision     *int             `json:"board_rev,omitempty"`
	ManufacturerID    *int             `json:"manufacturer_id,omitempty"`
	Version           string           `json:"version"`
	RequiredVersion   string           `json:"required_version,omitempty"`
	SysID             int              `json:"sysid"`
	IP                string           `json:"ip"`
	Time              int64            `json:"time"`
	InformURL         string           `json:"inform_url"`
	InformIP          string           `json:"inform_ip"`
	Uptime            int64            `json:"uptime"`
	LastInform        int64            `json:"last_inform"`
	CfgVersion        string           `json:"cfgversion"`
	Default           bool             `json:"default"`
	State             int              `json:"state"`
	SelfRunBeacon     bool             `json:"selfrun_beacon"`
	DiscoveryResponse bool             `json:"discovery_response"`
	HashID            string           `json:"hash_id,omitempty"`
	AnonID            string           `json:"anon_id,omitempty"`
	GUID              string           `json:"guid"`
	Locating          bool             `json:"locating"`
	SystemStats       *wireSystemStats `json:"system-stats,omitempty"`
	FWCaps            *int64           `json:"fw_caps,omitempty"`
	HWCaps            *int64           `json:"hw_caps,omitempty"`
	SysErrorCaps      *int64           `json:"sys_error_caps,omitempty"`
	HasSpeaker        bool             `json:"has_speaker"`
	HasEth1           bool             `json:"has_eth1"`
	AdoptionCaps      *int64           `json:"adoption_caps,omitempty"`
	SmartPowerCaps    *int64           `json:"smart_power_caps,omitempty"`
	VBMSTable         wireVBMS         `json:"vbms_table"`
	InterfaceTable    []wireInterface  `json:"if_table"`
	OutletTable       []wireOutlet     `json:"outlet_table"`
	PortTable         []wirePort       `json:"port_table"`
	BeepEnabled       *bool            `json:"beep_enabled,omitempty"`
	NUTServer         *wireNUTServer   `json:"nut_server,omitempty"`
}

type wireSystemStats struct {
	Memory *string `json:"mem,omitempty"`
	CPU    *string `json:"cpu,omitempty"`
}

type wireVBMS struct {
	Battery       wireBattery `json:"battpool"`
	EPOEnabled    *bool       `json:"epo_enabled,omitempty"`
	InputTHDLevel *int        `json:"input_thd_level,omitempty"`
	BatteryMode   *bool       `json:"is_battery_mode,omitempty"`
	AVRMode       *AVRMode    `json:"avr_mode,omitempty"`
	BMSCount      *int        `json:"bms_num,omitempty"`
	BMSRunAnomaly *uint64     `json:"bms_run_anomaly,omitempty"`
	BMSVersion    *string     `json:"bms_version,omitempty"`
	BMSLogFile    *string     `json:"bms_log_file,omitempty"`
}

type wireBattery struct {
	AvailableCount    *int     `json:"batt_available_cnt,omitempty"`
	LevelPercent      *int     `json:"batteryLevel,omitempty"`
	TotalPowerBudgetW *int     `json:"device_total_power_budget,omitempty"`
	TotalPowerOutputW *float64 `json:"device_total_power_output,omitempty"`
	TotalPowerFactor  *float64 `json:"device_total_power_factor,omitempty"`
	OutputVoltageV    *float64 `json:"device_output_voltage,omitempty"`
	InputVoltageV     *float64 `json:"device_input_voltage,omitempty"`
	OutputCurrentA    *float64 `json:"device_output_current,omitempty"`
	Charging          *bool    `json:"ischarging,omitempty"`
	ReadyCount        *int     `json:"readycnt,omitempty"`
	RuntimeSeconds    *uint64  `json:"timeToRemain,omitempty"`
}

type wireInterface struct {
	Name       string `json:"name"`
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Netmask    string `json:"netmask"`
	PortCount  int    `json:"num_port"`
	SpeedMbps  int    `json:"speed"`
	Up         *bool  `json:"up,omitempty"`
	FullDuplex bool   `json:"full_duplex"`
}

type wireOutlet struct {
	Index             int      `json:"index"`
	Capabilities      *int     `json:"outlet_caps,omitempty"`
	RelayGroup        int      `json:"relay_group"`
	RelayState        *bool    `json:"relay_state,omitempty"`
	ButtonGroup       *int     `json:"button_group,omitempty"`
	ButtonState       *bool    `json:"button_state,omitempty"`
	Name              string   `json:"name"`
	VoltageV          *float64 `json:"outlet_voltage,omitempty"`
	CurrentA          *float64 `json:"outlet_current,omitempty"`
	PowerW            *int     `json:"outlet_power,omitempty"`
	PowerFactor       *float64 `json:"outlet_power_factor,omitempty"`
	EnergyOneDayWh    *float64 `json:"outlet_ac_energy_1,omitempty"`
	EnergySevenDayWh  *float64 `json:"outlet_ac_energy_7,omitempty"`
	EnergyThirtyDayWh *float64 `json:"outlet_ac_energy_30,omitempty"`
}

type wirePort struct {
	IsUplink   bool   `json:"is_uplink"`
	FullDuplex bool   `json:"full_duplex"`
	Media      string `json:"media"`
	PortIndex  int    `json:"port_idx"`
	Up         *bool  `json:"up,omitempty"`
}

type wireNUTServer struct {
	Enabled            bool   `json:"enabled"`
	ID                 string `json:"id"`
	Port               int    `json:"port"`
	CredentialRequired bool   `json:"credential_required"`
}

// BuildPowerDevicePayload validates r and emits the exact firmware-observed
// JSON table names. The auth key is deliberately absent from this model's JSON;
// it is used only by the TNBU envelope codec.
func BuildPowerDevicePayload(r PowerDeviceReport) ([]byte, error) {
	spec, err := specForProfile(r.Profile)
	if err != nil {
		return nil, err
	}
	if err := validatePowerDeviceReport(r, spec); err != nil {
		return nil, err
	}
	capabilities := resolveCapabilities(r.Capabilities, spec)
	requiredVersion := r.Identity.RequiredVersion
	if requiredVersion == "" {
		requiredVersion = spec.requiredVersion
	}
	mac, _ := net.ParseMAC(r.Identity.MAC)
	macText := strings.ToLower(mac.String())
	state := DeviceStatePending
	if r.Adoption.Adopted {
		state = DeviceStateAdopted
	}
	lastInform := int64(0)
	if !r.LastInformAt.IsZero() {
		lastInform = r.LastInformAt.Unix()
	}
	var systemStats *wireSystemStats
	if r.System.MemoryPercent != nil || r.System.CPUPercent != nil {
		systemStats = &wireSystemStats{Memory: oneDecimal(r.System.MemoryPercent), CPU: oneDecimal(r.System.CPUPercent)}
	}
	profileGUID := r.Identity.GUID
	if spec.metadata.ProfileGUID != "" {
		profileGUID = spec.metadata.ProfileGUID
	}
	p := powerDevicePayload{
		MAC:               macText,
		Hostname:          r.Identity.Hostname,
		Serial:            r.Identity.Serial,
		Model:             spec.metadata.DeviceModel,
		ModelDisplay:      spec.metadata.ModelDisplay,
		BoardRevision:     r.Identity.BoardRevision,
		ManufacturerID:    r.Identity.ManufacturerID,
		Version:           spec.metadata.FirmwareVersion,
		RequiredVersion:   requiredVersion,
		SysID:             spec.metadata.SysID,
		IP:                r.Identity.IP,
		Time:              r.ObservedAt.Unix(),
		InformURL:         r.Adoption.InformURL,
		InformIP:          r.Identity.InformIP,
		Uptime:            int64(r.Uptime / time.Second),
		LastInform:        lastInform,
		CfgVersion:        r.Adoption.CfgVersion,
		Default:           !r.Adoption.Adopted,
		State:             state,
		SelfRunBeacon:     r.Identity.SelfRunBeacon,
		DiscoveryResponse: r.Identity.DiscoveryResponse,
		HashID:            r.Identity.HashID,
		AnonID:            r.Identity.AnonID,
		GUID:              profileGUID,
		Locating:          r.Identity.Locating,
		SystemStats:       systemStats,
		FWCaps:            capabilities.Firmware,
		HWCaps:            capabilities.Hardware,
		SysErrorCaps:      capabilities.SysError,
		AdoptionCaps:      capabilities.Adoption,
		SmartPowerCaps:    capabilities.SmartPower,
		VBMSTable: wireVBMS{
			Battery: wireBattery{
				AvailableCount: r.VBMS.Battery.AvailableCount, LevelPercent: r.VBMS.Battery.LevelPercent,
				TotalPowerBudgetW: r.VBMS.Battery.TotalPowerBudgetW, TotalPowerOutputW: r.VBMS.Battery.TotalPowerOutputW,
				TotalPowerFactor: r.VBMS.Battery.TotalPowerFactor, OutputVoltageV: r.VBMS.Battery.OutputVoltageV,
				InputVoltageV: r.VBMS.Battery.InputVoltageV, OutputCurrentA: r.VBMS.Battery.OutputCurrentA,
				Charging: r.VBMS.Battery.Charging, ReadyCount: r.VBMS.Battery.ReadyCount,
				RuntimeSeconds: r.VBMS.Battery.RuntimeSeconds,
			},
			EPOEnabled: r.VBMS.EPOEnabled, InputTHDLevel: r.VBMS.InputTHDLevel,
			BatteryMode: r.VBMS.BatteryMode, AVRMode: r.VBMS.AVRMode,
			BMSCount: r.VBMS.BMSCount, BMSRunAnomaly: r.VBMS.BMSRunAnomaly,
			BMSVersion: r.VBMS.BMSVersion, BMSLogFile: r.VBMS.BMSLogFile,
		},
		InterfaceTable: []wireInterface{{
			Name: "eth0", MAC: strings.ToLower(r.Interface.MAC), IP: r.Interface.IP,
			Netmask: r.Interface.Netmask, PortCount: 1, SpeedMbps: 100,
			Up: r.Interface.Up, FullDuplex: true,
		}},
		PortTable:   []wirePort{{IsUplink: true, FullDuplex: true, Media: "FE", PortIndex: 1, Up: r.Interface.Up}},
		BeepEnabled: r.BeepEnabled,
	}
	if r.NUTServer != nil {
		p.NUTServer = &wireNUTServer{
			Enabled: true, ID: r.NUTServer.ID, Port: r.NUTServer.Port,
			CredentialRequired: false,
		}
	}
	for outletIndex, outlet := range r.Outlets {
		outletCapabilities := outlet.Capabilities
		if r.OutletTopologySource == OutletTopologyProfile && len(spec.outletCaps) != 0 {
			outletCapabilities = intPointer(spec.outletCaps[outletIndex])
		}
		wireIndex := outlet.Index
		if wireIndex == 0 {
			wireIndex = outletIndex + 1
		}
		var buttonGroup *int
		if outlet.ButtonGroup > 0 {
			buttonGroup = intPointer(outlet.ButtonGroup)
		}
		p.OutletTable = append(p.OutletTable, wireOutlet{
			Index: wireIndex, Capabilities: outletCapabilities,
			RelayGroup: outlet.RelayGroup, RelayState: outlet.RelayState,
			ButtonGroup: buttonGroup, ButtonState: outlet.ButtonState,
			Name: outlet.Name, VoltageV: outlet.VoltageV, CurrentA: outlet.CurrentA,
			PowerW: outlet.PowerW, PowerFactor: outlet.PowerFactor,
			EnergyOneDayWh: outlet.EnergyOneDayWh, EnergySevenDayWh: outlet.EnergySevenDayWh,
			EnergyThirtyDayWh: outlet.EnergyThirtyDayWh,
		})
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, errors.New("inform: marshal power-device payload")
	}
	return b, nil
}

func validatePowerDeviceReport(r PowerDeviceReport, spec profileSpec) error {
	if err := r.Adoption.Validate(); err != nil {
		return err
	}
	mac, err := net.ParseMAC(r.Identity.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || allZero(mac) {
		return errors.New("inform: invalid power-device identity MAC")
	}
	if !validText(r.Identity.Serial, 128) || !validText(r.Identity.Hostname, 63) || !validUUIDText(r.Identity.GUID) ||
		!validHashID(r.Identity.HashID) || !validUUIDText(r.Identity.AnonID) {
		return errors.New("inform: incomplete power-device identity")
	}
	if r.Identity.RequiredVersion != "" && (!validConfigValue(r.Identity.RequiredVersion, 128) || (spec.requiredVersion != "" && r.Identity.RequiredVersion != spec.requiredVersion)) {
		return errors.New("inform: required_version does not match firmware profile")
	}
	if net.ParseIP(r.Identity.IP).To4() == nil || net.ParseIP(r.Identity.InformIP).To4() == nil {
		return errors.New("inform: power-device identity requires IPv4 addresses")
	}
	if r.ObservedAt.IsZero() || r.ObservedAt.Unix() < 0 || (!r.LastInformAt.IsZero() && (r.LastInformAt.Unix() < 0 || r.LastInformAt.After(r.ObservedAt))) || r.Uptime < 0 {
		return errors.New("inform: invalid power-device timestamps")
	}
	if !optionalFloatRange(r.System.MemoryPercent, 0, 100) || !optionalFloatRange(r.System.CPUPercent, 0, 100) {
		return errors.New("inform: invalid system utilization")
	}
	if r.NUTServer != nil && (!r.NUTServer.Enabled || !validToken(r.NUTServer.ID, 31) || r.NUTServer.Port < 1 || r.NUTServer.Port > 65535) {
		return errors.New("inform: invalid NUT server advertisement")
	}
	b := r.VBMS.Battery
	if !optionalIntRange(b.AvailableCount, 0, math.MaxInt) || !optionalIntRange(b.ReadyCount, 0, math.MaxInt) ||
		!optionalIntRange(b.LevelPercent, 0, 100) || !optionalIntRange(b.TotalPowerBudgetW, 0, math.MaxInt) {
		return errors.New("inform: invalid battery counters")
	}
	if b.AvailableCount != nil && b.ReadyCount != nil && *b.ReadyCount > *b.AvailableCount {
		return errors.New("inform: battery ready count exceeds available count")
	}
	if b.RuntimeSeconds != nil && *b.RuntimeSeconds > maxRuntimeSeconds {
		return errors.New("inform: battery runtime exceeds safety bound")
	}
	for _, value := range []*float64{b.TotalPowerOutputW, b.OutputVoltageV, b.InputVoltageV, b.OutputCurrentA} {
		if !optionalFloatRange(value, 0, math.MaxFloat64) {
			return errors.New("inform: invalid battery measurement")
		}
	}
	if !optionalFloatRange(b.TotalPowerFactor, 0, 1) || !optionalIntRange(r.VBMS.BMSCount, 0, math.MaxInt) || !optionalIntRange(r.VBMS.InputTHDLevel, 0, math.MaxInt) {
		return errors.New("inform: invalid battery power factor")
	}
	if r.VBMS.AVRMode != nil {
		switch *r.VBMS.AVRMode {
		case AVRInactive, AVRBoost, AVRBuck:
		default:
			return errors.New("inform: invalid AVR mode")
		}
	}
	if !validOptionalTextPointer(r.VBMS.BMSVersion, 128) || !validOptionalTextPointer(r.VBMS.BMSLogFile, 4096) {
		return errors.New("inform: invalid BMS metadata")
	}
	ifMac, err := net.ParseMAC(r.Interface.MAC)
	if err != nil || len(ifMac) != 6 || ifMac[0]&1 != 0 || !strings.EqualFold(ifMac.String(), mac.String()) {
		return errors.New("inform: interface MAC must match device identity")
	}
	maskIP := net.ParseIP(r.Interface.Netmask).To4()
	ones, bits := net.IPMask(maskIP).Size()
	if net.ParseIP(r.Interface.IP).To4() == nil || maskIP == nil || bits != 32 || ones < 0 || r.Interface.IP != r.Identity.IP {
		return errors.New("inform: invalid interface IPv4 configuration")
	}
	switch r.OutletTopologySource {
	case OutletTopologyProfile:
		if len(r.Outlets) != spec.metadata.OutletCount {
			return fmt.Errorf("inform: profile requires exactly %d outlets", spec.metadata.OutletCount)
		}
	case OutletTopologyCarrierFallback:
		if len(r.Outlets) != spec.metadata.OutletCount {
			return fmt.Errorf("inform: carrier fallback requires exactly %d outlets", spec.metadata.OutletCount)
		}
	case OutletTopologyObservedNUT:
		if len(r.Outlets) < 1 || len(r.Outlets) > maxOutletCount {
			return fmt.Errorf("inform: observed NUT topology requires 1..%d outlets", maxOutletCount)
		}
	default:
		return errors.New("inform: invalid outlet topology source")
	}
	if err := validateCapabilities(r.Capabilities, spec); err != nil {
		return err
	}
	observedGroups := make(map[int]struct{}, len(r.Outlets))
	observedGroupRelayState := make(map[int]int, len(r.Outlets))
	nextObservedGroup := 1
	for outletIndex, outlet := range r.Outlets {
		if !validText(outlet.Name, 128) {
			return errors.New("inform: invalid outlet name")
		}
		if !optionalIntRange(outlet.Capabilities, 0, math.MaxInt) || !optionalIntRange(outlet.PowerW, 0, math.MaxInt) ||
			outlet.RelayGroup < 1 || outlet.RelayGroup > len(r.Outlets) || outlet.ButtonGroup < 0 || outlet.ButtonGroup > len(r.Outlets) ||
			!optionalFloatRange(outlet.PowerFactor, 0, 1) {
			return errors.New("inform: invalid outlet measurement or group")
		}
		wireIndex := outlet.Index
		if wireIndex == 0 {
			wireIndex = outletIndex + 1
		}
		if wireIndex != outletIndex+1 {
			return errors.New("inform: outlet indices must be contiguous and ordered")
		}
		if r.OutletTopologySource == OutletTopologyCarrierFallback || r.OutletTopologySource == OutletTopologyObservedNUT {
			if outlet.Index == 0 || outlet.Capabilities == nil {
				return errors.New("inform: projected outlet requires explicit index and capabilities")
			}
			const allowed = OutletCapabilityHasRelay | OutletCapabilityPowerMeter | OutletCapabilityAC | OutletCapabilityUSB
			if *outlet.Capabilities&^allowed != 0 {
				return errors.New("inform: projected outlet has unsupported capabilities")
			}
			physicalType := *outlet.Capabilities & (OutletCapabilityAC | OutletCapabilityUSB)
			if physicalType != OutletCapabilityAC && physicalType != OutletCapabilityUSB {
				return errors.New("inform: projected outlet requires exactly one physical type")
			}
			if outlet.ButtonGroup != 0 || outlet.ButtonState != nil {
				return errors.New("inform: projected topology cannot infer physical buttons")
			}
			if _, seen := observedGroups[outlet.RelayGroup]; !seen {
				if outlet.RelayGroup != nextObservedGroup {
					return errors.New("inform: observed NUT relay groups must be dense in first-occurrence order")
				}
				observedGroups[outlet.RelayGroup] = struct{}{}
				nextObservedGroup++
			}
			relayState := 0
			if outlet.RelayState != nil {
				relayState = 1
				if *outlet.RelayState {
					relayState = 2
				}
			}
			if prior, seen := observedGroupRelayState[outlet.RelayGroup]; seen && prior != relayState {
				return errors.New("inform: observed NUT relay group states must be consistent")
			}
			observedGroupRelayState[outlet.RelayGroup] = relayState
			if (outlet.CurrentA != nil || outlet.PowerW != nil) && *outlet.Capabilities&OutletCapabilityPowerMeter == 0 {
				return errors.New("inform: observed NUT current or power requires POWER_METER capability")
			}
			if outlet.EnergyOneDayWh != nil || outlet.EnergySevenDayWh != nil || outlet.EnergyThirtyDayWh != nil {
				return errors.New("inform: observed NUT topology has no rolling-energy projection")
			}
			if r.OutletTopologySource == OutletTopologyCarrierFallback {
				if *outlet.Capabilities != OutletCapabilityAC || outlet.RelayState != nil ||
					outlet.VoltageV != nil || outlet.CurrentA != nil || outlet.PowerW != nil || outlet.PowerFactor != nil {
					return errors.New("inform: carrier fallback may expose only AC-compatible topology")
				}
			}
		}
		if r.OutletTopologySource == OutletTopologyProfile && r.Profile.Model == ModelUPS2UEU {
			expectedGroup := outletIndex/4 + 1
			expectedButtonGroup := 0
			if outletIndex < 4 {
				expectedButtonGroup = 1
			}
			if outlet.RelayGroup != expectedGroup || outlet.ButtonGroup != expectedButtonGroup {
				return errors.New("inform: USWDA26 outlets require 4+4 relay groups and buttons only on outlets 1-4")
			}
			if outletIndex >= 4 && outlet.ButtonState != nil {
				return errors.New("inform: USWDA26 surge outlets do not expose button state")
			}
			if outlet.VoltageV != nil || outlet.CurrentA != nil || outlet.PowerW != nil || outlet.PowerFactor != nil ||
				outlet.EnergyOneDayWh != nil || outlet.EnergySevenDayWh != nil || outlet.EnergyThirtyDayWh != nil {
				return errors.New("inform: USWDA26 firmware does not expose per-outlet electrical telemetry")
			}
		}
		if r.OutletTopologySource == OutletTopologyProfile && r.Profile.Model == ModelUPS2UProEU {
			index := outletIndex + 1
			if outlet.RelayGroup != index || outlet.ButtonGroup != index {
				return errors.New("inform: USPDA2C outlets require individual relay/button groups")
			}
			if outlet.Capabilities != nil && *outlet.Capabilities != spec.outletCaps[outletIndex] {
				return errors.New("inform: USPDA2C outlet capabilities do not match firmware profile")
			}
		}
		if r.OutletTopologySource == OutletTopologyProfile && r.Profile.Model == ModelUPS2UEU && outlet.Capabilities != nil && *outlet.Capabilities != spec.outletCaps[outletIndex] {
			return errors.New("inform: USWDA26 outlet capabilities do not match firmware profile")
		}
		for _, value := range []*float64{outlet.VoltageV, outlet.CurrentA, outlet.EnergyOneDayWh, outlet.EnergySevenDayWh, outlet.EnergyThirtyDayWh} {
			if !optionalFloatRange(value, 0, math.MaxFloat64) {
				return errors.New("inform: invalid outlet measurement")
			}
		}
	}
	return nil
}

func oneDecimal(value *float64) *string {
	if value == nil {
		return nil
	}
	formatted := strconv.FormatFloat(*value, 'f', 1, 64)
	return &formatted
}

func finiteRange(value, min, max float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= min && value <= max
}

func optionalFloatRange(value *float64, min, max float64) bool {
	return value == nil || finiteRange(*value, min, max)
}

func optionalIntRange(value *int, min, max int) bool {
	return value == nil || (*value >= min && *value <= max)
}

func validateCapabilities(value Capabilities, spec profileSpec) error {
	fields := []struct {
		value    *int64
		expected int64
	}{
		{value.Firmware, spec.fwCaps},
		{value.Hardware, spec.hwCaps},
		{value.SysError, spec.sysErrorCaps},
		{value.Adoption, spec.adoptionCaps},
	}
	for _, field := range fields {
		if field.value == nil {
			continue
		}
		if *field.value < 0 {
			return errors.New("inform: negative capability bitmap")
		}
		if spec.capabilitiesKnown && *field.value != field.expected {
			return errors.New("inform: capability bitmap does not match firmware profile")
		}
	}
	if value.SmartPower != nil {
		if *value.SmartPower < 0 || (spec.capabilitiesKnown && *value.SmartPower&^spec.smartPowerCaps != 0) {
			return errors.New("inform: smart-power capability bitmap is not a firmware-supported subset")
		}
	}
	return nil
}

func resolveCapabilities(value Capabilities, spec profileSpec) Capabilities {
	if !spec.capabilitiesKnown {
		return value
	}
	smartPower := int64Pointer(spec.smartPowerCaps)
	if value.SmartPower != nil {
		smartPower = int64Pointer(*value.SmartPower)
	}
	return Capabilities{
		Firmware: int64Pointer(spec.fwCaps), SmartPower: smartPower,
		Hardware: int64Pointer(spec.hwCaps), SysError: int64Pointer(spec.sysErrorCaps),
		Adoption: int64Pointer(spec.adoptionCaps),
	}
}

func intPointer(value int) *int       { return &value }
func int64Pointer(value int64) *int64 { return &value }

func validText(value string, max int) bool {
	return value != "" && validOptionalText(value, max)
}

func validOptionalText(value string, max int) bool {
	if len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validOptionalTextPointer(value *string, max int) bool {
	return value == nil || validOptionalText(*value, max)
}

func validHashID(value string) bool {
	if len(value) != 16 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 8 && !allZero(decoded)
}

func validUUIDText(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) ||
		value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16 && !allZero(decoded)
}

func allZero(value []byte) bool {
	var acc byte
	for _, b := range value {
		acc |= b
	}
	return acc == 0
}
