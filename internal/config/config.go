// Package config loads and validates the gateway's environment-only runtime
// configuration. Secrets may be supplied directly or through Docker-style
// *_FILE variables; values are never rendered back into errors or logs.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	envPrefix      = "N2U_"
	maxSecretBytes = 64 * 1024
)

// Config is immutable after startup.
type Config struct {
	NUT      NUT
	UniFi    UniFi
	Device   Device
	Runtime  Runtime
	LogLevel string
}

type NUT struct {
	Address             string
	UPSName             string
	Username            string
	Password            string
	Timeout             time.Duration
	AllowInsecureRemote bool
}

type UniFi struct {
	Model             string
	Version           string
	InformURL         string
	InformInterval    time.Duration
	InformTimeout     time.Duration
	DiscoveryInterval time.Duration
}

type Device struct {
	MAC      string
	Serial   string
	Hostname string
	IP       string
}

type Runtime struct {
	StateFile     string
	HealthAddress string
	PollInterval  time.Duration
	StaleAfter    time.Duration
}

// Load reads configuration from the process environment.
func Load() (Config, error) {
	password, err := secret("N2U_NUT_PASSWORD")
	if err != nil {
		return Config{}, err
	}
	c := Config{
		NUT: NUT{
			Address:  value("N2U_NUT_ADDRESS", "127.0.0.1:3493"),
			UPSName:  value("N2U_NUT_UPS", "ups"),
			Username: os.Getenv("N2U_NUT_USERNAME"),
			Password: password,
		},
		UniFi: UniFi{
			Model:     value("N2U_UNIFI_MODEL", "USWDA26"),
			Version:   value("N2U_UNIFI_VERSION", "1.6.1"),
			InformURL: value("N2U_INFORM_URL", "http://unifi:8080/inform"),
		},
		Device: Device{
			MAC:      os.Getenv("N2U_DEVICE_MAC"),
			Serial:   os.Getenv("N2U_DEVICE_SERIAL"),
			Hostname: value("N2U_DEVICE_HOSTNAME", "nut-2-unifi-ups-gateway"),
			IP:       os.Getenv("N2U_DEVICE_IP"),
		},
		Runtime: Runtime{
			StateFile:     value("N2U_STATE_FILE", "/var/lib/n2u/state.json"),
			HealthAddress: value("N2U_HEALTH_ADDRESS", "127.0.0.1:9199"),
		},
		LogLevel: strings.ToLower(value("N2U_LOG_LEVEL", "info")),
	}

	if c.NUT.Timeout, err = duration("N2U_NUT_TIMEOUT", 5*time.Second, time.Second, time.Minute); err != nil {
		return Config{}, err
	}
	if c.UniFi.InformInterval, err = duration("N2U_INFORM_INTERVAL", 10*time.Second, time.Second, 10*time.Minute); err != nil {
		return Config{}, err
	}
	if c.UniFi.InformTimeout, err = duration("N2U_INFORM_TIMEOUT", 10*time.Second, time.Second, time.Minute); err != nil {
		return Config{}, err
	}
	if c.UniFi.DiscoveryInterval, err = duration("N2U_DISCOVERY_INTERVAL", 30*time.Second, 5*time.Second, 10*time.Minute); err != nil {
		return Config{}, err
	}
	if c.Runtime.PollInterval, err = duration("N2U_POLL_INTERVAL", 5*time.Second, time.Second, 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.Runtime.StaleAfter, err = duration("N2U_STALE_AFTER", 20*time.Second, 2*time.Second, 30*time.Minute); err != nil {
		return Config{}, err
	}
	if c.NUT.AllowInsecureRemote, err = boolean("N2U_NUT_ALLOW_INSECURE_REMOTE", false); err != nil {
		return Config{}, err
	}
	if err := rejectUnknownEnvironment(); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if c.NUT.Timeout < time.Second || c.NUT.Timeout > time.Minute {
		return errors.New("N2U_NUT_TIMEOUT must be between 1 second and 1 minute")
	}
	if c.UniFi.InformInterval < time.Second || c.UniFi.InformInterval > 10*time.Minute {
		return errors.New("N2U_INFORM_INTERVAL must be between 1 second and 10 minutes")
	}
	if c.UniFi.InformTimeout < time.Second || c.UniFi.InformTimeout > time.Minute {
		return errors.New("N2U_INFORM_TIMEOUT must be between 1 second and 1 minute")
	}
	if c.UniFi.DiscoveryInterval < 5*time.Second || c.UniFi.DiscoveryInterval > 10*time.Minute {
		return errors.New("N2U_DISCOVERY_INTERVAL must be between 5 seconds and 10 minutes")
	}
	if c.Runtime.PollInterval < time.Second || c.Runtime.PollInterval > 5*time.Minute {
		return errors.New("N2U_POLL_INTERVAL must be between 1 second and 5 minutes")
	}
	if c.Runtime.StaleAfter < 2*time.Second || c.Runtime.StaleAfter > 30*time.Minute {
		return errors.New("N2U_STALE_AFTER must be between 2 seconds and 30 minutes")
	}
	host, _, err := net.SplitHostPort(c.NUT.Address)
	if err != nil {
		return fmt.Errorf("N2U_NUT_ADDRESS: %w", err)
	}
	if !loopbackHost(host) && !c.NUT.AllowInsecureRemote {
		return errors.New("remote plaintext NUT requires N2U_NUT_ALLOW_INSECURE_REMOTE=true")
	}
	if !safeToken(c.NUT.UPSName) {
		return errors.New("N2U_NUT_UPS must contain only letters, digits, '.', '_' or '-'")
	}
	if (c.NUT.Username == "") != (c.NUT.Password == "") {
		return errors.New("N2U_NUT_USERNAME and N2U_NUT_PASSWORD[_FILE] must be supplied together")
	}
	u, err := url.Parse(c.UniFi.InformURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("N2U_INFORM_URL must be an http(s) URL without credentials, query, or fragment")
	}
	if u.Path != "/inform" {
		return errors.New("N2U_INFORM_URL path must be /inform")
	}
	if c.UniFi.Model != "USWDA26" && c.UniFi.Model != "USPDA2C" {
		return errors.New("N2U_UNIFI_MODEL must be USWDA26 or USPDA2C")
	}
	if (c.UniFi.Model == "USWDA26" && c.UniFi.Version != "1.6.1" && c.UniFi.Version != "1.6.1.413") ||
		(c.UniFi.Model == "USPDA2C" && c.UniFi.Version != "1.6.1" && c.UniFi.Version != "1.6.1.4933") {
		return errors.New("N2U_UNIFI_VERSION must select the firmware-proven 1.6.1 profile")
	}
	if c.Device.MAC != "" {
		hw, err := net.ParseMAC(c.Device.MAC)
		if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
			return errors.New("N2U_DEVICE_MAC must be a six-byte unicast MAC address")
		}
	}
	if c.Device.IP != "" && net.ParseIP(c.Device.IP).To4() == nil {
		return errors.New("N2U_DEVICE_IP must be an IPv4 address")
	}
	if len(c.Device.Hostname) > 63 || !safeToken(c.Device.Hostname) {
		return errors.New("N2U_DEVICE_HOSTNAME must contain 1-63 safe ASCII characters")
	}
	if c.Runtime.StateFile == "" || c.Runtime.HealthAddress == "" {
		return errors.New("state file and health address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.Runtime.HealthAddress); err != nil {
		return fmt.Errorf("N2U_HEALTH_ADDRESS: %w", err)
	}
	if c.Runtime.StaleAfter < c.Runtime.PollInterval {
		return errors.New("N2U_STALE_AFTER must be at least N2U_POLL_INTERVAL")
	}
	if c.LogLevel != "debug" && c.LogLevel != "info" && c.LogLevel != "warn" && c.LogLevel != "error" {
		return errors.New("N2U_LOG_LEVEL must be debug, info, warn, or error")
	}
	return nil
}

func value(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func secret(name string) (string, error) {
	direct, hasDirect := os.LookupEnv(name)
	path, hasFile := os.LookupEnv(name + "_FILE")
	if hasFile && path == "" {
		hasFile = false
	}
	if hasDirect && hasFile {
		return "", fmt.Errorf("set only one of %s and %s_FILE", name, name)
	}
	if !hasFile {
		return direct, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("read %s_FILE: secret must be a regular file", name)
	}
	if info.Size() > maxSecretBytes {
		return "", fmt.Errorf("%s_FILE is too large", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	if len(b) > maxSecretBytes {
		return "", fmt.Errorf("%s_FILE is too large", name)
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}

func duration(name string, fallback, min, max time.Duration) (time.Duration, error) {
	raw := value(name, fallback.String())
	d, err := time.ParseDuration(raw)
	if err != nil || d < min || d > max {
		return 0, fmt.Errorf("%s must be a duration between %s and %s", name, min, max)
	}
	return d, nil
}

func boolean(name string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return b, nil
}

func safeToken(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var knownEnvironment = map[string]struct{}{
	"N2U_NUT_ADDRESS": {}, "N2U_NUT_UPS": {}, "N2U_NUT_USERNAME": {},
	"N2U_NUT_PASSWORD": {}, "N2U_NUT_PASSWORD_FILE": {}, "N2U_NUT_TIMEOUT": {},
	"N2U_NUT_ALLOW_INSECURE_REMOTE": {},
	"N2U_UNIFI_MODEL":               {}, "N2U_UNIFI_VERSION": {}, "N2U_INFORM_URL": {},
	"N2U_INFORM_INTERVAL": {}, "N2U_INFORM_TIMEOUT": {}, "N2U_DISCOVERY_INTERVAL": {},
	"N2U_DEVICE_MAC": {}, "N2U_DEVICE_SERIAL": {}, "N2U_DEVICE_HOSTNAME": {}, "N2U_DEVICE_IP": {},
	"N2U_STATE_FILE": {}, "N2U_HEALTH_ADDRESS": {}, "N2U_POLL_INTERVAL": {}, "N2U_STALE_AFTER": {},
	"N2U_LOG_LEVEL": {},
}

func rejectUnknownEnvironment() error {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, envPrefix) {
			if _, ok := knownEnvironment[name]; !ok {
				return fmt.Errorf("unknown %s environment variable", name)
			}
		}
	}
	return nil
}

// Prefix returns the only environment prefix consumed by this program.
func Prefix() string { return envPrefix }
