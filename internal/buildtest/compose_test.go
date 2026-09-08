package buildtest

import (
	"strings"
	"testing"
)

func TestComposeKeepsLANIdentityExplicitAndSharedWithRuntime(t *testing.T) {
	compose := readRepositoryFile(t, "deploy", "compose", "compose.yaml")
	for _, option := range []string{"N2U_DEVICE_IP", "N2U_DEVICE_MAC"} {
		if strings.Count(compose, "${"+option+":?") != 2 {
			t.Errorf("%s must be required for both the LAN endpoint and the runtime", option)
		}
	}
	for _, required := range []string{
		"      N2U_NETWORK_MODE: separate\n",
		"    networks:\n      lan:\n        ipv4_address: ${N2U_DEVICE_IP:?",
		"        mac_address: ${N2U_DEVICE_MAC:?",
		"      N2U_NUT_ADDRESS: ${N2U_NUT_ADDRESS:?",
		"  lan:\n    external: true\n    name: ${N2U_LAN_NETWORK:?",
		"name: nut-2-unifi-ups-gateway\n",
		"      - state:/var/lib/n2u\n",
		"      N2U_UNIFI_NUT_SERVER_ENABLED: ${N2U_UNIFI_NUT_SERVER_ENABLED:-false}",
	} {
		if !strings.Contains(compose, required) {
			t.Errorf("base Compose is missing deployment boundary %q", required)
		}
	}
	if strings.Contains(compose, "nut_host:") {
		t.Error("base Compose must not attach the optional host NUT bridge")
	}
}

func TestComposeNetworkOverlayPreservesContainerIsolation(t *testing.T) {
	for _, name := range []string{"compose.yaml", "compose.legacy.yaml", "compose.auth.yaml", "compose.nut-host.yaml"} {
		compose := readRepositoryFile(t, "deploy", "compose", name)
		for _, line := range strings.Split(compose, "\n") {
			line = strings.TrimSpace(line)
			for _, forbidden := range []string{
				"network_mode:", "ports:", "privileged:", "cap_add:",
				"entrypoint:", "command:", "post_start:", "pre_start:",
				"gw_priority:", "interface_name:", "driver:", "driver_opts:",
			} {
				if strings.HasPrefix(line, forbidden) {
					// The log driver's existing json-file setting is unrelated to networking.
					if line == "driver: json-file" {
						continue
					}
					t.Errorf("%s introduces unsupported deployment setting %q", name, forbidden)
				}
			}
		}
	}

	overlay := readRepositoryFile(t, "deploy", "compose", "compose.nut-host.yaml")
	for _, required := range []string{
		"    networks:\n      nut_host:\n        ipv4_address: ${N2U_NUT_HOST_IP:?",
		"  nut_host:\n    external: true\n    name: ${N2U_NUT_HOST_NETWORK:?",
	} {
		if !strings.Contains(overlay, required) {
			t.Errorf("host NUT overlay is missing explicit network contract %q", required)
		}
	}
	for _, forbidden := range []string{"environment:", "volumes:", "image:", "mac_address:", "      lan:"} {
		if strings.Contains(overlay, forbidden) {
			t.Errorf("host NUT overlay must not override runtime or LAN identity through %q", forbidden)
		}
	}
}

func TestLegacyComposeDiffIsOnlyMACPlacement(t *testing.T) {
	canonical := readRepositoryFile(t, "deploy", "compose", "compose.yaml")
	expected := strings.Replace(canonical,
		"# Shared Linux macvlan deployment; Docker Compose 2.23.2 or later.",
		"# Alternate base for Docker Engine 24 and Compose 2.20.x; do not merge with compose.yaml.", 1)
	expected = strings.Replace(expected, "    networks:\n      lan:\n",
		"    mac_address: ${N2U_DEVICE_MAC:?set the stable gateway identity MAC address}\n    networks:\n      lan:\n        priority: 100\n", 1)
	expected = strings.Replace(expected, "        mac_address: ${N2U_DEVICE_MAC:?set the stable gateway identity MAC address}\n", "", 1)
	if got := readRepositoryFile(t, "deploy", "compose", "compose.legacy.yaml"); got != expected {
		t.Fatal("legacy template drifted beyond reviewed MAC placement")
	}
}

func TestSharedDaemonExampleDoesNotInventMACOrRequirePrivileges(t *testing.T) {
	env := readRepositoryFile(t, "deploy", "systemd", "n2u.env.example")
	for _, line := range []string{"N2U_NETWORK_MODE=shared", "N2U_DEVICE_IP=", "N2U_NUT_ADDRESS=127.0.0.1:3493"} {
		if !strings.Contains(env, line) {
			t.Fatal("shared daemon environment incomplete")
		}
	}
	if strings.Contains(env, "N2U_DEVICE_MAC=") || strings.Contains(env, "N2U_IMAGE=") {
		t.Fatal("daemon must derive host MAC and not import Compose environment")
	}
	unit := readRepositoryFile(t, "deploy", "systemd", "nut-2-unifi-ups-gateway.service")
	for _, line := range []string{"DynamicUser=yes", "StateDirectory=n2u", "StateDirectoryMode=0700", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "NoNewPrivileges=yes"} {
		if !strings.Contains(unit, line) {
			t.Fatal("daemon service hardening incomplete")
		}
	}
}

func TestManagedComposeConfinesPrivilegesAndSecrets(t *testing.T) {
	compose := readRepositoryFile(t, "deploy", "compose", "compose.managed.yaml")
	parts := strings.Split(compose, "\n  gateway:\n")
	if len(parts) != 2 {
		t.Fatal("managed service boundaries changed")
	}
	agent, gateway := parts[0], parts[1]
	for _, required := range []string{"entrypoint: [\"/n2u-netagent\"]", "user: \"0:0\"", "cap_drop: [ALL]", "cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]", "read_only: true", "security_opt: [\"no-new-privileges:true\"]"} {
		if !strings.Contains(agent, required) {
			t.Fatalf("missing agent boundary %q", required)
		}
	}
	for _, forbidden := range []string{"/var/lib/n2u", "N2U_NUT_", "N2U_INFORM_", "/var/run/docker.sock", "privileged:"} {
		if strings.Contains(agent, forbidden) {
			t.Fatalf("agent crosses secret/privilege boundary %q", forbidden)
		}
	}
	for _, required := range []string{"network_mode: service:netagent", "user: \"65532:65532\"", "cap_drop: [ALL]", "network_status:/run/n2u-network:ro", "N2U_NETWORK_STATUS_FILE: /run/n2u-network/status.json"} {
		if !strings.Contains(gateway, required) {
			t.Fatalf("missing gateway boundary %q", required)
		}
	}
	for _, forbidden := range []string{"cap_add:", "N2U_DEVICE_IP:", "privileged:", "/var/run/docker.sock"} {
		if strings.Contains(gateway, forbidden) {
			t.Fatalf("managed gateway crosses boundary %q", forbidden)
		}
	}
}

func TestManagedAuxiliaryTupleIsExplicitAndHelperOnly(t *testing.T) {
	overlay := readRepositoryFile(t, "deploy", "compose", "compose.managed-nut-host.yaml")
	for _, required := range []string{
		"  netagent:\n    environment:\n",
		"N2U_NET_AUX_ADDRESS: ${N2U_NUT_HOST_IP:?",
		"N2U_NET_AUX_ROUTER: ${N2U_NUT_HOST_GATEWAY:?",
	} {
		if !strings.Contains(overlay, required) {
			t.Fatal("missing explicit auxiliary tuple boundary")
		}
	}
	for _, forbidden := range []string{"  gateway:", "volumes:", "cap_add:", "N2U_NUT_ADDRESS:", "N2U_NUT_PASSWORD"} {
		if strings.Contains(overlay, forbidden) {
			t.Fatal("auxiliary overlay exceeds route-only boundary")
		}
	}
}
