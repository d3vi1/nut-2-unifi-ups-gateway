package releaseguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxReleaseAssetSize   = 128 << 20
	maxExpandedBundleSize = 4 << 20
	maxBundleMemberSize   = 1 << 20
	composeSHA256         = "355434062a389e9c6440b34e5bcd0c04c8a70ff2bf304b33afc6ea3778e0447a"
	composeAuthSHA256     = "dff79bb144fc83589d3c4eb0d7a3b73ef25051db9db59ff71273cd606e6f7cfd"
)

type localAsset struct {
	name   string
	size   int64
	digest string
	data   []byte
}

func loadReleaseAssets(release Context, binding bindingInput, getenv func(string) string) ([]localAsset, error) {
	if getenv == nil {
		return nil, errors.New("release environment is unavailable")
	}
	raw := getenv("N2U_RELEASE_ASSETS")
	if raw == "" {
		return nil, errors.New("N2U_RELEASE_ASSETS is required")
	}
	if strings.ContainsRune(raw, '\r') {
		return nil, errors.New("N2U_RELEASE_ASSETS contains an invalid carriage return")
	}
	raw = strings.TrimSuffix(raw, "\n")
	paths := strings.Split(raw, "\n")
	if len(paths) != 2 || paths[0] == "" || paths[1] == "" || paths[0] == paths[1] {
		return nil, errors.New("N2U_RELEASE_ASSETS must contain exactly two distinct paths")
	}
	wanted := map[string]bool{
		fmt.Sprintf("nut-2-unifi-ups-gateway-%s-synology.tar.gz", release.Tag):     false,
		fmt.Sprintf("nut-2-unifi-ups-gateway-%s-synology.SHA256SUMS", release.Tag): false,
	}
	assets := make([]localAsset, 0, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("release asset paths must be absolute and canonical")
		}
		name := filepath.Base(path)
		if _, exists := wanted[name]; !exists || wanted[name] {
			return nil, errors.New("release asset names do not match the release")
		}
		wanted[name] = true
		asset, err := snapshotReleaseAsset(path, name)
		if err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	var bundle, checksums *localAsset
	for index := range assets {
		if strings.HasSuffix(assets[index].name, ".tar.gz") {
			bundle = &assets[index]
		} else if strings.HasSuffix(assets[index].name, ".SHA256SUMS") {
			checksums = &assets[index]
		}
	}
	if bundle == nil || checksums == nil {
		return nil, errors.New("release bundle and checksum assets are required")
	}
	expectedChecksum := strings.TrimPrefix(bundle.digest, "sha256:") + "  " + bundle.name + "\n"
	if string(checksums.data) != expectedChecksum {
		return nil, errors.New("SHA256SUMS does not exactly bind the release bundle")
	}
	if err := verifySynologyBundle(release, binding, bundle.data); err != nil {
		return nil, err
	}
	return assets, nil
}

func snapshotReleaseAsset(path, name string) (localAsset, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxReleaseAssetSize {
		return localAsset{}, fmt.Errorf("release asset %q is not a bounded regular file", name)
	}
	file, err := os.Open(path)
	if err != nil {
		return localAsset{}, fmt.Errorf("open release asset %q", name)
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) {
		file.Close()
		return localAsset{}, fmt.Errorf("release asset %q changed while opening", name)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxReleaseAssetSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != after.Size() || len(data) > maxReleaseAssetSize {
		return localAsset{}, fmt.Errorf("read release asset %q", name)
	}
	digest := sha256.Sum256(data)
	return localAsset{name: name, size: after.Size(), digest: "sha256:" + hex.EncodeToString(digest[:]), data: data}, nil
}

func verifySynologyBundle(release Context, binding bindingInput, compressed []byte) error {
	compressedReader := bytes.NewReader(compressed)
	gzipReader, err := gzip.NewReader(compressedReader)
	if err != nil {
		return errors.New("Synology release bundle is not valid gzip")
	}
	gzipReader.Multistream(false)
	limited := &io.LimitedReader{R: gzipReader, N: maxExpandedBundleSize + 1}
	tarReader := tar.NewReader(limited)
	root := fmt.Sprintf("nut-2-unifi-ups-gateway-%s-synology", release.Tag)
	expected := map[string]byte{
		root + "/":                     tar.TypeDir,
		root + "/.env":                 tar.TypeReg,
		root + "/compose.yaml":         tar.TypeReg,
		root + "/compose.auth.yaml":    tar.TypeReg,
		root + "/RELEASE-METADATA.txt": tar.TypeReg,
	}
	contents := make(map[string][]byte, len(expected))
	seen := make(map[string]struct{}, len(expected))
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			gzipReader.Close()
			return errors.New("Synology release bundle contains an invalid tar stream")
		}
		wantedType, exists := expected[header.Name]
		if !exists || header.Typeflag != wantedType || header.Uid != 0 || header.Gid != 0 || header.Size < 0 || header.Size > maxBundleMemberSize {
			gzipReader.Close()
			return errors.New("Synology release bundle contains an unexpected member")
		}
		if _, duplicate := seen[header.Name]; duplicate {
			gzipReader.Close()
			return errors.New("Synology release bundle contains a duplicate member")
		}
		seen[header.Name] = struct{}{}
		if wantedType == tar.TypeDir {
			if header.Size != 0 || header.Mode&0o7777 != 0o755 {
				gzipReader.Close()
				return errors.New("Synology release bundle root has invalid metadata")
			}
			continue
		}
		expectedMode := int64(0o644)
		if header.Name == root+"/.env" {
			expectedMode = 0o600
		}
		if header.Mode&0o7777 != expectedMode || header.Size == 0 {
			gzipReader.Close()
			return errors.New("Synology release bundle member has invalid metadata")
		}
		member, err := io.ReadAll(io.LimitReader(tarReader, maxBundleMemberSize+1))
		if err != nil || int64(len(member)) != header.Size || len(member) > maxBundleMemberSize {
			gzipReader.Close()
			return errors.New("Synology release bundle member exceeds its safety bound")
		}
		contents[header.Name] = member
	}
	if len(seen) != len(expected) || limited.N <= 0 {
		gzipReader.Close()
		return errors.New("Synology release bundle member set is incomplete")
	}
	trailing, err := io.ReadAll(limited)
	if err != nil || limited.N <= 0 {
		gzipReader.Close()
		return errors.New("Synology release bundle exceeds its expansion bound")
	}
	for _, value := range trailing {
		if value != 0 {
			gzipReader.Close()
			return errors.New("Synology release bundle contains data after the tar terminator")
		}
	}
	if err := gzipReader.Close(); err != nil || compressedReader.Len() != 0 {
		return errors.New("Synology release bundle contains trailing or concatenated gzip data")
	}
	if err := verifyBundleEnvironment(release, binding, contents[root+"/.env"]); err != nil {
		return err
	}
	composeDigest := sha256.Sum256(contents[root+"/compose.yaml"])
	composeAuthDigest := sha256.Sum256(contents[root+"/compose.auth.yaml"])
	if hex.EncodeToString(composeDigest[:]) != composeSHA256 || hex.EncodeToString(composeAuthDigest[:]) != composeAuthSHA256 {
		return errors.New("Synology compose files do not match the reviewed release templates")
	}
	expectedMetadata := fmt.Sprintf("Release tag: %s\nSource commit: %s\nImage: %s@%s\nRetention anchor: %s:%s\nWorkflow run: %d (attempt %d)\n", release.Tag, release.SourceSHA, ImageName, binding.digest, ImageName, release.OCITag(), release.RunID, release.RunAttempt)
	if string(contents[root+"/RELEASE-METADATA.txt"]) != expectedMetadata {
		return errors.New("Synology release metadata does not match this workflow")
	}
	return nil
}

func verifyBundleEnvironment(release Context, binding bindingInput, data []byte) error {
	if len(data) == 0 || bytes.IndexByte(data, 0) >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return errors.New("Synology bundle environment is malformed")
	}
	if string(data) != expectedBundleEnvironment(release, binding) {
		return errors.New("Synology bundle environment does not match the reviewed digest-pinned template")
	}
	return nil
}

func expectedBundleEnvironment(release Context, binding bindingInput) string {
	return fmt.Sprintf(`# Generated for %s; keep the OCI manifest digest pinned.
# Source-tree example for local development and review. The published Synology
# release bundle replaces this tag with the exact multi-platform OCI digest.
N2U_IMAGE=%s@%s
# Same-Synology NUT: keep loopback and the insecure-remote opt-in disabled.
# Remote NUT: replace the address, set the correct UPS name, and set the opt-in
# to true only on a trusted LAN or VPN. NUT traffic is not encrypted.
N2U_NUT_ADDRESS=127.0.0.1:3493
N2U_NUT_UPS=ups
N2U_NUT_TIMEOUT=5s
N2U_NUT_ALLOW_INSECURE_REMOTE=false
# Authentication overlay only:
# N2U_NUT_USERNAME=monitor
# File must be host-administered, mode 0400, and owned by numeric UID/GID 65532.
# N2U_NUT_PASSWORD_SECRET_FILE=/absolute/path/to/nut_password
N2U_UNIFI_MODEL=USWDA26
N2U_UNIFI_VERSION=1.6.1
# Interoperability experiment for rename-related controller configuration.
# Whether it clears Getting Ready remains CANDIDATE; it mirrors cfgversion only.
# It does not promise a Network UI transition.
# Enable only for authenticated GCM under a non-default key on a trusted LAN.
N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC=false
# Multi-field configuration receipts: off, memory (first test), or persistent.
# Requires the volatile option above to stay false. Trusted management LAN only.
# CANDIDATE until live acceptance; received settings are not applied.
N2U_UNIFI_HTTP_GCM_CONFIG_RECEIPT_MODE=off
# Experimental: leave false unless a separate, credential-free NUT service was
# verified from another LAN host at the emulated device IP, served ID, and port.
N2U_UNIFI_NUT_SERVER_ENABLED=false
N2U_UNIFI_NUT_SERVER_ID=ups
N2U_UNIFI_NUT_SERVER_PORT=3493
# Replace "unifi" with the final IP address or resolvable name of the console
# before first startup. First adoption must happen on a trusted management LAN.
N2U_INFORM_URL=http://unifi:8080/inform
N2U_INFORM_INTERVAL=10s
N2U_INFORM_TIMEOUT=10s
N2U_DISCOVERY_INTERVAL=30s
N2U_POLL_INTERVAL=5s
N2U_STALE_AFTER=20s
N2U_DEVICE_HOSTNAME=nut-2-unifi-ups-gateway
N2U_HEALTH_ADDRESS=127.0.0.1:9199
N2U_LOG_LEVEL=info
`, release.Tag, ImageName, binding.digest)
}
