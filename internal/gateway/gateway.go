// Package gateway composes the bounded NUT, model, UniFi, state, discovery,
// and health components into the long-running compatibility service.
package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/health"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/model"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/nut"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/discovery"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

// Poller is the read-only upstream seam used by the runtime and its tests.
type Poller interface {
	Poll(context.Context) (nut.Snapshot, error)
}

// Options supplies test seams. Zero values select production implementations.
type Options struct {
	Poller     Poller
	Controller Controller
	Resolver   Resolver
	Monitor    *health.Monitor
	Logger     *slog.Logger
	Network    NetworkIdentity
	Now        func() time.Time
	SaveState  func(string, state.State) error
}

// Gateway is safe for concurrent health, poll, and inform activity.
type Gateway struct {
	configuration config.Config
	poller        Poller
	controller    Controller
	encoder       *inform.Encoder
	monitor       *health.Monitor
	logger        *slog.Logger
	network       NetworkIdentity
	now           func() time.Time
	saveState     func(string, state.State) error
	started       time.Time
	mac           [6]byte
	informMu      sync.Mutex

	mu            sync.RWMutex
	persistent    state.State
	latest        nut.Snapshot
	haveLatest    bool
	upstreamOK    bool
	lastInform    time.Time
	nextDiscovery uint32
}

// New validates every dependency, loads or creates the stable emulated
// identity, and constructs a gateway without opening listeners.
func New(ctx context.Context, configuration config.Config, options Options) (*Gateway, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if _, err := inform.ResolveProfile(inform.DeviceProfile{
		Model:           configuration.UniFi.Model,
		FirmwareVersion: configuration.UniFi.Version,
	}); err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Monitor == nil {
		options.Monitor = health.New(configuration.Runtime.StaleAfter)
	}
	if options.SaveState == nil {
		options.SaveState = state.Save
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}

	poller := options.Poller
	if poller == nil {
		client, err := nut.New(nut.Config{
			Address:  configuration.NUT.Address,
			UPSName:  configuration.NUT.UPSName,
			Username: configuration.NUT.Username,
			Password: configuration.NUT.Password,
			Timeout:  configuration.NUT.Timeout,
		})
		if err != nil {
			return nil, err
		}
		poller = client
	}
	controller := options.Controller
	if controller == nil {
		var err error
		controller, err = NewHTTPController(configuration.UniFi.InformTimeout)
		if err != nil {
			return nil, err
		}
	}

	persistent, err := state.LoadOrCreate(
		configuration.Runtime.StateFile,
		configuration.Device.MAC,
		configuration.Device.Serial,
		configuration.UniFi.InformURL,
		inform.DefaultKey,
	)
	if err != nil {
		return nil, err
	}
	if err := adoptionFromState(persistent).Validate(); err != nil {
		return nil, err
	}

	network := options.Network
	if network == (NetworkIdentity{}) {
		network, err = ResolveNetworkIdentity(ctx, configuration.Device.IP, persistent.Adoption.InformURL, options.Resolver)
		if err != nil {
			return nil, err
		}
	}
	if net.ParseIP(network.DeviceIP).To4() == nil || net.ParseIP(network.InformIP).To4() == nil || net.ParseIP(network.Netmask).To4() == nil {
		return nil, errors.New("gateway network identity requires IPv4 values")
	}

	hardwareAddress, err := net.ParseMAC(persistent.Identity.MAC)
	if err != nil || len(hardwareAddress) != len([6]byte{}) {
		return nil, errors.New("gateway persistent MAC is invalid")
	}
	var mac [6]byte
	copy(mac[:], hardwareAddress)
	encoder, err := inform.NewEncoder()
	if err != nil {
		return nil, err
	}
	gateway := &Gateway{
		configuration: configuration,
		poller:        poller,
		controller:    controller,
		encoder:       encoder,
		monitor:       options.Monitor,
		logger:        options.Logger,
		network:       network,
		now:           options.Now,
		saveState:     options.SaveState,
		started:       options.Now().UTC(),
		mac:           mac,
		persistent:    persistent,
		nextDiscovery: 1,
	}
	gateway.monitor.SetAdopted(persistent.Adoption.Adopted)
	return gateway, nil
}

// PollOnce performs one bounded NUT observation and updates readiness.
func (g *Gateway) PollOnce(ctx context.Context) error {
	snapshot, err := g.poller.Poll(ctx)
	now := g.now().UTC()
	if err != nil {
		g.mu.Lock()
		g.upstreamOK = false
		g.mu.Unlock()
		g.monitor.MarkPoll(now, false)
		return err
	}
	if observation := g.mapObservation(snapshot, now); observation.Availability != model.AvailabilityAvailable {
		g.mu.Lock()
		g.upstreamOK = false
		g.mu.Unlock()
		g.monitor.MarkPoll(now, false)
		return errors.New("NUT observation is not semantically available")
	}
	g.mu.Lock()
	g.latest = snapshot
	g.haveLatest = true
	g.upstreamOK = true
	g.mu.Unlock()
	g.monitor.MarkPoll(now, true)
	return nil
}

// InformOnce projects the latest NUT observation and performs one complete
// TNBU exchange. Controller state is committed only after endpoint-transition
// authorization and a successful atomic state-file replacement.
func (g *Gateway) InformOnce(ctx context.Context) (inform.Outcome, error) {
	g.informMu.Lock()
	defer g.informMu.Unlock()

	g.mu.RLock()
	snapshot := g.latest
	haveLatest := g.haveLatest
	upstreamOK := g.upstreamOK
	persistent := g.persistent
	lastInform := g.lastInform
	g.mu.RUnlock()
	now := g.now().UTC()
	if !haveLatest || !upstreamOK {
		return inform.Outcome{}, errors.New("inform skipped without a current valid NUT observation")
	}

	observation := g.mapObservation(snapshot, now)
	if observation.Availability != model.AvailabilityAvailable {
		return inform.Outcome{}, errors.New("inform skipped because NUT telemetry is not current")
	}
	report := projectPowerDevice(g.configuration, persistent, g.network, g.mac, observation, now, g.started, lastInform)
	payload, err := inform.BuildPowerDevicePayload(report)
	if err != nil {
		return inform.Outcome{}, err
	}
	mode := inform.ModeCBC
	if persistent.Adoption.UseAESGCM {
		mode = inform.ModeGCM
	}
	requestPacket, err := g.encoder.Encode(inform.Packet{MAC: g.mac, Payload: payload}, persistent.Adoption.AuthKey, mode)
	if err != nil {
		return inform.Outcome{}, err
	}
	controllerReached := false
	informResult := health.InformFailure
	defer func() {
		g.monitor.MarkInform(now, controllerReached, informResult)
	}()
	responsePacket, err := g.controller.Exchange(ctx, persistent.Adoption.InformURL, requestPacket)
	if err != nil {
		controllerReached = controllerResponseReceived(err)
		if errors.Is(err, ErrAdoptionPending) {
			informResult = health.InformPending
		}
		return inform.Outcome{}, err
	}
	controllerReached = true
	decoded, err := (inform.Decoder{ExpectedMAC: &g.mac, ExpectedMode: &mode}).Decode(responsePacket, persistent.Adoption.AuthKey)
	if err != nil {
		return inform.Outcome{}, err
	}
	nextAdoption := adoptionFromState(persistent)
	outcome, err := nextAdoption.ApplyControllerResponse(decoded.Payload)
	if err != nil {
		return inform.Outcome{}, err
	}
	outcome.Interval = cappedInformInterval(outcome.Interval, g.configuration.UniFi.InformInterval)
	if outcome.Kind == inform.ResponseRelayControl && len(outcome.CycleIntents) != 0 {
		// Firmware-proven relayctl is a per-outlet power-cycle operation. This
		// 4+4 zone gateway has no proven atomic NUT equivalent, so v1 observes
		// and explicitly ignores the request without invoking upstream writes.
		g.logger.Warn("controller relay cycle ignored", "component", "control", "intent_count", len(outcome.CycleIntents))
	}
	if nextAdoption.InformURL != persistent.Adoption.InformURL {
		if err := g.controller.AuthorizeTransition(ctx, persistent.Adoption.InformURL, nextAdoption.InformURL); err != nil {
			return inform.Outcome{}, err
		}
	}

	nextPersistent := persistent
	nextPersistent.Adoption = adoptionToState(nextAdoption)
	if nextPersistent.Adoption != persistent.Adoption {
		if err := g.saveState(g.configuration.Runtime.StateFile, nextPersistent); err != nil {
			return inform.Outcome{}, err
		}
	}
	g.mu.Lock()
	g.persistent = nextPersistent
	g.lastInform = now
	g.mu.Unlock()
	informResult = health.InformSuccess
	g.monitor.SetAdopted(nextPersistent.Adoption.Adopted)
	return outcome, nil
}

func (g *Gateway) mapObservation(snapshot nut.Snapshot, now time.Time) model.State {
	return model.FromSnapshot(snapshot, model.Options{
		Now:        now,
		StaleAfter: g.configuration.Runtime.StaleAfter,
	})
}

// Cycle is the deterministic end-to-end test and one-shot seam.
func (g *Gateway) Cycle(ctx context.Context) (inform.Outcome, error) {
	if err := g.PollOnce(ctx); err != nil {
		return inform.Outcome{}, err
	}
	return g.InformOnce(ctx)
}

// Run serves health and discovery while polling and informing until ctx is
// cancelled. Operational upstream failures update health and are retried;
// listener failures stop the process.
func (g *Gateway) Run(ctx context.Context) error {
	healthListener, err := net.Listen("tcp", g.configuration.Runtime.HealthAddress)
	if err != nil {
		return errors.New("bind health listener")
	}
	discoverySocket, err := openDiscoveryBroadcaster(g.network.DeviceIP)
	if err != nil {
		_ = healthListener.Close()
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	server := health.Server(g.configuration.Runtime.HealthAddress, g.monitor.Handler())
	fatal := make(chan error, 2)
	var workers sync.WaitGroup
	initialPollDone := make(chan struct{})
	workers.Add(4)
	go func() {
		defer workers.Done()
		if err := server.Serve(healthListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case fatal <- errors.New("health server failed"):
			default:
			}
		}
	}()
	go func() {
		defer workers.Done()
		g.announcementLoop(runContext, discoverySocket)
	}()
	go func() {
		defer workers.Done()
		g.pollLoop(runContext, initialPollDone)
	}()
	go func() {
		defer workers.Done()
		g.informLoop(runContext, initialPollDone)
	}()

	var result error
	select {
	case <-ctx.Done():
	case result = <-fatal:
	}
	cancel()
	_ = discoverySocket.Close()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil && result == nil {
		result = errors.New("health server shutdown failed")
	}
	workers.Wait()
	return result
}

func (g *Gateway) pollLoop(ctx context.Context, initialPollDone chan<- struct{}) {
	pollTicker := time.NewTicker(g.configuration.Runtime.PollInterval)
	defer pollTicker.Stop()
	if err := g.PollOnce(ctx); err != nil {
		g.logger.Warn("NUT poll failed", "component", "nut")
	}
	close(initialPollDone)
	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTicker.C:
			if err := g.PollOnce(ctx); err != nil {
				g.logger.Warn("NUT poll failed", "component", "nut")
			}
		}
	}
}

func (g *Gateway) informLoop(ctx context.Context, initialPollDone <-chan struct{}) {
	select {
	case <-ctx.Done():
		return
	case <-initialPollDone:
	}
	informInterval := g.configuration.UniFi.InformInterval
	outcome, err := g.InformOnce(ctx)
	if err != nil {
		g.logInformFailure(err)
	} else if outcome.Interval > 0 {
		informInterval = outcome.Interval
	}
	informTimer := time.NewTimer(informInterval)
	defer informTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-informTimer.C:
			outcome, err := g.InformOnce(ctx)
			if err != nil {
				g.logInformFailure(err)
			} else if outcome.Interval > 0 {
				informInterval = outcome.Interval
			}
			informTimer.Reset(informInterval)
		}
	}
}

func (g *Gateway) logInformFailure(err error) {
	if errors.Is(err, ErrAdoptionPending) {
		g.logger.Debug("controller inform pending or device profile unrecognized", "component", "unifi")
		return
	}
	g.logger.Warn("controller inform failed", "component", "unifi")
}

func (g *Gateway) announcementLoop(ctx context.Context, writer discovery.PacketWriter) {
	ticker := time.NewTicker(g.configuration.UniFi.DiscoveryInterval)
	defer ticker.Stop()
	for {
		announcement, err := g.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
		if err == nil {
			var packet []byte
			packet, err = announcement.Marshal()
			if err == nil {
				destination := &net.UDPAddr{IP: net.ParseIP(discovery.BroadcastIPv4).To4(), Port: discovery.Port}
				var written int
				written, err = writer.WriteTo(packet, destination)
				if err == nil && written != len(packet) {
					err = io.ErrShortWrite
				}
			}
		}
		if err != nil {
			g.logger.Warn("discovery announcement failed", "component", "discovery")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *Gateway) discoveryAnnouncement(version discovery.Version, command uint8) (discovery.Announcement, error) {
	if version != discovery.V2 || command != discovery.CommandAnnouncement {
		return discovery.Announcement{}, errors.New("gateway emits only firmware-proven v2 command-6 discovery")
	}
	_, err := inform.ResolveProfile(inform.DeviceProfile{
		Model:           g.configuration.UniFi.Model,
		FirmwareVersion: g.configuration.UniFi.Version,
	})
	if err != nil {
		return discovery.Announcement{}, err
	}
	g.mu.Lock()
	persistent := g.persistent
	if g.nextDiscovery == 0 {
		g.mu.Unlock()
		return discovery.Announcement{}, errors.New("discovery sequence exhausted")
	}
	sequence := g.nextDiscovery
	g.nextDiscovery++
	g.mu.Unlock()
	hardwareAddress := append(net.HardwareAddr(nil), g.mac[:]...)
	uptime := g.now().UTC().Sub(g.started) / time.Second
	if uptime < 1 {
		uptime = 1
	}
	if uptime > time.Duration(^uint32(0)) {
		uptime = time.Duration(^uint32(0))
	}
	uptimeSeconds := uint32(uptime)
	isDefault := !persistent.Adoption.Adopted
	hashID, anonID := deriveDiscoveryIDs(persistent.Identity.GUID, g.mac, g.configuration.UniFi.Model)
	identityIP := net.ParseIP(g.network.DeviceIP).To4()
	if g.configuration.UniFi.Model == inform.ModelUPS2UProEU {
		return discovery.NewUSPDA2CAnnouncement(discovery.USPDA2CIdentity{
			MAC: hardwareAddress, IP: identityIP, Hostname: g.configuration.Device.Hostname,
			Uptime: uptimeSeconds, Sequence: sequence, IsDefault: isDefault,
			HashID: hashID, AnonID: anonID,
		})
	}
	return discovery.NewUSWDA26Announcement(discovery.USWDA26Identity{
		MAC: hardwareAddress, IP: identityIP, Hostname: g.configuration.Device.Hostname,
		Uptime: uptimeSeconds, Sequence: sequence, IsDefault: isDefault,
		HashID: hashID, AnonID: anonID,
	})
}

func deriveDiscoveryIDs(guid string, mac [6]byte, profile string) ([8]byte, [16]byte) {
	hashMaterial := make([]byte, 0, len("n2u-hash-id\x00")+len(guid)+len(mac))
	hashMaterial = append(hashMaterial, "n2u-hash-id\x00"...)
	hashMaterial = append(hashMaterial, guid...)
	hashMaterial = append(hashMaterial, mac[:]...)
	hashDigest := sha256.Sum256(hashMaterial)

	anonMaterial := make([]byte, 0, len("n2u-anon-id\x00")+len(guid)+len(mac))
	anonMaterial = append(anonMaterial, "n2u-anon-id\x00"...)
	anonMaterial = append(anonMaterial, guid...)
	anonMaterial = append(anonMaterial, mac[:]...)
	anonDigest := sha256.Sum256(anonMaterial)

	var hashID [8]byte
	var anonID [16]byte
	copy(hashID[:], hashDigest[:len(hashID)])
	copy(anonID[:], anonDigest[:len(anonID)])
	if profile == inform.ModelUPS2UEU {
		// UPS26 firmware deliberately normalizes its anonymous UUID with a
		// non-RFC nibble layout: text[14]='8' and text[19]='4'. Discovery TLV
		// 0x2a carries these bytes and inform renders the same bytes.
		anonID[6] = (anonID[6] & 0x0f) | 0x80
		anonID[8] = (anonID[8] & 0x0f) | 0x40
	}
	return hashID, anonID
}

func adoptionFromState(persistent state.State) inform.AdoptionState {
	return inform.AdoptionState{
		AuthKey:    persistent.Adoption.AuthKey,
		InformURL:  persistent.Adoption.InformURL,
		CfgVersion: persistent.Adoption.CfgVersion,
		Adopted:    persistent.Adoption.Adopted,
		UseAESGCM:  persistent.Adoption.UseAESGCM,
	}
}

func adoptionToState(adoption inform.AdoptionState) state.Adoption {
	return state.Adoption{
		AuthKey:    adoption.AuthKey,
		InformURL:  adoption.InformURL,
		CfgVersion: adoption.CfgVersion,
		Adopted:    adoption.Adopted,
		UseAESGCM:  adoption.UseAESGCM,
	}
}

// cappedInformInterval honors a controller's request only when it cannot
// weaken the operator-selected local inform cadence. Zero remains the wire
// signal to preserve the current negotiated cadence.
func cappedInformInterval(requested, localMaximum time.Duration) time.Duration {
	if requested > localMaximum {
		return localMaximum
	}
	return requested
}
