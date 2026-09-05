package gateway

import (
	"errors"
	"os"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/health"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

// Firmware receipt metadata is accessed only at startup or under informMu.
// The published version is separately protected by mu for discovery snapshots.
func (g *Gateway) resetFirmwareContext(s state.State) {
	g.firmwareReceipt = state.FirmwareReceipt{}
	g.firmwareEpoch = ""
	if !g.configuration.UniFi.ReportedFirmwareSync {
		return
	}
	g.monitor.RecordFirmwareReceipt(health.ReceiptPending)
	if g.firmwareBlocked || g.receiptBlocked {
		g.monitor.RecordFirmwareReceipt(health.ReceiptStorageError)
	}
	if !g.receiptsEligible(s, inform.ModeGCM) {
		return
	}
	profile, err := inform.ResolveProfile(inform.DeviceProfile{Model: g.configuration.UniFi.Model, FirmwareVersion: g.configuration.UniFi.Version})
	if err != nil {
		return
	}
	g.firmwareEpoch, _ = state.FirmwareEpoch(s, g.configuration.UniFi.Model, profile.FullVersion)
}

func (g *Gateway) initializeFirmwareReceipt() {
	g.resetFirmwareContext(g.persistent)
	if g.firmwareEpoch == "" || g.receiptBlocked {
		return
	}
	r, err := state.LoadFirmwareReceipt(state.FirmwareReceiptPath(g.configuration.Runtime.StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		g.blockFirmwareReceipts()
		return
	}
	if r.Epoch != g.firmwareEpoch {
		return
	}
	g.firmwareReceipt = r
	g.reportedFirmwareVersion = r.Version
	g.monitor.RecordFirmwareReceipt(health.ReceiptStored)
}

func (g *Gateway) blockFirmwareReceipts() {
	g.firmwareBlocked = true
	g.monitor.RecordFirmwareReceipt(health.ReceiptStorageError)
	g.logger.Error("reported firmware storage unavailable; repair storage and restart", "component", "configuration")
}

func (g *Gateway) acceptFirmwareTarget(target inform.FirmwareTarget, nonce [16]byte, now time.Time) error {
	if g.firmwareBlocked || g.receiptBlocked || g.firmwareEpoch == "" {
		g.monitor.RecordFirmwareReceipt(health.ReceiptStorageError)
		return errors.New("reported firmware storage unavailable")
	}
	if target.Version == g.firmwareReceipt.Version {
		g.monitor.RecordFirmwareReceipt(health.ReceiptStored)
		return nil
	}
	if !g.firmwareLastWrite.IsZero() && now.Sub(g.firmwareLastWrite) < receiptWriteInterval {
		g.monitor.RecordFirmwareReceipt(health.ReceiptRateLimited)
		return errors.New("reported firmware write deferred by local rate limit")
	}
	next := state.NewFirmwareReceipt(g.firmwareEpoch, target.Version, g.firmwareReceipt, nonce)
	g.firmwareLastWrite = now
	if err := g.saveFirmwareReceipt(state.FirmwareReceiptPath(g.configuration.Runtime.StateFile), next); err != nil {
		g.blockFirmwareReceipts()
		return errors.New("reported firmware receipt commit failed")
	}
	g.firmwareReceipt = next
	g.mu.Lock()
	g.reportedFirmwareVersion = next.Version
	g.mu.Unlock()
	g.monitor.RecordFirmwareReceipt(health.ReceiptStored)
	g.logger.Info("controller firmware target recorded; no firmware installed", "component", "configuration")
	return nil
}
