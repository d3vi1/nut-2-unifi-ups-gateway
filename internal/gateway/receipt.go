package gateway

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/health"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

const receiptWriteInterval = 30 * time.Second

// Receipt state is accessed only during initialization or under informMu.
func (g *Gateway) receiptsEligible(s state.State, mode inform.Mode) bool {
	endpoint, err := parseControllerURL(s.Adoption.InformURL)
	return g.configuration.UniFi.ConfigReceiptsEnabled() && err == nil && endpoint.Scheme == "http" && s.Adoption.Adopted && s.Adoption.UseAESGCM && mode == inform.ModeGCM && !strings.EqualFold(s.Adoption.AuthKey, inform.DefaultKey)
}

func (g *Gateway) resetReceiptContext(s state.State) {
	g.receipt = state.Receipt{}
	g.receiptEpoch = ""
	if g.configuration.UniFi.ConfigReceiptsEnabled() {
		g.monitor.RecordConfigReceipt(health.ReceiptPending)
		if g.receiptBlocked {
			g.monitor.RecordConfigReceipt(health.ReceiptStorageError)
		}
		if g.receiptsEligible(s, inform.ModeGCM) {
			g.receiptEpoch, _ = state.ReceiptEpoch(s, g.configuration.UniFi.Model)
		}
	}
}

func (g *Gateway) initializeReceipt() {
	g.resetReceiptContext(g.persistent)
	if g.receiptEpoch == "" || g.configuration.UniFi.ConfigReceiptMode != "persistent" {
		return
	}
	receipt, err := state.LoadReceipt(state.ReceiptPath(g.configuration.Runtime.StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		g.blockReceipts()
		return
	}
	if receipt.Epoch != g.receiptEpoch {
		return
	}
	g.receipt = receipt
	g.reportedCfgVersion = receipt.CfgVersion
	g.monitor.RecordConfigReceipt(health.ReceiptStored)
}

func (g *Gateway) blockReceipts() {
	g.receiptBlocked = true
	g.monitor.RecordConfigReceipt(health.ReceiptStorageError)
	g.logger.Error("configuration receipt storage unavailable; repair storage and restart", "component", "configuration")
}

func (g *Gateway) acceptConfigReceipt(candidate inform.ConfigReceipt, nonce [16]byte, now time.Time) error {
	if g.receiptBlocked || g.receiptEpoch == "" {
		g.monitor.RecordConfigReceipt(health.ReceiptStorageError)
		return errors.New("configuration receipt storage unavailable")
	}
	g.monitor.SetIgnoredControllerSettings(len(candidate.UnsupportedSettings))
	if candidate.CfgVersion == g.receipt.CfgVersion {
		if g.configuration.UniFi.ConfigReceiptMode == "persistent" {
			g.monitor.RecordConfigReceipt(health.ReceiptStored)
		} else {
			g.monitor.RecordConfigReceipt(health.ReceiptReceived)
		}
		return nil
	}
	next := state.NewReceipt(g.receiptEpoch, candidate.CfgVersion, g.receipt, nonce)
	if g.configuration.UniFi.ConfigReceiptMode == "persistent" {
		if !g.receiptLastWrite.IsZero() && now.Sub(g.receiptLastWrite) < receiptWriteInterval {
			g.monitor.RecordConfigReceipt(health.ReceiptRateLimited)
			return errors.New("configuration receipt write deferred by local rate limit")
		}
		g.receiptLastWrite = now
		if err := g.saveReceipt(state.ReceiptPath(g.configuration.Runtime.StateFile), next); err != nil {
			// A rename may already have succeeded. Never continue from ambiguous
			// durable state in this process after a failed commit.
			g.blockReceipts()
			return errors.New("configuration receipt commit failed")
		}
		g.monitor.RecordConfigReceipt(health.ReceiptStored)
	} else {
		g.monitor.RecordConfigReceipt(health.ReceiptReceived)
	}
	g.receipt = next
	g.mu.Lock()
	g.reportedCfgVersion = next.CfgVersion
	g.mu.Unlock()
	g.logger.Info("controller configuration receipt accepted; unsupported settings remain unapplied", "component", "configuration", "mode", g.configuration.UniFi.ConfigReceiptMode, "ignored_setting_categories", len(candidate.UnsupportedSettings))
	return nil
}
