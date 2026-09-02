package discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type writeRecord struct {
	packet []byte
	addr   net.Addr
}

type recordingWriter struct {
	mu      sync.Mutex
	records []writeRecord
	fail    bool
}

func (w *recordingWriter) WriteTo(packet []byte, addr net.Addr) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail {
		return 0, errors.New("injected write failure with private details")
	}
	w.records = append(w.records, writeRecord{packet: append([]byte(nil), packet...), addr: addr})
	return len(packet), nil
}

func TestAnnouncerUsesInjectedWriterAndMonotonicSequence(t *testing.T) {
	destinations := []net.Addr{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: Port},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: Port},
	}
	announcer, err := NewAnnouncer(sampleAnnouncement(), destinations)
	if err != nil {
		t.Fatal(err)
	}
	writer := &recordingWriter{}
	if err := announcer.Announce(writer); err != nil {
		t.Fatal(err)
	}
	if err := announcer.Announce(writer); err != nil {
		t.Fatal(err)
	}
	if len(writer.records) != 4 {
		t.Fatalf("writes = %d, want 4", len(writer.records))
	}
	first, err := Parse(writer.records[0].packet)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse(writer.records[2].packet)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 7 || second.Sequence != 8 {
		t.Fatalf("announcement sequences = %d,%d, want 7,8", first.Sequence, second.Sequence)
	}
}

func TestAnnouncerFailureIsRedacted(t *testing.T) {
	announcer, err := NewAnnouncer(sampleAnnouncement(), []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: Port}})
	if err != nil {
		t.Fatal(err)
	}
	err = announcer.Announce(&recordingWriter{fail: true})
	if err == nil || err.Error() != "discovery: announce write failed" {
		t.Fatalf("write error missing or leaked details: %v", err)
	}
}

func TestAnnouncerRunHonorsCancellationWithoutLiveSocket(t *testing.T) {
	announcer, err := NewAnnouncer(sampleAnnouncement(), []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: Port}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer := &recordingWriter{}
	if err := announcer.Run(ctx, writer, time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(writer.records) != 1 {
		t.Fatalf("cancelled run writes = %d, want immediate one only", len(writer.records))
	}
}

func TestResponderAnswersV1AndV2QueriesWithoutTraffic(t *testing.T) {
	responder, err := NewResponder(sampleAnnouncement())
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []Version{V1, V2} {
		request, err := Query(version)
		if err != nil {
			t.Fatal(err)
		}
		response, handled, err := responder.ResponseFor(request)
		if err != nil {
			t.Fatal(err)
		}
		if !handled {
			t.Fatalf("v%d query was not handled", version)
		}
		announcement, err := Parse(response)
		if err != nil {
			t.Fatal(err)
		}
		if announcement.Version != version || announcement.Command != CommandDiscover {
			t.Fatalf("v%d response header = v%d command %d", version, announcement.Version, announcement.Command)
		}
		if err := announcement.ValidateIdentity(); err != nil {
			t.Fatalf("v%d response identity: %v", version, err)
		}
	}
}

func TestResponderDoesNotLoopAnnouncements(t *testing.T) {
	responder, err := NewResponder(sampleAnnouncement())
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := sampleAnnouncement().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	response, handled, err := responder.ResponseFor(announcement)
	if err != nil {
		t.Fatal(err)
	}
	if handled || response != nil {
		t.Fatal("responder answered an announcement")
	}
	if _, _, err := responder.ResponseFor([]byte{1, 0}); err == nil {
		t.Fatal("malformed probe did not fail closed")
	}
}

func TestDefaultDestinationsArePort10001(t *testing.T) {
	destinations := DefaultDestinations()
	if len(destinations) != 1 {
		t.Fatalf("destinations = %d, want firmware-faithful broadcast only", len(destinations))
	}
	for _, destination := range destinations {
		udp, ok := destination.(*net.UDPAddr)
		if !ok || udp.Port != Port || udp.IP.To4() == nil {
			t.Fatalf("invalid default destination: %v", destination)
		}
	}
}

func TestPrivateSourcePolicy(t *testing.T) {
	for _, addr := range []*net.UDPAddr{
		{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		{IP: net.IPv4(192, 168, 1, 1), Port: 1234},
		{IP: net.IPv4(169, 254, 1, 1), Port: 1234},
	} {
		if !privateSource(addr) {
			t.Fatalf("local source rejected: %v", addr)
		}
	}
	if privateSource(&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 1234}) {
		t.Fatal("public source accepted")
	}
}
