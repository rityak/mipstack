package mipstack

import (
	"io"
	"testing"
	"time"
)

// New echoes on full-sized segments are sampled and smoothed; repeated echoes
// and short segments are ignored.
func TestTCPReceiveRTTFromTimestampEchoes(t *testing.T) {
	var r tcpReceiveRTT
	r.observe(1010, 1000, false) // short segment
	r.observe(1010, 0, true)     // no echo
	if r.duration() != 0 {
		t.Fatalf("sampled a short segment or a missing echo: %v", r.duration())
	}
	r.observe(1010, 1000, true)
	if r.duration() != 10*time.Millisecond {
		t.Fatalf("first sample = %v, want 10ms", r.duration())
	}
	r.observe(1050, 1000, true) // same echo: the gap between segments, not an RTT
	if r.duration() != 10*time.Millisecond {
		t.Fatalf("repeated echo changed the estimate to %v", r.duration())
	}
	r.observe(1100, 1082, true) // 18 ms: smoothed by 1/8
	if want := 11 * time.Millisecond; r.duration() != want {
		t.Fatalf("smoothed rtt = %v, want %v", r.duration(), want)
	}
	r.observe(1100, 1100, true) // same tick counts as 1 ms
	if r.rtt == 0 || r.duration() >= 11*time.Millisecond {
		t.Fatalf("zero-tick sample not counted as 1 ms: %v", r.duration())
	}
}

// A receive-only connection whose handshake RTT is far below the data RTT (a
// local TUN in front of queued data) must still grow its receive buffer when
// the sender is limited by the advertised window (miray T-016).
func TestTCPReceiveAutoTuningGrowsWithHandshakeRTTBelowDataRTT(t *testing.T) {
	sender, receiver, link := newTestTCPConnectionPair(t, "cubic", testLinkConditions{})
	initial := receiver.Info().ReceiveBufferCapacity
	link.extraLatency.Store(int64(5 * time.Millisecond)) // data RTT 10 ms, handshake ~0

	done := make(chan struct{})
	go func() {
		defer close(done)
		chunk := make([]byte, 64<<10)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := sender.Write(chunk); err != nil {
				return
			}
		}
		_ = sender.CloseWrite()
	}()
	if _, err := io.Copy(io.Discard, receiver); err != nil {
		t.Fatal(err)
	}
	<-done

	if got := receiver.Info().ReceiveBufferCapacity; got <= initial {
		t.Fatalf("receive buffer stayed at %d (initial %d): auto-tuning did not grow", got, initial)
	}
}

// The receive target is derived from bytes the application consumed: a slow
// reader keeps the initial buffer however fast the sender is.
func TestTCPReceiveAutoTuningIgnoresSlowReader(t *testing.T) {
	sender, receiver, link := newTestTCPConnectionPair(t, "cubic", testLinkConditions{})
	initial := receiver.Info().ReceiveBufferCapacity
	link.extraLatency.Store(int64(5 * time.Millisecond))

	go func() {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := sender.Write(chunk); err != nil {
				return
			}
		}
	}()
	buffer := make([]byte, 16<<10)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) { // ~1.6 MB/s, about 16 KB per 10 ms RTT
		if _, err := receiver.Read(buffer); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := receiver.Info().ReceiveBufferCapacity; got != initial {
		t.Fatalf("slow reader grew the receive buffer from %d to %d", initial, got)
	}
}
