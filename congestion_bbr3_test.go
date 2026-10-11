package mipstack

import (
	"bytes"
	"context"
	"net/netip"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

type bbr3TailProbeRecorder struct {
	algorithm *bbr3CongestionControl
	seen      atomic.Bool
	acks      atomic.Uint64
	recovery  atomic.Uint64
}

type bbr3RenegingRecorder struct {
	algorithm *bbr3CongestionControl
	validLoss atomic.Uint64
	staleLoss atomic.Uint64
	lostBytes atomic.Uint64
}

func (r *bbr3RenegingRecorder) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventPacketLost {
		if event.PacketLossEvidenceValid {
			r.validLoss.Add(1)
		} else {
			r.staleLoss.Add(1)
		}
		r.lostBytes.Add(uint64(event.PacketBytes))
	}
	r.algorithm.HandleCongestionEvent(event)
}

func (r *bbr3TailProbeRecorder) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventACK && event.RateSample != nil {
		r.acks.Add(1)
		if event.RateSample.TailLossProbeACK() {
			r.seen.Store(true)
		}
	}
	if event.Type == CongestionEventTailLossProbeRecovered {
		r.recovery.Add(1)
	}
	r.algorithm.HandleCongestionEvent(event)
}

func bbr3RateSample(now time.Time, delivered, acked, flight uint32, interval time.Duration) *tcpDeliveryRateSample {
	remaining := uint32(0)
	if acked < flight {
		remaining = flight - acked
	}
	return &tcpDeliveryRateSample{
		priorDelivered: 1,
		delivered:      delivered,
		acked:          acked,
		priorInFlight:  flight,
		inFlight:       remaining,
		interval:       interval,
		rtt:            interval,
		smoothedRTT:    interval,
		ackTime:        now,
		valid:          interval > 0,
	}
}

func TestBBR3PacketStatePreservesLossInputs(t *testing.T) {
	state := CongestionState{
		BytesInFlight:      20_000,
		LostBytes:          uint64(^uint32(0)) + 123,
		ApplicationLimited: true,
	}
	encoded := bbr3EncodePacketState(&state, 1000)
	decoded := bbr3DecodePacketState(encoded)
	if decoded.inflight != 21_000 || decoded.lost != 122 || !decoded.applicationLimited {
		t.Fatalf("decoded packet state = %+v", decoded)
	}
	state.BytesInFlight = bbr3PacketInflightMask
	decoded = bbr3DecodePacketState(bbr3EncodePacketState(&state, 1000))
	if decoded.inflight != bbr3PacketInflightMask {
		t.Fatalf("saturated tx.in_flight = %d, want %d", decoded.inflight, bbr3PacketInflightMask)
	}
}

func TestBBR3InitialWindowFollowsControllerInitialization(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	state := CongestionState{CongestionWindow: 40 * mss, MaximumSegmentSize: mss, SmoothedRTT: time.Millisecond}
	bbr.HandleCongestionEvent(&CongestionEvent{Type: CongestionEventInitialize, Time: time.Unix(100, 0), State: &state})
	if bbr.initialWindowMSS != 40 || bbr.modelWindowForBandwidth(0, 1, mss) != 40*mss {
		t.Fatalf("initial window = %d MSS/%d bytes", bbr.initialWindowMSS, bbr.modelWindowForBandwidth(0, 1, mss))
	}
	if got := bbr3InitialWindowMSS(tcpMaximumScaledWindow, mss); got != 127 {
		t.Fatalf("capped initial window = %d MSS, want 127", got)
	}
}

func TestBBR3StartupWindowIncludesACKAggregation(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	bbr.initialWindowMSS = bbrInitialCongestionMSS
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.extraACKed[0] = 10_000
	sample := bbr3RateSample(time.Unix(100, 0), mss, mss, 25*mss, time.Millisecond)
	if window := bbr.setCongestionWindow(25*mss, sample, mss); window != 26*mss {
		t.Fatalf("Startup ACK-aggregation window = %d, want %d", window, 26*mss)
	}
}

func TestBBR3UsesLinuxDefaultGains(t *testing.T) {
	bbr := newBBR3CongestionControl()
	if gain := bbr.pacingGain(); gain != 710.0/256 {
		t.Fatalf("Startup pacing gain = %v", gain)
	}
	bbr.mode = bbrDrain
	if gain := bbr.pacingGain(); gain != 88.0/256 {
		t.Fatalf("Drain pacing gain = %v", gain)
	}
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeDown
	if gain := bbr.pacingGain(); gain != 232.0/256 {
		t.Fatalf("ProbeDOWN pacing gain = %v", gain)
	}
	bbr.probePhase = bbr3ProbeUp
	if gain := bbr.pacingGain(); gain != 1.25 || bbr.congestionWindowGain() != 2.25 {
		t.Fatalf("ProbeUP gains = pacing %v cwnd %v", gain, bbr.congestionWindowGain())
	}
}

func TestBBR3StartupPlateauEntersDrain(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.fullBandwidth = 1_000_000
	for round := 0; round < bbrFullBandwidthRounds; round++ {
		bbr.roundStart = true
		bbr.checkFullBandwidth(bbr3RateSample(now.Add(time.Duration(round)*time.Millisecond), 1000, 1000, 10_000, time.Millisecond), 1_000_000)
	}
	if !bbr.fullBandwidthReached {
		t.Fatal("three stagnant rounds did not fill the pipe")
	}
	sample := bbr3RateSample(now, 1000, 1000, 1000, time.Millisecond)
	threshold := bbr.checkDrain(sample, mss)
	if bbr.mode != bbrProbeBandwidth || bbr.probePhase != bbr3ProbeDown || threshold == 0 {
		t.Fatalf("post-Startup state = mode %v phase %v threshold %d", bbr.mode, bbr.probePhase, threshold)
	}
}

func TestBBR3ProbeBandwidthCycle(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.fullBandwidthReached = true
	bbr.enterProbePhase(bbr3ProbeDown, now)
	bbr.probeWait = 2 * time.Second
	sample := bbr3RateSample(now, 1000, 1000, 4000, time.Millisecond)
	bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 20_000, mss)
	if bbr.probePhase != bbr3ProbeCruise {
		t.Fatalf("drained phase = %s", bbr.probePhase.String())
	}
	sample.ackTime = now.Add(2*time.Second + time.Microsecond)
	bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 20_000, mss)
	if bbr.probePhase != bbr3ProbeRefill || bbr.ackPhase != bbr3ACKsRefilling {
		t.Fatalf("scheduled probe = phase %s ACK phase %d", bbr.probePhase.String(), bbr.ackPhase)
	}
	bbr.roundStart = true
	bbr.roundCount++
	bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 20_000, mss)
	if bbr.probePhase != bbr3ProbeUp || !bbr.probeSamples {
		t.Fatalf("refill completion = phase %s samples %t", bbr.probePhase.String(), bbr.probeSamples)
	}
}

func TestBBR3BandwidthFilterRotatesAfterProbeFeedback(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.fullBandwidthReached = true
	bbr.ackPhase = bbr3ACKsProbeStopping
	bbr.probeSamples = true
	bbr.roundStart = true
	bbr.bandwidthHigh = [2]float64{800_000, 1_000_000}
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 10_000, time.Millisecond)
	bbr.adaptUpperBounds(sample, bbr3PacketSnapshot{}, 20_000, 1000)
	if bbr.probeSamples || bbr.ackPhase != bbr3ACKsInitial || bbr.bandwidthHigh != [2]float64{1_000_000, 0} {
		t.Fatalf("rotated probe feedback = samples %t phase %d bw %v", bbr.probeSamples, bbr.ackPhase, bbr.bandwidthHigh)
	}
}

func TestBBR3LossBoundsAndProbePrefix(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeUp
	bbr.probeSamples = true
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.minimumRTT = 10 * time.Millisecond
	state := CongestionState{CongestionWindow: 20_000, MaximumSegmentSize: mss, LostBytes: 500}
	packetState := bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss)
	event := CongestionEvent{Type: CongestionEventPacketLost, Time: now, State: &state, PacketBytes: mss, PacketState: packetState, PacketLossEvidenceValid: true}
	bbr.onPacketLost(&event)
	if bbr.inflightHigh == 0 || bbr.inflightHigh >= 20_000 || bbr.probeSamples || bbr.probePhase != bbr3ProbeDown {
		t.Fatalf("probe loss response = inflight_hi %d samples %t phase %s", bbr.inflightHigh, bbr.probeSamples, bbr.probePhase.String())
	}

	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeCruise
	bbr.bandwidthLow = 1_000_000
	bbr.inflightLow = 20_000
	bbr.latestBandwidth = 800_000
	bbr.latestInflight = 16_000
	bbr.lossInRound = true
	bbr.lossRoundStart = true
	bbr.updateCongestionSignals(bbr3RateSample(now, 1000, 1000, 10_000, time.Millisecond), 1_000_000, 20_000)
	if bbr.bandwidthLow != 800_000 || bbr.inflightLow != 16_000 {
		t.Fatalf("lower bounds = %v/%d", bbr.bandwidthLow, bbr.inflightLow)
	}
}

func TestBBR3RenegingLossDoesNotUseProbeEvidence(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
	bbr.fullBandwidthReached, bbr.probeSamples = true, true
	bbr.minimumRTT, bbr.minimumRTTStamp = 10*time.Millisecond, now
	bbr.bandwidthHigh[1], bbr.probeStarted = 1_000_000, now
	state := CongestionState{CongestionWindow: 20_000, MaximumSegmentSize: mss, LostBytes: 500}
	event := CongestionEvent{
		Type:                    CongestionEventPacketLost,
		Time:                    now,
		State:                   &state,
		PacketBytes:             mss,
		PacketState:             bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss),
		PacketLossEvidenceValid: false,
	}
	bbr.onPacketLost(&event)
	if !bbr.lossInRound || bbr.lost != state.LostBytes || !bbr.probeSamples || bbr.probePhase != bbr3ProbeUp || bbr.inflightHigh != 0 {
		t.Fatalf("reneging loss feedback = lossInRound:%v samples:%v phase:%s inflight_hi:%d", bbr.lossInRound, bbr.probeSamples, bbr.probePhase.String(), bbr.inflightHigh)
	}
}

func TestTCPBBR3SACKRenegingLossEvidence(t *testing.T) {
	local, remote := netip.MustParseAddr("192.0.2.192"), netip.MustParseAddr("198.51.100.192")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	recorder := &bbr3RenegingRecorder{algorithm: newBBR3CongestionControl()}
	builtin, _ := registeredCongestionControlFactory(CongestionControlBBR3)
	definition := builtin.definition
	definition.Name = "BBRv3-reneging"
	definition.New = func(CongestionControlContext) CongestionController { return recorder }
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP: TCPSocketDefaults{CongestionControlFactory: factory}}); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.echoTCP, link.sackTCP, link.sackReneging = true, true, true
	link.dropTCPOrdinals = map[int]bool{1: true}
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8103))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeAndReadTCPEcho(t, connection, make([]byte, 16*1024))
	link.mu.Lock()
	renege := !link.sackRenegingAt.IsZero()
	link.mu.Unlock()
	if !renege || recorder.staleLoss.Load() < 2 || recorder.validLoss.Load() == 0 || recorder.lostBytes.Load() == 0 {
		t.Fatalf("reneging:%t stale-loss:%d ordinary-loss:%d bytes:%d", renege, recorder.staleLoss.Load(), recorder.validLoss.Load(), recorder.lostBytes.Load())
	}
	if undos := connection.(*TCPConn).Info().SpuriousRecoveryUndos; undos != 0 {
		t.Fatalf("reneging produced %d spurious undos", undos)
	}
}

// TestTCPBBR3SACKRenegingAfterHostQueueDeparture exercises the Linux-style
// host-queue barrier around SACK reneging. The first loss waits for its
// original packet to leave the device queue; the peer then reneges on the
// second SACKed range, which must likewise wait for that original packet's
// departure before publishing loss without stale probe evidence.
func TestTCPBBR3SACKRenegingAfterHostQueueDeparture(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	recorder := &bbr3RenegingRecorder{algorithm: newBBR3CongestionControl()}
	builtin, _ := registeredCongestionControlFactory(CongestionControlBBR3)
	definition := builtin.definition
	definition.Name = "BBRv3-host-queue-reneging"
	definition.New = func(CongestionControlContext) CongestionController { return recorder }
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	info := connection.Info()
	if info.CongestionControl != definition.Name {
		t.Fatalf("congestion controller = %q, want %q", info.CongestionControl, definition.Name)
	}

	link.mu.Lock()
	link.dropTCPOrdinals = map[int]bool{1: true}
	link.sackReneging = true
	link.mu.Unlock()

	type queuedData struct {
		raw      []byte
		slot     uint16
		sequence uint32
	}
	snapshotData := func() []queuedData {
		scheduler := stack.outbound.scheduler
		if scheduler == nil {
			return nil
		}
		scheduler.mu.Lock()
		defer scheduler.mu.Unlock()
		packets := make([]queuedData, 0, scheduler.queued)
		for slot := range scheduler.nodes {
			entry := scheduler.nodes[slot].entry
			if len(entry.packet) == 0 {
				continue
			}
			packet, parseErr := ParseIPPacket(entry.packet)
			if parseErr != nil || packet.Protocol != ProtocolTCP {
				continue
			}
			segment, parseErr := packet.TCPSegment()
			if parseErr != nil || len(segment.Payload) == 0 {
				continue
			}
			packets = append(packets, queuedData{
				raw: append([]byte(nil), entry.packet...), slot: uint16(slot), sequence: segment.SequenceNumber,
			})
		}
		sort.Slice(packets, func(i, j int) bool {
			return tcpSequenceLess(packets[i].sequence, packets[j].sequence)
		})
		return packets
	}

	payload := bytes.Repeat([]byte{0x7a}, 2*info.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("TCP Write = %d, %v", n, err)
	}
	var initial []queuedData
	waitFor(t, time.Second, func() bool {
		initial = snapshotData()
		return len(initial) >= 2
	})
	first, second := initial[0], initial[1]
	// Feed copies to the peer while retaining both queue-owned originals. This
	// separates wire observation from device departure, as required by the
	// host-queue loss rule.
	if err = link.handleOutboundPacket(first.raw); err != nil {
		t.Fatal(err)
	}
	if err = link.handleOutboundPacket(second.raw); err != nil {
		t.Fatal(err)
	}
	// Serialize the SACK before waiting for the loss timer. Both original
	// transmissions remain owned by the host queue at this point.
	_ = connection.Info()

	findDepartureWaiter := func() *packetQueueDepartureWaiter {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return nil
		}
		for index := range waiters.slots {
			if waiter := waiters.slots[index].Load(); waiter != nil {
				return waiter
			}
		}
		return nil
	}
	var firstWaiter *packetQueueDepartureWaiter
	waitFor(t, 2*info.RetransmissionTimeout+time.Second, func() bool {
		firstWaiter = findDepartureWaiter()
		return firstWaiter != nil
	})
	entry, available := stack.outbound.tryDequeue()
	if !available || entry.slot != first.slot {
		if available {
			stack.outbound.release(entry)
		}
		t.Fatalf("first host-queue departure slot = %d/%t, want %d", entry.slot, available, first.slot)
	}
	firstWire := consumeTestPacket(&stack.outbound, entry)
	firstPacket, err := ParseIPPacket(firstWire)
	if err != nil {
		t.Fatal(err)
	}
	firstSegment, err := firstPacket.TCPSegment()
	if err != nil || firstSegment.SequenceNumber != first.sequence {
		t.Fatalf("departed first segment = %+v, %v", firstSegment, err)
	}
	var firstRetransmission queuedData
	waitFor(t, time.Second, func() bool {
		for _, packet := range snapshotData() {
			if packet.sequence == first.sequence {
				firstRetransmission = packet
				return true
			}
		}
		return false
	})
	if err = link.handleOutboundPacket(firstRetransmission.raw); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()

	var secondWaiter *packetQueueDepartureWaiter
	waitFor(t, 2*info.RetransmissionTimeout+time.Second, func() bool {
		secondWaiter = findDepartureWaiter()
		return secondWaiter != nil && secondWaiter != firstWaiter
	})
	entry, available = stack.outbound.tryDequeue()
	if !available || entry.slot != second.slot {
		if available {
			stack.outbound.release(entry)
		}
		t.Fatalf("second host-queue departure slot = %d/%t, want %d", entry.slot, available, second.slot)
	}
	secondWire := consumeTestPacket(&stack.outbound, entry)
	secondPacket, err := ParseIPPacket(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	secondSegment, err := secondPacket.TCPSegment()
	if err != nil || secondSegment.SequenceNumber != second.sequence {
		t.Fatalf("departed second segment = %+v, %v", secondSegment, err)
	}
	waitFor(t, time.Second, func() bool { return recorder.staleLoss.Load() != 0 })
	if recorder.validLoss.Load() == 0 {
		t.Fatal("initial RACK loss did not retain valid evidence")
	}
	var secondRetransmission queuedData
	waitFor(t, time.Second, func() bool {
		for _, packet := range snapshotData() {
			if packet.sequence == second.sequence {
				secondRetransmission = packet
				return true
			}
		}
		return false
	})
	if err = link.handleOutboundPacket(secondRetransmission.raw); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	renege := !link.sackRenegingAt.IsZero()
	link.mu.Unlock()
	if !renege {
		t.Fatal("SACK reneging was not observed")
	}
	_ = connection.Info()
}

func TestBBR3LossThresholdIsStrictlyAboveTwoPercent(t *testing.T) {
	bbr := newBBR3CongestionControl()
	if bbr.inflightTooHigh(1000, 51_200) {
		t.Fatal("exact fixed-point two-percent threshold was treated as excessive")
	}
	if !bbr.inflightTooHigh(1001, 51_200) {
		t.Fatal("loss above the fixed-point two-percent threshold was accepted")
	}
}

func TestBBR3ACKLossRateUsesTransmissionSnapshot(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeUp
	bbr.fullBandwidthReached = true
	bbr.probeSamples = true
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.lost = 5000
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 20_000, time.Millisecond)
	packet := bbr3PacketSnapshot{inflight: 20_000, lost: 3000}
	if transitioned := bbr.adaptUpperBounds(sample, packet, 20_000, 1000); transitioned {
		t.Fatal("loss response was reported as an independent state transition")
	}
	if bbr.inflightHigh == 0 || bbr.probeSamples || bbr.probePhase != bbr3ProbeDown {
		t.Fatalf("cumulative loss response = inflight_hi %d samples %t phase %s", bbr.inflightHigh, bbr.probeSamples, bbr.probePhase.String())
	}
}

func TestBBR3ACKWithoutDeliveryDoesNotInventProbeLoss(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	for _, hasSnapshot := range []bool{false, true} {
		bbr := newBBR3CongestionControl()
		bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
		bbr.fullBandwidthReached, bbr.probeSamples = true, true
		bbr.minimumRTT, bbr.minimumRTTStamp = 10*time.Millisecond, now
		bbr.bandwidthHigh[1], bbr.probeStarted = 1_000_000, now
		bbr.lost = 1000
		sample := tcpDeliveryRateSample{ackTime: now, priorInFlight: 20_000, inFlight: 20_000, smoothedRTT: 10 * time.Millisecond}
		if hasSnapshot {
			// A valid transmission can have tx.lost=0 even when its rate
			// interval is unusable. Its actual loss proof must still apply.
			sample.packetState = bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss)
		}
		_, _ = bbr.onRateSample(20_000, mss, &sample)
		if hasSnapshot {
			if bbr.probeSamples || bbr.probePhase != bbr3ProbeDown || bbr.inflightHigh == 0 {
				t.Fatalf("real transmission loss was ignored: %+v", bbr)
			}
		} else if !bbr.probeSamples || bbr.probePhase != bbr3ProbeUp || bbr.inflightHigh != 0 {
			t.Fatalf("ACK without a transmission snapshot invented probe loss: %+v", bbr)
		}
	}
}

func TestBBR3SACKDeliveryDoesNotUseStaleProbeSnapshot(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
	bbr.fullBandwidthReached, bbr.probeSamples = true, true
	bbr.minimumRTT, bbr.minimumRTTStamp = 10*time.Millisecond, now
	bbr.bandwidthHigh[1], bbr.probeStarted = 1_000_000, now
	bbr.inflightHigh = 10_000
	bbr.lost = 1000
	sample := tcpDeliveryRateSample{ackTime: now, priorInFlight: 20_000, inFlight: 20_000, smoothedRTT: 10 * time.Millisecond}
	sample.observe(sentTCPSegment{
		state:                 sentTCPSegmentTransmitted | sentTCPSegmentSACKed,
		congestionPacketState: bbr3EncodePacketState(&CongestionState{BytesInFlight: 18_000}, mss),
		hostQueue:             packetQueueTicket{queuedAt: 1},
		delivery:              tcpDeliverySnapshot{firstSent: 1, deliveredStamp: 1},
	})
	if sample.PacketLossEvidenceValid() {
		t.Fatal("SACK-selected transmission retained loss evidence")
	}
	_, _ = bbr.onRateSample(20_000, mss, &sample)
	if !bbr.probeSamples || bbr.probePhase != bbr3ProbeUp || bbr.inflightHigh != 19_000 {
		t.Fatalf("SACK-selected transmission feedback = samples %t phase %s inflight_hi %d, want no loss response and 19000 upper bound", bbr.probeSamples, bbr.probePhase.String(), bbr.inflightHigh)
	}
}

func TestTCPSACKPreservesCongestionTransmissionState(t *testing.T) {
	segment := sentTCPSegment{
		sequence: 100, end: 200,
		state:                 sentTCPSegmentInitialState(false, false, false, false),
		congestionPacketState: 0x1234,
	}
	outstanding, _, _, newInformation, _, newlySACKed := applyTCPSACK(
		[]sentTCPSegment{segment}, []TCPSACKBlock{{LeftEdge: 100, RightEdge: 200}}, time.Time{},
	)
	if !newInformation || len(outstanding) != 1 {
		t.Fatalf("SACK application = information %t ranges %d", newInformation, len(outstanding))
	}
	if !outstanding[0].state.has(sentTCPSegmentSACKed) {
		t.Fatal("SACKed range did not enter the scoreboard")
	}
	if outstanding[0].congestionPacketState != 0x1234 {
		t.Fatalf("SACKed congestion transmission state = %#x, want original", outstanding[0].congestionPacketState)
	}
	if len(newlySACKed) != 1 || newlySACKed[0].congestionPacketState != 0x1234 || !newlySACKed[0].state.has(sentTCPSegmentSACKed) {
		t.Fatalf("SACK delivery sample state = %#v, want original metadata and SACK mark", newlySACKed)
	}

	// A retransmission is a new generation and may install fresh controller
	// metadata without being confused with the SACKed transmission.
	outstanding[0].state.set(sentTCPSegmentSACKed, false)
	outstanding[0].advanceTransmissionGeneration()
	if !outstanding[0].state.has(sentTCPSegmentTransmitted) || !outstanding[0].state.has(sentTCPSegmentRetransmitted) || outstanding[0].congestionPacketState != 0x1234 {
		t.Fatalf("retransmission generation = state %#x metadata %#x", outstanding[0].state, outstanding[0].congestionPacketState)
	}
	outstanding[0].congestionPacketState = 0x5678
	if outstanding[0].congestionPacketState != 0x5678 {
		t.Fatal("retransmission did not accept fresh controller metadata")
	}
}

func TestBBR3LossRoundAdvancesIndependently(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.lossRoundDelivered = 100
	bbr.delivered = 200
	first := bbr3RateSample(time.Unix(100, 0), 100, 100, 1000, time.Millisecond)
	first.priorDelivered = 100
	bbr.updateLatestDeliverySignals(first, 100_000)
	if !bbr.lossRoundStart || bbr.lossRoundDelivered != 200 {
		t.Fatalf("first loss round = start %t boundary %d", bbr.lossRoundStart, bbr.lossRoundDelivered)
	}
	second := bbr3RateSample(time.Unix(100, 0), 50, 50, 1000, time.Millisecond)
	second.priorDelivered = 150
	bbr.updateLatestDeliverySignals(second, 50_000)
	if bbr.lossRoundStart {
		t.Fatal("an ACK inside the current loss round started another round")
	}
}

func TestBBR3TailLossProbeACKIsSampleScoped(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.lossRoundStart = true
	bbr.latestBandwidth = 900_000
	bbr.latestInflight = 9000
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 10_000, time.Millisecond)
	sample.tailLossProbeACK = true
	bbr.advanceLatestDeliverySignals(sample, 500_000)
	if bbr.latestBandwidth != 900_000 || bbr.latestInflight != 9000 {
		t.Fatalf("TLP ACK discarded prior delivery signals: %v/%d", bbr.latestBandwidth, bbr.latestInflight)
	}
	sample.tailLossProbeACK = false
	bbr.advanceLatestDeliverySignals(sample, 500_000)
	if bbr.latestBandwidth != 500_000 || bbr.latestInflight != 1000 {
		t.Fatalf("TLP ACK state leaked into the next sample: %v/%d", bbr.latestBandwidth, bbr.latestInflight)
	}
}

func TestBBR3TailLossProbeRecoveryBoundsRiskyProbe(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeUp
	bbr.probeSamples = true
	bbr.latestInflight = 20_000
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.minimumRTT = 10 * time.Millisecond
	state := CongestionState{
		CongestionWindow: 20_000, MaximumSegmentSize: mss,
		DeliveredBytes: 100_000,
	}
	packetState := bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss)
	bbr.HandleCongestionEvent(&CongestionEvent{
		Type: CongestionEventTailLossProbeRecovered, Time: now, State: &state,
		PacketBytes: mss, PacketState: packetState,
	})
	if bbr.lossRoundDelivered != 100_000 {
		t.Fatalf("TLP loss-round boundary = %d, want 100000", bbr.lossRoundDelivered)
	}
	if bbr.inflightHigh == 0 || bbr.probeSamples || bbr.probePhase != bbr3ProbeDown {
		t.Fatalf("TLP probe response = inflight_hi %d samples %t phase %s", bbr.inflightHigh, bbr.probeSamples, bbr.probePhase.String())
	}
}

func TestTCPBBR3ObservesAmbiguousTailLossProbeACK(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.190")
	remote := netip.MustParseAddr("192.0.2.191")
	recorder := &bbr3TailProbeRecorder{algorithm: newBBR3CongestionControl()}
	name := nextCongestionAPITestName()
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: name,
		New:  func(CongestionControlContext) CongestionController { return recorder },
		Features: CongestionControlFeatureDeliveryRate |
			CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureCustomPacing |
			CongestionControlFeatureCustomRecovery |
			CongestionControlFeatureLossEvents,
		SendBufferMultiplier: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = RegisterCongestionControl(factory); err != nil {
		t.Fatal(err)
	}
	link, stack := newTestStack(t, local, remote)
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		MTU:            1400,
		TCP:            TCPSocketDefaults{CongestionControl: name},
	}); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8389))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte("warmup"))
	link.mu.Lock()
	link.holdTCPACKs = 2
	link.dropTCPOrdinals = map[int]bool{3: true}
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, make([]byte, 2000))
	if !recorder.seen.Load() {
		link.mu.Lock()
		retransmitted := link.tailRetransmission
		link.mu.Unlock()
		info := connection.(*TCPConn).Info()
		t.Fatalf("BBRv3 did not observe the ACK matching a retransmitted tail-loss probe: algorithm=%q RTT=%v ACKs=%d recovery=%d retransmitted=%t probes=%d retransmissions=%d", info.CongestionControl, info.RTT, recorder.acks.Load(), recorder.recovery.Load(), retransmitted, stack.Stats().TCPTailLossProbes, info.Retransmissions)
	}
}

func TestBBR3WindowBoundsFollowMode(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	bbr.inflightHigh = 10_000
	bbr.mode = bbrDrain
	if got := bbr.boundWindow(20_000, mss); got != 20_000 {
		t.Fatalf("Drain was capped by inflight_hi: %d", got)
	}
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeDown
	if got := bbr.boundWindow(20_000, mss); got != 10_000 {
		t.Fatalf("ProbeDOWN inflight_hi cap = %d", got)
	}
	bbr.probePhase = bbr3ProbeCruise
	if got := bbr.boundWindow(20_000, mss); got != 8516 {
		t.Fatalf("Cruise headroom cap = %d, want 8516", got)
	}
}

func TestBBR3ProbeLossDoesNotReduceLowerBounds(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeRefill
	bbr.bandwidthLow = 1_000_000
	bbr.inflightLow = 20_000
	bbr.latestBandwidth = 700_000
	bbr.latestInflight = 14_000
	bbr.lossInRound = true
	bbr.lossRoundStart = true
	bbr.updateCongestionSignals(bbr3RateSample(time.Unix(100, 0), 1000, 1000, 10_000, time.Millisecond), 1_000_000, 20_000)
	if bbr.bandwidthLow != 1_000_000 || bbr.inflightLow != 20_000 {
		t.Fatalf("probe loss reduced lower bounds to %v/%d", bbr.bandwidthLow, bbr.inflightLow)
	}
}

func TestBBR3StartupLossExitRequiresRecoveryRound(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.latestInflight = 20_000
	bbr.lossRoundStart = true
	bbr.lossEventsInRound = bbr3FullLossEvents
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 20_000, time.Millisecond)
	sample.losses = 1000
	bbr.lost = 1000
	packet := bbr3PacketSnapshot{inflight: 20_000}
	bbr.checkStartupLoss(sample, packet, mss)
	if bbr.fullBandwidthReached {
		t.Fatal("Startup exited on loss outside fast recovery")
	}
	bbr.lossEventsInRound = bbr3FullLossEvents
	sample.fastRecovery = true
	bbr.checkStartupLoss(sample, packet, mss)
	if !bbr.fullBandwidthReached || bbr.inflightHigh == 0 {
		t.Fatal("lossy Startup recovery round did not bound inflight")
	}
}

func TestBBR3ProbeRTTUsesIndependentFiveSecondWindow(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeCruise
	bbr.fullBandwidthReached = true
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.minimumRTTStamp = start
	bbr.probeRTTMinimum = 10 * time.Millisecond
	bbr.probeRTTStamp = start
	sample := bbr3RateSample(start.Add(bbr3ProbeRTTWindow+time.Millisecond), 1000, 1000, 20_000, time.Millisecond)
	window := bbr.updateMinimumRTT(20_000, sample, mss)
	if bbr.mode != bbrProbeRTT || window != 20_000 || !bbr.requestAppLimited {
		t.Fatalf("ProbeRTT entry = mode %v window %d app-limited %t", bbr.mode, window, bbr.requestAppLimited)
	}
	bbr.probeDone = sample.ackTime.Add(-time.Millisecond)
	bbr.probeRound = true
	bbr.priorWindow = 20_000
	bbr.roundStart = true
	window = bbr.updateMinimumRTT(4000, sample, mss)
	if window != 20_000 || bbr.mode != bbrProbeBandwidth || bbr.probePhase != bbr3ProbeCruise {
		t.Fatalf("ProbeRTT exit = window %d mode %v phase %s", window, bbr.mode, bbr.probePhase.String())
	}
}

func TestBBR3RecoveryUndoOnlyWidensBounds(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.bandwidthLow = 800_000
	bbr.inflightLow = 16_000
	bbr.inflightHigh = 20_000
	bbr.saveWindow(24_000)
	bbr.bandwidthLow = 500_000
	bbr.inflightLow = 10_000
	bbr.inflightHigh = 12_000
	bbr.undoRecovery()
	if bbr.bandwidthLow != 800_000 || bbr.inflightLow != 16_000 || bbr.inflightHigh != 20_000 {
		t.Fatalf("undo bounds = %v/%d/%d", bbr.bandwidthLow, bbr.inflightLow, bbr.inflightHigh)
	}
}

func TestTCPBBR3TransfersAndRecoversLoss(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.188")
	remote := netip.MustParseAddr("192.0.2.189")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.sackTCP = true
	link.delayTCPACK = 100 * time.Microsecond
	link.dropTCPOrdinals = map[int]bool{3: true, 7: true}
	link.mu.Unlock()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR3},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8388))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	writeAndReadTCPEcho(t, connection, make([]byte, 128*1024))
	info := connection.(*TCPConn).Info()
	if info.CongestionControl != CongestionControlBBR3 || info.DeliveryRate == 0 || info.PacingRate == 0 || info.CongestionWindow >= tcpMaximumScaledWindow {
		t.Fatalf("BBRv3 connection info = %+v", info)
	}
	if stack.Stats().TCPSACKRetransmissions < 2 {
		t.Fatalf("BBRv3 SACK retransmissions = %d", stack.Stats().TCPSACKRetransmissions)
	}
}

func TestTCPBBR3ImpairmentMatrix(t *testing.T) {
	tests := []struct {
		name      string
		condition testLinkCondition
	}{
		{name: "high-delay-jitter", condition: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond}},
		{name: "random-loss", condition: testLinkCondition{Latency: 2 * time.Millisecond, LossRate: 0.08}},
		{name: "burst-loss", condition: testLinkCondition{Latency: 2 * time.Millisecond, BurstEnterRate: 0.04, BurstExitRate: 0.35}},
		{name: "delay-and-loss", condition: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond, LossRate: 0.08, BurstEnterRate: 0.02, BurstExitRate: 0.4}},
		{name: "narrow-queue", condition: testLinkCondition{Latency: 3 * time.Millisecond, Bandwidth: 256 * 1024, QueueBytes: 16 * 1024}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server, _ := newTestTCPConnectionPair(t, CongestionControlBBR3, testLinkConditions{
				Seed: 9917, ClientToPeer: test.condition, PeerToClient: test.condition,
			})
			transferTestTCPPayload(t, client, server, 96*1024, 20*time.Second)
			if info := client.Info(); info.CongestionWindow == 0 || info.CongestionWindow >= tcpMaximumScaledWindow {
				t.Fatalf("BBRv3 impaired connection info = %+v", info)
			}
		})
	}
}

func TestTCPBBR3IPv6FullDuplexUnderAsymmetricImpairment(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::301")
	serverAddress := netip.MustParseAddr("2001:db8::302")
	client, server, link := newTestTCPConnectionPairForAddresses(t, CongestionControlBBR3, testLinkConditions{
		Seed: 4811,
		ClientToPeer: testLinkCondition{
			Latency: 30 * time.Millisecond, Jitter: 8 * time.Millisecond, LossRate: 0.06,
			BurstEnterRate: 0.01, BurstExitRate: 0.5, Bandwidth: 1024 * 1024, QueueBytes: 48 * 1024,
		},
		PeerToClient: testLinkCondition{
			Latency: 5 * time.Millisecond, Jitter: 2 * time.Millisecond, LossRate: 0.04,
			DuplicateRate: 0.03, Bandwidth: 2 * 1024 * 1024, QueueBytes: 64 * 1024,
		},
	}, clientAddress, serverAddress)
	results := make(chan error, 2)
	go func() { results <- exchangeTestTCPPayload(client, server, 128*1024, 20*time.Second, 0x33333333) }()
	go func() { results <- exchangeTestTCPPayload(server, client, 128*1024, 20*time.Second, 0x44444444) }()
	for direction := 0; direction < 2; direction++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	clientStats, serverStats := link.Stats(0), link.Stats(1)
	if clientStats.RandomDrops == 0 || serverStats.RandomDrops == 0 {
		t.Fatalf("BBRv3 IPv6 impairment was not exercised: client=%+v server=%+v", clientStats, serverStats)
	}
}
