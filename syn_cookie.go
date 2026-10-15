package mipstack

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

const (
	// synCookiePeriod is short enough to limit replay while allowing normal
	// retransmission delays. The current and immediately previous period are
	// accepted.
	synCookiePeriod = 64 * time.Second
	// synCookieDataBits reserves low sequence-number bits for reconstructible peer
	// options. The remaining 24 bits authenticate the tuple, client ISN, time
	// period, and all negotiated option flags.
	synCookieDataBits = 8
	// synCookieDataMask extracts the reconstructible option bits.
	synCookieDataMask = uint32(1<<synCookieDataBits - 1)
)

// synCookieMSSValues are safe lower bounds for common advertised MSS values.
// Selecting the greatest entry no larger than the peer's offer never causes a
// reconstructed connection to transmit oversized segments.
var synCookieMSSValues = [...]uint16{tcpMinimumPeerMSS, 256, 536, 1200, 1220, 1360, 1440, 8960}

// synCookieOptions is the handshake state that can be reconstructed from a
// final ACK without retaining the original SYN.
type synCookieOptions struct {
	mss              int
	windowScale      uint8
	localWindowScale uint8
	windowScaling    bool
	sack             bool
	timestamp        bool
	ecn              bool
	timestampNow     uint32
}

// synCookieKey returns the lazily initialized per-stack secret and current
// cookie period. A random source failure is retried on a later SYN instead of
// permanently disabling cookies. Listener-specific receive policy is retained
// by the listener, not by this shared passive dispatcher.
func (state *tcpPassiveState) synCookieKey(now time.Time) ([16]byte, uint64, error) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	if !state.cookieSet {
		if _, err := rand.Read(state.cookieKey[:]); err != nil {
			return [16]byte{}, 0, err
		}
		state.cookieEpoch = now
		state.cookieSet = true
	}
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	return state.cookieKey, period, nil
}

// noteSYNCookie records the Linux-style recent-overflow window in which a
// stateless final ACK is eligible for cookie validation.
func (state *tcpPassiveState) noteSYNCookie(period uint64) {
	state.cookieMu.Lock()
	if !state.cookieActive || period > state.cookiePeriod {
		state.cookiePeriod = period
	}
	state.cookieActive = true
	state.cookieMu.Unlock()
}

// recentSYNCookieState returns the secret and current validation period only
// after this passive state issued a recent cookie. The final ACK still obtains
// its receive scale from the listener that issued the matching SYN-cookie.
func (state *tcpPassiveState) recentSYNCookieState(now time.Time) ([16]byte, uint64, bool) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	if !state.cookieSet || !state.cookieActive || period < state.cookiePeriod || period-state.cookiePeriod > 1 {
		return [16]byte{}, 0, false
	}
	return state.cookieKey, period, true
}

// sendSYNCookie replies to a SYN without allocating a TCPConn.
func (state *tcpPassiveState) sendSYNCookie(stack *Stack, listener *TCPListener, key tcpKey, syn tcpSegment, now time.Time) error {
	defaults := stack.network.Load().tcpDefaults
	if listener != nil {
		defaults = applyTCPSocketOptions(defaults, listener.options)
	}
	configuredScale := tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer)
	secret, period, err := state.synCookieKey(now)
	if err != nil {
		return err
	}
	options, data := encodeSYNCookieOptions(syn, key.remote.Addr())
	authenticatedData := synCookieAuthenticatedData(data, options.timestamp, options.ecn)
	var generation uint64
	if listener != nil {
		generation = listener.cookieGeneration
	}
	sequence := synCookieSequence(secret, key, generation, syn.sequence, period, data, authenticatedData)
	localMSS := tcpMSSForMTU(stack.mtuFor(key.remote.Addr()), key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	// RFC 7323 requires TSval to use the sender's current timestamp clock. Keep
	// the cookie timestamp independent of the delayed input event time; ECN
	// parity encoding must not move it ahead of that clock.
	timestamp := stack.tcpTimestamp()
	if options.timestamp {
		timestamp = synCookieTimestamp(timestamp, options.ecn)
	}
	var optionStorage [40]byte
	advertisedScale := configuredScale
	if listener != nil {
		advertisedScale = listener.recordSYNCookieScale(period, configuredScale)
	}
	tcpOptions := tcpPassiveSYNOptions(optionStorage[:0], localMSS, options.sack, options.windowScaling, options.timestamp, advertisedScale, timestamp, options.timestampNow)
	flags := byte(TCPFlagSYN | TCPFlagACK)
	if options.ecn {
		flags |= TCPFlagECE
	}
	receiveWindow := defaults.ReceiveBuffer
	if receiveWindow > 65535 {
		receiveWindow = 65535
	}
	state.noteSYNCookie(period)
	flowLabelSet := listener != nil && listener.options.flowLabel.set
	return stack.tryWriteTCPControl(key.local.Addr(), key.remote.Addr(), key.local.Port(), key.remote.Port(), sequence, syn.sequence+1, flags, uint16(receiveWindow), tcpOptions, nil, stack.mtuFor(key.remote.Addr()), defaults.TrafficClass, 0, defaults.FlowLabel, flowLabelSet, outputFlowKey{})
}

// synCookieTimestamp encodes ECN in TSval's low bit without exceeding the
// current clock, as Linux does for option-packed cookie timestamps.
// RFC 7323 section 3.2 permits TSval zero. Timestamp negotiation is tracked
// separately from TSval here, so Linux's SYN-ACK zero-value sentinel is not
// needed; backward rounding also preserves parity across wraparound.
func synCookieTimestamp(raw uint32, ecn bool) uint32 {
	timestamp := raw &^ 1
	if ecn {
		timestamp |= 1
	}
	if tcpSequenceGreater(timestamp, raw) {
		timestamp -= 2
	}
	return timestamp
}

// validateSYNCookie authenticates a final ACK against the current or previous
// cookie period. attempted reports eligibility for authentication diagnostics.
func (state *tcpPassiveState) validateSYNCookie(key tcpKey, ack tcpSegment, now time.Time, listener *TCPListener) (uint32, synCookieOptions, bool, bool) {
	if ack.flags&TCPFlagACK == 0 || ack.flags&(TCPFlagSYN|TCPFlagRST) != 0 {
		return 0, synCookieOptions{}, false, false
	}
	secret, period, active := state.recentSYNCookieState(now)
	if !active {
		return 0, synCookieOptions{}, false, false
	}
	serverSequence := ack.acknowledgement - 1
	clientSequence := ack.sequence - 1
	data := serverSequence & synCookieDataMask
	timestampValue, timestampEcho, timestampPresent := parseTCPTimestamp(ack.optionBytes())
	// Linux accepts a final ACK whose negotiated Timestamp option was removed
	// in flight. Such an ACK cannot reveal whether the SYN-cookie was created
	// with timestamps or ECN, so authenticate the three possible states (TS with
	// ECN, TS without ECN, and no TS). A present zero TSecr is ambiguous: RFC
	// 7323 carries an unsigned 32-bit field, so zero cannot by itself prove
	// that the option was removed; try both ECN states and let the authenticated
	// cookie tag select the original negotiation.
	var candidates [3]struct{ timestamp, ecn bool }
	candidateCount := 1
	if timestampPresent {
		candidates[0] = struct{ timestamp, ecn bool }{timestamp: true, ecn: timestampEcho&1 != 0}
		if timestampEcho == 0 {
			candidates[0] = struct{ timestamp, ecn bool }{timestamp: true, ecn: true}
			candidates[1] = struct{ timestamp, ecn bool }{timestamp: true}
			candidateCount = 2
		}
	} else {
		candidates[0] = struct{ timestamp, ecn bool }{timestamp: true, ecn: true}
		candidates[1] = struct{ timestamp, ecn bool }{timestamp: true}
		candidates[2] = struct{ timestamp, ecn bool }{}
		candidateCount = len(candidates)
	}
	valid := false
	matchedTimestamp, matchedECN := false, false
	matchedPeriod := uint64(0)
	var generation uint64
	if listener != nil {
		generation = listener.cookieGeneration
	}
	for attempt := uint64(0); attempt < 2; attempt++ {
		if attempt > period {
			break
		}
		candidatePeriod := period - attempt
		for candidateIndex := 0; candidateIndex < candidateCount; candidateIndex++ {
			candidate := candidates[candidateIndex]
			authenticatedData := synCookieAuthenticatedData(data, candidate.timestamp, candidate.ecn)
			expected := synCookieSequence(secret, key, generation, clientSequence, candidatePeriod, data, authenticatedData)
			if subtle.ConstantTimeEq(int32(expected), int32(serverSequence)) == 1 {
				valid = true
				matchedTimestamp = candidate.timestamp
				matchedECN = candidate.ecn
				matchedPeriod = candidatePeriod
			}
		}
	}
	if !valid {
		return 0, synCookieOptions{}, false, true
	}
	options, ok := decodeSYNCookieOptions(data)
	if !ok {
		return 0, synCookieOptions{}, false, true
	}
	options.timestamp = timestampPresent && matchedTimestamp
	if options.timestamp {
		options.timestampNow = timestampValue
	}
	// RFC 7323 defines TSecr as an unsigned 32-bit value, but normal timestamp
	// negotiation still expects it to echo the SYN-ACK's TSval. Linux therefore
	// uses a conservative zero-echo fallback in its compact cookie decoder.
	// MIPStack's cookie tag authenticates the Timestamp/ECN negotiation bits
	// independently; it does not authenticate the TSval or TSecr values. A
	// zero echo can therefore retain only the option state proved by that tag.
	// This is deliberately more permissive than Linux for a zero-valued cookie
	// timestamp and remains limited to the stateless compatibility path.
	options.ecn = timestampPresent && matchedECN
	if listener != nil && options.windowScaling {
		localScale, ok := listener.lookupSYNCookieScale(matchedPeriod)
		if !ok {
			return 0, synCookieOptions{}, false, true
		}
		// The local scale is usable only when the peer's SYN offered Window
		// Scale and the SYN-cookie could therefore advertise it. The final
		// timestamp-less compatibility fallback below may still clear it.
		options.localWindowScale = localScale
	}
	if !timestampPresent {
		// Linux does not restore SACK or window scaling when
		// cookie_timestamp_decode sees no Timestamp in the final ACK. MSS remains
		// reconstructible from the authenticated cookie; Timestamp and ECN remain
		// disabled because the ACK did not prove that either option was negotiated.
		options.sack = false
		options.windowScaling = false
		options.windowScale = 0
		// Keep the local receive scale zero because this implementation suppresses
		// peer window scaling on a no-Timestamp cookie SYN-ACK; the final ACK cannot
		// prove a scale that was never advertised. A Timestamp-bearing ACK,
		// including one with TSecr zero, restores the listener scale recorded for
		// the SYN-cookie.
		options.localWindowScale = 0
	}
	return serverSequence, options, true, true
}

// encodeSYNCookieOptions converts a SYN's offered options into eight sequence
// bits. Timestamp and ECN flags are authenticated separately.
func encodeSYNCookieOptions(syn tcpSegment, remoteAddress netip.Addr) (synCookieOptions, uint32) {
	mss, scale, scaling, sack, timestamp, timestampValue := parseTCPOptions(syn.optionBytes(), defaultTCPPeerMSS(remoteAddress), 65535)
	if !timestamp {
		// RFC 7323 fixes the window scale during the SYN exchange, and RFC
		// 2018 requires SACK-Permitted to be negotiated by both SYNs. Linux
		// may advertise these options in a cookie SYN-ACK, then clear them
		// when a cookie ACK lacks Timestamp because its stateless recovery
		// carries them in the Timestamp echo. MIPStack suppresses them before
		// advertising instead, so the handshake never promises extensions
		// that the conservative recovery path will drop.
		scale, scaling, sack = 0, false, false
	}
	mssIndex := 0
	for index, value := range synCookieMSSValues {
		if int(value) > mss {
			break
		}
		mssIndex = index
	}
	encodedScale := uint32(15)
	if scaling {
		encodedScale = uint32(scale)
	}
	data := uint32(mssIndex) | encodedScale<<3
	if sack {
		data |= 1 << 7
	}
	// The server timestamp echo carries ECN state for the final ACK. Without
	// timestamps, cookie mode conservatively declines ECN rather than spending
	// sequence bits that would weaken the authentication tag.
	ecn := timestamp && syn.flags&(TCPFlagECE|TCPFlagCWR) == TCPFlagECE|TCPFlagCWR
	return synCookieOptions{
		mss: int(synCookieMSSValues[mssIndex]), windowScale: scale, windowScaling: scaling,
		sack: sack, timestamp: timestamp, ecn: ecn, timestampNow: timestampValue,
	}, data
}

// decodeSYNCookieOptions reconstructs peer options from authenticated data.
func decodeSYNCookieOptions(data uint32) (synCookieOptions, bool) {
	if data & ^synCookieDataMask != 0 {
		return synCookieOptions{}, false
	}
	mssIndex := int(data & 7)
	encodedScale := uint8(data >> 3 & 15)
	options := synCookieOptions{
		mss: int(synCookieMSSValues[mssIndex]), sack: data&(1<<7) != 0,
	}
	if encodedScale != 15 {
		options.windowScaling = true
		options.windowScale = encodedScale
	}
	return options, true
}

// synCookieAuthenticatedData adds option flags recovered from the ACK's
// timestamp to the compact sequence data. They consume no sequence bits but
// remain covered by the keyed tag.
func synCookieAuthenticatedData(data uint32, timestamp, ecn bool) uint32 {
	if timestamp {
		data |= 1 << 8
	}
	if ecn {
		data |= 1 << 9
	}
	return data
}

// synCookiePeriodNumber returns the monotonically advancing cookie period.
func synCookiePeriodNumber(now, epoch time.Time) uint64 {
	elapsed := now.Sub(epoch)
	if elapsed <= 0 {
		return 0
	}
	return uint64(elapsed / synCookiePeriod)
}

// synCookieSequence authenticates one tuple, listener incarnation, and its
// compact option data. The incarnation is not sent on the wire; it prevents a
// cookie issued before listener replacement from being accepted by the new
// listener while the passive cookie secret remains shared.
func synCookieSequence(secret [16]byte, key tcpKey, generation uint64, clientSequence uint32, period uint64, data, authenticatedData uint32) uint32 {
	var input [59]byte
	if key.local.Addr().Is6() {
		input[0] = 6
	} else {
		input[0] = 4
	}
	local := key.local.Addr().As16()
	remote := key.remote.Addr().As16()
	copy(input[1:17], local[:])
	copy(input[17:33], remote[:])
	binary.BigEndian.PutUint16(input[33:35], key.local.Port())
	binary.BigEndian.PutUint16(input[35:37], key.remote.Port())
	binary.BigEndian.PutUint64(input[37:45], generation)
	binary.BigEndian.PutUint32(input[45:49], clientSequence)
	binary.BigEndian.PutUint64(input[49:57], period)
	binary.BigEndian.PutUint16(input[57:59], uint16(authenticatedData))
	tag := uint32(sipHash24(secret, input[:])) &^ synCookieDataMask
	return tag | data
}

// runPassiveCookie owns a server-side connection reconstructed from a final
// cookie ACK.
func (c *TCPConn) runPassiveCookie(listener *TCPListener, finalACK tcpSegment, initialSequence uint32) {
	queued := false
	defer func() {
		if !queued {
			listener.removePending(c)
		}
	}()
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if len(finalACK.payload) != 0 || finalACK.flags&TCPFlagFIN != 0 {
		c.inbound.prepend(finalACK)
	}
	if !listener.enqueue(c) {
		_ = c.sendAbortReset(initialSequence+1, c.receiveNext, 0)
		c.finish(net.ErrClosed)
		return
	}
	queued = true
	c.finish(c.established(initialSequence+1, protocolTimer, tcpInitialReceive{}))
}
