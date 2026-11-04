// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! The relay media channel: DTLS over the relay's UDP flow, SCTP inside it, and the pre-negotiated id=0 stream that
//! carries STUN/RTP/RTCP as binary messages. Sans-IO: JavaScript moves the UDP datagrams and supplies the clock.
//! The protocol stack (`RelayStack`) is wacore-voip's relay transport from whatsapp-rust, minus the Tokio driver.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use rtc_datachannel::data_channel::DataChannel;
use rtc_datachannel::message::message_channel_open::ChannelType;
use rtc_dtls::config::ConfigBuilder as DtlsConfigBuilder;
use rtc_dtls::crypto::Certificate;
use rtc_dtls::endpoint::{Endpoint as DtlsEndpoint, EndpointEvent as DtlsEndpointEvent};
use rtc_shared::TransportProtocol;
use rtc_sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint as SctpEndpoint,
    EndpointConfig, Event as SctpEvent, Payload, PayloadProtocolIdentifier, StreamEvent, StreamId,
    TransportConfig,
};
use wasm_bindgen::prelude::*;

macro_rules! debug {
    ($($t:tt)*) => {{}};
}

/// Largest message the relay association reassembles.
const RELAY_SCTP_MAX_MESSAGE: u32 = 65_536;

/// DataChannel label WA Web uses (pre-negotiated, id=0).
const DATA_CHANNEL_LABEL: &str = "pre-negotiated";
/// SCTP-over-DTLS WebRTC port.
const SCTP_PORT: u16 = 5000;
/// The pre-negotiated DataChannel's stream id. Both ends open it directly, because a pre-negotiated
/// channel carries no DCEP handshake -- which is why WA Web uses one.
const MEDIA_STREAM_ID: StreamId = 0;

/// The shape WA Web opens the media channel with (`ordered=false, maxRetransmits=0`), and the shape
/// this transport has to keep. Real-time RTP must NOT ride a reliable, ordered SCTP stream: a single
/// reordered or lost packet head-of-line-blocks every later one (the receiver holds them until the
/// gap is retransmitted, then delivers a burst), which the peer hears as choppy or garbled audio,
/// worst on links that reorder at all. Reliability is per-sender, which is why an ordered outbound
/// stream sounded choppy to the peer while inbound stayed clean.
const MEDIA_CHANNEL_TYPE: ChannelType = ChannelType::PartialReliableRexmitUnordered;
/// The retransmit count [`MEDIA_CHANNEL_TYPE`] carries: never retransmit, abandon instead.
const MEDIA_MAX_RETRANSMITS: u32 = 0;


/// Why the media stack stopped. The driver branches on the variant: a peer close ends the call the
/// way hanging up does, anything else is a transport failure the call surfaces as a read error.
#[derive(Debug, thiserror::Error)]
enum StackError {
    /// The relay sent `close_notify` or a fatal alert, or tore its association down.
    #[error("relay closed the media channel: {0}")]
    PeerClosed(String),
    /// The stack cannot continue: a handshake that failed or ran out of retransmissions, a socket
    /// error, or a protocol layer that refused what we asked of it.
    #[error("{0}")]
    Failed(String),
}


/// The sans-IO relay media stack: DTLS over the relay's UDP flow, an SCTP association inside it,
/// and the pre-negotiated id=0 stream that carries STUN/RTP/RTCP.
///
/// Every entry point takes the current `Instant` and every output is polled, so this type never
/// touches a socket, a clock or a task. That is what makes the retransmission timers of both DTLS
/// and SCTP the driver's business rather than a library thread's, and what would let the whole
/// stack move to the runtime-agnostic core later.
struct RelayStack {
    remote: SocketAddr,
    dtls: DtlsEndpoint,
    sctp: SctpEndpoint,
    /// Set on the dialling end. The client drives both handshakes -- DTLS first, then the SCTP
    /// association inside it; the accepting end has both handed to it.
    initiator: bool,
    /// `None` until the association exists. SCTP only ever runs inside the secure channel.
    assoc: Option<(AssociationHandle, Association)>,
    /// Set once the media stream is open, which is what `Connected` means to the caller.
    open: bool,
    /// Reassembled inbound messages, drained by the driver into relay events.
    inbound: VecDeque<Bytes>,
    /// Set once the stack has stopped, so later input is ignored rather than re-reported.
    stopped: bool,
}

impl RelayStack {
    /// Build the dialling half and queue the DTLS ClientHello. Nothing reaches the wire until the
    /// driver polls [`Self::poll_transmit`].
    fn connect(local: SocketAddr, remote: SocketAddr, now: Instant) -> Result<Self> {
        let config = dtls_config(true, Some(remote))?;
        let mut dtls = DtlsEndpoint::new(local, TransportProtocol::UDP, None);
        dtls.connect(now, remote, Arc::new(config), None)
            .map_err(|e| anyhow!("dtls connect: {e}"))?;
        // The dialling end initiates the association too, so its SCTP endpoint needs no server
        // config: nothing will ever arrive on it that this side did not ask for.
        let sctp = SctpEndpoint::new(
            local,
            TransportProtocol::UDP,
            Arc::new(EndpointConfig::new()),
            None,
        );
        Ok(Self::new(remote, dtls, sctp, true))
    }

    /// The accepting half, which the loopback relay in this module's tests runs. Only the roles
    /// differ: from the first datagram on it is the same state machine, driven by the same loop.

    fn new(remote: SocketAddr, dtls: DtlsEndpoint, sctp: SctpEndpoint, initiator: bool) -> Self {
        Self {
            remote,
            dtls,
            sctp,
            initiator,
            assoc: None,
            open: false,
            inbound: VecDeque::new(),
            stopped: false,
        }
    }

    /// Whether the media channel is open for traffic.
    fn is_open(&self) -> bool {
        self.open
    }

    /// Feed one datagram off the relay socket.
    fn handle_datagram(&mut self, now: Instant, data: &[u8]) -> Result<(), StackError> {
        if self.stopped {
            return Ok(());
        }
        let events = match self.dtls.read(now, self.remote, None, BytesMut::from(data)) {
            Ok(events) => events,
            // A close_notify or fatal alert ends the call. Anything else is one unusable datagram:
            // the socket is connected to the relay, so a record that fails to parse or authenticate
            // means corruption on the path, and dropping it is what a datagram protocol is supposed
            // to do. The exception is the handshake, where the only datagrams that arrive are the
            // ones it needs, so a failure there is the handshake failing and there is nothing to
            // wait for.
            Err(rtc_shared::error::Error::ErrAlertFatalOrClose) => {
                self.stopped = true;
                return Err(StackError::PeerClosed("alert".to_owned()));
            }
            Err(e) if self.assoc.is_none() => {
                self.stopped = true;
                return Err(StackError::Failed(format!("dtls handshake: {e}")));
            }
            Err(e) => {
                debug!("voip: dropping unusable relay datagram: {e}");
                return Ok(());
            }
        };

        for event in events {
            match event {
                DtlsEndpointEvent::HandshakeComplete if self.initiator => {
                    self.start_association(now)?;
                }
                DtlsEndpointEvent::ApplicationData(sctp_packet) => {
                    self.feed_association(now, sctp_packet.freeze());
                }
                // The event set is non-exhaustive by design, and a variant this transport has never
                // heard of carries nothing it could act on.
                _ => {}
            }
        }
        self.pump(now)
    }

    /// Queue one media message. Fails only if the channel is not (or no longer) open.
    fn write_media(&mut self, now: Instant, data: &Bytes) -> Result<(), StackError> {
        if !self.open {
            return Err(StackError::Failed("media channel is not open".to_owned()));
        }
        let Some((_, assoc)) = self.assoc.as_mut() else {
            return Err(StackError::Failed("no sctp association".to_owned()));
        };
        // SCTP cannot carry a zero-length message, so an empty one travels under its own payload
        // protocol id. The engine never sends one, but the rule belongs with the framing.
        let ppi = if data.is_empty() {
            PayloadProtocolIdentifier::BinaryEmpty
        } else {
            PayloadProtocolIdentifier::Binary
        };
        assoc
            .stream(MEDIA_STREAM_ID)
            .and_then(|mut s| s.write_chunk_with_ppi(data, ppi))
            .map_err(|e| StackError::Failed(format!("media write: {e}")))?;
        self.pump(now)
    }

    /// Start the SCTP association. The dialling end does this once, when DTLS reports complete.
    fn start_association(&mut self, now: Instant) -> Result<(), StackError> {
        let (handle, assoc) = self
            .sctp
            .connect(now, ClientConfig::new(sctp_transport_config()), self.remote)
            .map_err(|e| StackError::Failed(format!("sctp connect: {e}")))?;
        self.assoc = Some((handle, assoc));
        Ok(())
    }

    /// Route one decrypted SCTP packet into the association, creating it on the accepting end.
    fn feed_association(&mut self, now: Instant, packet: Bytes) {
        let Self {
            sctp,
            assoc,
            remote,
            ..
        } = self;
        match sctp.handle(now, *remote, None, packet) {
            Some((ch, DatagramEvent::AssociationEvent(event))) => {
                // Application data before the association exists cannot be ours; nothing else
                // shares this DTLS channel.
                if let Some((handle, association)) = assoc.as_mut()
                    && ch == *handle
                {
                    association.handle_event(event);
                }
            }
            // Only an endpoint carrying a server config produces this, so on the dialling end the
            // arm never fires; it is what makes the accepting end the same type.
            Some((ch, DatagramEvent::NewAssociation(association))) if assoc.is_none() => {
                *assoc = Some((ch, association));
            }
            _ => {}
        }
    }

    /// Drain everything the association produced since the last call: state changes, endpoint
    /// bookkeeping, inbound messages, and the packets it wants encrypted and sent.
    fn pump(&mut self, now: Instant) -> Result<(), StackError> {
        let Self {
            remote,
            dtls,
            sctp,
            assoc,
            open,
            inbound,
            stopped,
            ..
        } = self;
        let Some((handle, association)) = assoc.as_mut() else {
            return Ok(());
        };

        let mut connected = false;
        let mut readable = false;
        let mut ended = None;
        while let Some(event) = association.poll() {
            match event {
                SctpEvent::Connected => connected = true,
                SctpEvent::Stream(StreamEvent::Readable { id }) if id == MEDIA_STREAM_ID => {
                    readable = true;
                }
                // The association going away after the channel opened is the relay hanging up; a
                // handshake that never finished is a failure to connect.
                SctpEvent::AssociationLost { reason, .. } => {
                    ended = Some(StackError::PeerClosed(reason.to_string()));
                }
                SctpEvent::HandshakeFailed { reason } => {
                    ended = Some(StackError::Failed(format!("sctp handshake: {reason}")));
                }
                _ => {}
            }
        }

        if connected {
            open_media_stream(association)?;
            *open = true;
        }
        if readable && *open {
            drain_media_stream(association, inbound);
        }

        while let Some(event) = association.poll_endpoint_event() {
            sctp.handle_event(*handle, event);
        }
        // Every SCTP packet becomes one DTLS application-data record, and the driver turns each of
        // those into one datagram.
        while let Some(transmit) = association.poll_transmit(now) {
            if let Payload::RawEncode(packets) = transmit.message {
                for packet in packets {
                    dtls.write(now, *remote, &packet)
                        .map_err(|e| StackError::Failed(format!("dtls write: {e}")))?;
                }
            }
        }

        if let Some(e) = ended {
            *stopped = true;
            *open = false;
            return Err(e);
        }
        Ok(())
    }

    /// The next datagram to put on the wire, if any.
    fn poll_transmit(&mut self) -> Option<BytesMut> {
        self.dtls.poll_transmit().map(|t| t.message)
    }

    /// The next reassembled inbound message, if any.
    fn poll_inbound(&mut self) -> Option<Bytes> {
        self.inbound.pop_front()
    }

    /// When [`Self::handle_timeout`] next needs calling. DTLS handshake retransmission and SCTP's
    /// retransmission, ack and heartbeat timers both live here, so the driver arms one timer for
    /// the pair instead of racing two.
    fn poll_timeout(&self) -> Option<Instant> {
        let dtls = self.dtls.poll_timeout(&self.remote);
        let sctp = self.assoc.as_ref().and_then(|(_, a)| a.poll_timeout());
        match (dtls, sctp) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// Advance both state machines to `now`, firing whichever timers are due.
    fn handle_timeout(&mut self, now: Instant) -> Result<(), StackError> {
        if self.stopped {
            return Ok(());
        }
        // A DTLS timeout error means the handshake ran out of retransmissions, which nothing later
        // recovers from.
        if let Err(e) = self.dtls.handle_timeout(self.remote, now) {
            self.stopped = true;
            return Err(StackError::Failed(format!("dtls handshake timeout: {e}")));
        }
        if let Some((_, assoc)) = self.assoc.as_mut() {
            assoc.handle_timeout(now);
        }
        self.pump(now)
    }

    /// Reset the media stream the way a peer closing its DataChannel does, leaving the association
    /// itself up. Test-only, because production hangs up by tearing the whole channel down -- but
    /// the relay does exactly this at the end of a call, which is what the old stack saw as a read
    /// of `Ok(0)`.

    /// Tear the channel down politely: SHUTDOWN the association, then `close_notify` the DTLS
    /// channel. One flush, without waiting for the relay's SHUTDOWN-ACK -- the relay drops the flow
    /// on its own consent-freshness timer, and a teardown that waits on a peer that may already be
    /// gone is a teardown that hangs.
    fn close(&mut self, now: Instant) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.open = false;
        if let Some((_, assoc)) = self.assoc.as_mut() {
            let _ = assoc.shutdown();
        }
        let _ = self.pump(now);
        let _ = self.dtls.close(now);
    }
}

/// The clock the media stack runs on.
///
/// `std::time::Instant` rather than the portable `wacore::time::Instant`, because that is the type
/// the protocol crates take and hand back for their retransmission deadlines, and the type
/// `tokio::time::sleep_until` needs to arm a timer on one. Native-only either way: this module
/// already refuses to build where a Tokio UDP socket does not exist.
#[allow(clippy::disallowed_methods)]
fn now() -> Instant {
    Instant::now()
}

/// The DTLS configuration both ends of the relay flow use.
///
/// The relay does not validate our client certificate, and we do not validate its: the SDP
/// fingerprint is fixed and cosmetic at this layer, and media authentication is hop-by-hop SRTP
/// keyed from callKey, not from this handshake.
fn dtls_config(
    is_client: bool,
    remote: Option<SocketAddr>,
) -> Result<rtc_dtls::config::HandshakeConfig> {
    let provider = rtc_dtls::crypto_provider::default_provider()
        .map_err(|e| anyhow!("dtls crypto provider: {e}"))?;
    let cert = Certificate::generate_self_signed(vec!["wa-voip".to_owned()], provider.crypto())
        .map_err(|e| anyhow!("dtls self-signed cert: {e}"))?;
    DtlsConfigBuilder::default()
        .with_crypto_provider(provider)
        .with_certificates(vec![cert])
        // Deliberately not verified (as WhatsApp Web and the reference client do): signalling hands out no relay
        // certificate or fingerprint to check against, and this layer protects nothing the media depends on. Audio and
        // video are end-to-end encrypted with SRTP keys derived from the call key, and the relay's STUN
        // MESSAGE-INTEGRITY key comes over the authenticated signalling connection. A relay impersonator could drop
        // the call but not read or alter its media. If a stable relay fingerprint is ever captured, pin it here.
        .with_insecure_skip_verify(true)
        // Only the SNI/cert-hostname, irrelevant under insecure_skip_verify; set to silence the
        // library's empty-server-name warn.
        .with_server_name("localhost".to_owned())
        .build(is_client, remote)
        .map_err(|e| anyhow!("dtls config: {e}"))
}

/// The SCTP parameters of a relay association. Everything else is the crate's default, which is
/// already what the relay expects (MTU 1191, a 1 MiB advertised receive window).
fn sctp_transport_config() -> TransportConfig {
    TransportConfig::default()
        .with_sctp_port(SCTP_PORT)
        .with_max_message_size(RELAY_SCTP_MAX_MESSAGE)
}

/// Open the pre-negotiated id=0 media stream with the reliability [`MEDIA_CHANNEL_TYPE`] implies.
///
/// The reliability is applied here, to the SCTP stream, rather than by the DataChannel layer: for a
/// `negotiated` channel that layer only emits a `DATA_CHANNEL_OPEN` flagged as one the transport
/// must apply locally and must not send to the peer, and this driver is that transport. What the
/// library owns is the mapping from the W3C channel type to SCTP's ordered flag and reliability
/// type, which is where the RFC 8832 rule belongs -- so the pair cannot drift from the channel type
/// the way two hand-written arguments could.
fn open_media_stream(assoc: &mut Association) -> Result<(), StackError> {
    let (unordered, reliability) = DataChannel::get_reliability_params(MEDIA_CHANNEL_TYPE);
    let mut stream = assoc
        .open_stream(MEDIA_STREAM_ID, PayloadProtocolIdentifier::Binary)
        .map_err(|e| StackError::Failed(format!("open sctp media stream: {e}")))?;
    stream
        .set_reliability_params(unordered, reliability, MEDIA_MAX_RETRANSMITS)
        .map_err(|e| StackError::Failed(format!("media reliability: {e}")))?;
    debug!("voip: media channel '{DATA_CHANNEL_LABEL}' open on stream {MEDIA_STREAM_ID}");
    Ok(())
}

/// Move every reassembled message off the media stream into `inbound`.
fn drain_media_stream(assoc: &mut Association, inbound: &mut VecDeque<Bytes>) {
    let Ok(mut stream) = assoc.stream(MEDIA_STREAM_ID) else {
        return;
    };
    while let Ok(Some(chunks)) = stream.read() {
        // A pre-negotiated channel exchanges no DCEP, so anything but user data on this stream is
        // not addressed to us.
        if !matches!(
            chunks.ppi,
            PayloadProtocolIdentifier::Binary | PayloadProtocolIdentifier::String
        ) {
            continue;
        }
        // Cannot exceed the cap: it is the one the association reassembled under.
        if let Ok(payload) = chunks.to_payload(RELAY_SCTP_MAX_MESSAGE as usize) {
            inbound.push_back(payload.freeze());
        }
    }
}


/// A clock origin for `Instant`. `std::time::Instant::now()` is not available on `wasm32-unknown-unknown`, but the
/// protocol crates want `Instant`s for their timers. There `Instant` is a plain `Duration` since an arbitrary origin,
/// so one can be built from a millisecond count; the layout is checked once so a toolchain that changes it fails
/// loudly instead of misbehaving.
fn instant_origin() -> Result<Instant> {
    if std::mem::size_of::<Instant>() != std::mem::size_of::<Duration>() {
        return Err(anyhow!("unsupported Instant layout"));
    }
    // SAFETY: on this target `Instant` is a newtype over `Duration` (size checked above), and the arithmetic test
    // below proves the value behaves like one.
    let origin: Instant = unsafe { std::mem::transmute::<Duration, Instant>(Duration::from_secs(1)) };
    if origin + Duration::from_millis(5) - origin != Duration::from_millis(5) {
        return Err(anyhow!("unsupported Instant layout"));
    }
    Ok(origin)
}

/// The JavaScript-facing relay channel.
#[wasm_bindgen]
pub struct RelayChannel {
    stack: RelayStack,
    origin: Instant,
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen]
impl RelayChannel {
    /// Dial the relay at `ip:port`. Nothing is sent until `pollTransmit` is drained.
    #[wasm_bindgen(constructor)]
    pub fn new(ip: &str, port: u16) -> Result<RelayChannel, JsValue> {
        let remote: SocketAddr = format!("{ip}:{port}").parse().map_err(js_err)?;
        let local: SocketAddr = "0.0.0.0:0".parse().map_err(js_err)?;
        let origin = instant_origin().map_err(js_err)?;
        let stack = RelayStack::connect(local, remote, origin).map_err(js_err)?;
        Ok(RelayChannel { stack, origin })
    }

    fn at(&self, now_ms: f64) -> Instant {
        self.origin + Duration::from_micros((now_ms * 1000.0) as u64)
    }

    /// Feed a datagram from the relay. Returns an error text when the channel ended or failed.
    #[wasm_bindgen(js_name = handleDatagram)]
    pub fn handle_datagram(&mut self, now_ms: f64, data: &[u8]) -> Option<String> {
        self.stack
            .handle_datagram(self.at(now_ms), data)
            .err()
            .map(|e| e.to_string())
    }

    /// Queue one media message (STUN/RTP/RTCP bytes from the call engine).
    pub fn write(&mut self, now_ms: f64, data: &[u8]) -> Option<String> {
        self.stack
            .write_media(self.at(now_ms), &Bytes::copy_from_slice(data))
            .err()
            .map(|e| e.to_string())
    }

    /// The next datagram to send to the relay, if any.
    #[wasm_bindgen(js_name = pollTransmit)]
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.stack.poll_transmit().map(|b| b.to_vec())
    }

    /// The next media message from the relay, if any.
    #[wasm_bindgen(js_name = pollInbound)]
    pub fn poll_inbound(&mut self) -> Option<Vec<u8>> {
        self.stack.poll_inbound().map(|b| b.to_vec())
    }

    /// Milliseconds (on the caller's clock) when `handleTimeout` is due, or -1.
    #[wasm_bindgen(js_name = pollTimeout)]
    pub fn poll_timeout(&self) -> f64 {
        match self.stack.poll_timeout() {
            Some(t) => t.saturating_duration_since(self.origin).as_micros() as f64 / 1000.0,
            None => -1.0,
        }
    }

    #[wasm_bindgen(js_name = handleTimeout)]
    pub fn handle_timeout(&mut self, now_ms: f64) -> Option<String> {
        self.stack
            .handle_timeout(self.at(now_ms))
            .err()
            .map(|e| e.to_string())
    }

    #[wasm_bindgen(js_name = isOpen)]
    pub fn is_open(&self) -> bool {
        self.stack.is_open()
    }

    pub fn close(&mut self, now_ms: f64) {
        self.stack.close(self.at(now_ms));
    }
}
