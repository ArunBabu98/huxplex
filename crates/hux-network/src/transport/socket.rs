//! Datagram-level fault injection and observation.
//!
//! A [`DatagramFilter`] sees every datagram an endpoint sends and decides whether it is
//! delivered. Production endpoints have none. Tests use one to impose packet loss and partitions
//! (**G5-T4**) and to measure the handshake's first flight on the wire (**G5-T6**) — the same
//! job `netem` does for a kernel socket, done in-process so the gate tests run anywhere.

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

/// Decides the fate of each outgoing datagram.
pub trait DatagramFilter: Send + Sync + fmt::Debug + 'static {
    /// `true` delivers `datagram` from `from` to `to`; `false` drops it silently, as a lossy
    /// network would.
    fn deliver(&self, from: SocketAddr, to: SocketAddr, datagram: &[u8]) -> bool;
}

/// A UDP socket whose sends pass through a [`DatagramFilter`].
#[derive(Debug)]
pub(crate) struct FilteredSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    filter: Arc<dyn DatagramFilter>,
    local: SocketAddr,
}

impl FilteredSocket {
    pub(crate) fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        filter: Arc<dyn DatagramFilter>,
    ) -> io::Result<Self> {
        let local = inner.local_addr()?;
        Ok(FilteredSocket {
            inner,
            filter,
            local,
        })
    }
}

impl AsyncUdpSocket for FilteredSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self
            .filter
            .deliver(self.local, transmit.destination, transmit.contents)
        {
            self.inner.try_send(transmit)
        } else {
            Ok(())
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// One datagram per send, so a filter decides per datagram rather than per GSO batch.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
