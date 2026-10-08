//! A libp2p `StreamMuxer` over a quinn connection.
//!
//! QUIC multiplexes natively, so this is an adapter, not a muxer: each libp2p substream is one
//! bidirectional QUIC stream. Structure follows `libp2p-quic`'s connection adapter (MIT), which
//! Huxplex cannot use directly because that crate builds its own TLS (N0 outcome 3).
//!
//! # Semantics the swarm relies on
//!
//! - **Cancellation.** Each pending `accept_bi` / `open_bi` / `closed` future is stored, owns a
//!   clone of the connection, and is dropped with the muxer; dropping one mid-poll loses nothing,
//!   because quinn hands a stream out only when the future completes.
//! - **After the end.** Once the connection has a close reason, [`StreamMuxer::poll`] and
//!   [`StreamMuxer::poll_close`] answer from it and never poll a finished future again — an
//!   `async` block polled after completion panics, and the swarm is free to poll twice.
//! - **Resets.** A reset or stopped stream surfaces as an `io::Error` from the substream's reads or
//!   writes (quinn's `futures-io` impls); it never closes the connection or other substreams.
//!   A dropped [`Substream`] finishes its send half and stops its receive half (quinn 0.11).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{
    FutureExt,
    future::BoxFuture,
    io::{AsyncRead, AsyncWrite},
};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent};
use quinn::{ConnectionError, RecvStream, SendStream};

type StreamFuture = BoxFuture<'static, Result<(SendStream, RecvStream), ConnectionError>>;

pub struct Muxer {
    connection: quinn::Connection,
    inbound: Option<StreamFuture>,
    outbound: Option<StreamFuture>,
    closed: Option<BoxFuture<'static, ConnectionError>>,
    closing: Option<BoxFuture<'static, ConnectionError>>,
}

impl Muxer {
    pub fn new(connection: quinn::Connection) -> Self {
        Muxer {
            connection,
            inbound: None,
            outbound: None,
            closed: None,
            closing: None,
        }
    }
}

impl StreamMuxer for Muxer {
    type Substream = Substream;
    type Error = ConnectionError;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let future = this.inbound.get_or_insert_with(|| {
            let connection = this.connection.clone();
            async move { connection.accept_bi().await }.boxed()
        });
        let result = ready!(future.poll_unpin(cx));
        this.inbound = None;
        Poll::Ready(result.map(|(send, recv)| Substream { send, recv }))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let future = this.outbound.get_or_insert_with(|| {
            let connection = this.connection.clone();
            async move { connection.open_bi().await }.boxed()
        });
        let result = ready!(future.poll_unpin(cx));
        this.outbound = None;
        Poll::Ready(result.map(|(send, recv)| Substream { send, recv }))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let future = this.closing.get_or_insert_with(|| {
            let connection = this.connection.clone();
            connection.close(0u32.into(), b"");
            async move { connection.closed().await }.boxed()
        });
        let reason = match this.connection.close_reason() {
            Some(reason) => reason,
            None => ready!(future.poll_unpin(cx)),
        };
        match reason {
            ConnectionError::LocallyClosed => Poll::Ready(Ok(())),
            error => Poll::Ready(Err(error)),
        }
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        // QUIC connection migration is not used, so the only event is the connection ending.
        let this = self.get_mut();
        if let Some(reason) = this.connection.close_reason() {
            return Poll::Ready(Err(reason));
        }
        let future = this.closed.get_or_insert_with(|| {
            let connection = this.connection.clone();
            async move { connection.closed().await }.boxed()
        });
        Poll::Ready(Err(ready!(future.poll_unpin(cx))))
    }
}

/// One bidirectional QUIC stream.
pub struct Substream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for Substream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for Substream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(Pin::new(&mut self.get_mut().send), cx)
    }
}
