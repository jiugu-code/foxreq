//! Cross-platform plain TCP transport for native HTTP/1.1.

use std::{
    io::{ErrorKind, Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use crate::transport::{
    ConnectTarget, Connector, Scheme, TransportError, TransportErrorKind, TransportStream,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector;

impl TcpConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Connector for TcpConnector {
    type Stream = TcpTransport;

    fn connect(
        &mut self,
        target: &ConnectTarget,
        timeout: Duration,
    ) -> Result<Self::Stream, TransportError> {
        if target.scheme != Scheme::Http {
            return Err(TransportError::new(
                TransportErrorKind::Unsupported,
                "plain TCP transport supports HTTP only",
            ));
        }
        if timeout.is_zero() {
            return Err(timeout_error("TCP connection timed out"));
        }

        let started = Instant::now();
        let addresses = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|_| io_error("DNS resolution failed"))?;
        let mut saw_address = false;
        let mut last_error = None;
        for address in addresses {
            saw_address = true;
            let remaining = timeout
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| timeout_error("TCP connection timed out"))?;
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => {
                    stream
                        .set_nodelay(true)
                        .map_err(|_| io_error("TCP socket configuration failed"))?;
                    return Ok(TcpTransport {
                        stream: Some(stream),
                    });
                }
                Err(error) => last_error = Some(error.kind()),
            }
        }
        if !saw_address {
            return Err(io_error("DNS resolution returned no addresses"));
        }
        match last_error {
            Some(ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                Err(timeout_error("TCP connection timed out"))
            }
            Some(_) | None => Err(io_error("TCP connection failed")),
        }
    }
}

#[derive(Debug)]
pub struct TcpTransport {
    stream: Option<TcpStream>,
}

impl TcpTransport {
    fn stream(&mut self) -> Result<&mut TcpStream, TransportError> {
        self.stream.as_mut().ok_or_else(|| {
            TransportError::new(TransportErrorKind::State, "TCP transport is closed")
        })
    }
}

impl TransportStream for TcpTransport {
    fn read(&mut self, destination: &mut [u8], timeout: Duration) -> Result<usize, TransportError> {
        if timeout.is_zero() {
            return Err(timeout_error("TCP read timed out"));
        }
        let stream = self.stream()?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| io_error("TCP read timeout configuration failed"))?;
        stream
            .read(destination)
            .map_err(|error| match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => timeout_error("TCP read timed out"),
                _ => io_error("TCP read failed"),
            })
    }

    fn write(&mut self, source: &[u8], timeout: Duration) -> Result<usize, TransportError> {
        if timeout.is_zero() {
            return Err(timeout_error("TCP write timed out"));
        }
        let stream = self.stream()?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| io_error("TCP write timeout configuration failed"))?;
        stream.write(source).map_err(|error| match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => timeout_error("TCP write timed out"),
            _ => io_error("TCP write failed"),
        })
    }

    fn close(&mut self, _timeout: Duration) -> Result<(), TransportError> {
        let Some(stream) = self.stream.take() else {
            return Ok(());
        };
        match stream.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
            Err(_) => Err(io_error("TCP shutdown failed")),
        }
    }
}

fn io_error(message: &'static str) -> TransportError {
    TransportError::new(TransportErrorKind::Io, message)
}

fn timeout_error(message: &'static str) -> TransportError {
    TransportError::new(TransportErrorKind::Timeout, message)
}
