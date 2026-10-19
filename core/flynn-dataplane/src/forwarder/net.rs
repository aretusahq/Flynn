//! Outbound sockets. Every socket passes through the host's protector
//! before it connects, so it leaves through the real network rather than
//! looping back into the tunnel.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};

use crate::SocketProtector;

fn new_socket(
    target: SocketAddr,
    ty: Type,
    protocol: Protocol,
    protector: &dyn SocketProtector,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(target), ty, Some(protocol))?;
    if !protector.protect(socket.as_raw_fd()) {
        return Err(io::Error::other("host refused to protect the socket"));
    }
    socket.set_nonblocking(true)?;
    // A write to a closed peer must not raise SIGPIPE in the host process.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    socket.set_nosigpipe(true)?;
    Ok(socket)
}

/// Starts a non-blocking connect. Completion shows as writability.
pub(crate) fn connect_tcp(
    target: SocketAddr,
    protector: &dyn SocketProtector,
) -> io::Result<mio::net::TcpStream> {
    let socket = new_socket(target, Type::STREAM, Protocol::TCP, protector)?;
    socket.set_tcp_nodelay(true)?;
    match socket.connect(&target.into()) {
        Ok(()) => {}
        Err(e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(mio::net::TcpStream::from_std(socket.into()))
}

/// A connected UDP socket for one flow.
pub(crate) fn connect_udp(
    target: SocketAddr,
    protector: &dyn SocketProtector,
) -> io::Result<mio::net::UdpSocket> {
    let socket = new_socket(target, Type::DGRAM, Protocol::UDP, protector)?;
    socket.connect(&target.into())?;
    Ok(mio::net::UdpSocket::from_std(socket.into()))
}
