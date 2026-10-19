//! A macOS utun interface: the desktop stand-in for an iOS packet tunnel.
//!
//! Closing the descriptor destroys the interface and every route through
//! it, so a crash restores the Mac's network on its own.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub struct Utun {
    fd: OwnedFd,
    pub name: String,
}

impl Utun {
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain socket(2); the result is checked before use.
        let raw =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: ctl_info is plain data; zeroed is a valid value.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let control = b"com.apple.net.utun_control";
        for (dst, src) in info.ctl_name.iter_mut().zip(control) {
            *dst = *src as libc::c_char;
        }
        // SAFETY: CTLIOCGINFO fills `info` in place.
        if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0, // let the kernel pick utunN
            sc_reserved: [0; 5],
        };
        // SAFETY: `addr` is a valid sockaddr_ctl of the stated length.
        let rc = unsafe {
            libc::connect(
                raw,
                (&addr as *const libc::sockaddr_ctl).cast(),
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut name = [0 as libc::c_char; 32];
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `name`.
        let rc = unsafe {
            libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel NUL-terminates the interface name.
        let name = unsafe { CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        Ok(Self { fd, name })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Reads one packet, without the 4-byte address-family header.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: reads into `buf` within its length.
        let n = unsafe { libc::read(self.raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Ok(0);
        }
        buf.copy_within(4..n, 0);
        Ok(n - 4)
    }

    /// Writes one IP packet, prefixing the address-family header.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let family = match packet.first().map(|b| b >> 4) {
            Some(4) => libc::AF_INET,
            Some(6) => libc::AF_INET6,
            _ => return Ok(()),
        };
        let header = (family as u32).to_be_bytes();
        let iov = [
            libc::iovec {
                iov_base: header.as_ptr() as *mut _,
                iov_len: header.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut _,
                iov_len: packet.len(),
            },
        ];
        // SAFETY: both iovecs point at live buffers of the stated lengths.
        let n = unsafe { libc::writev(self.raw_fd(), iov.as_ptr(), 2) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
