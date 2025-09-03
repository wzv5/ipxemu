extern crate alloc;

use crate::util::mem_copy;
use alloc::borrow::ToOwned;
use core::{borrow::Borrow, fmt::Display, mem, ops::Deref, slice};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_IPX, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IPX, SOCKADDR_STORAGE,
    SOCKET_ADDRESS, htonl, htons,
};

#[derive(Clone)]
pub struct SockAddr {
    buf: [u8; mem::size_of::<SOCKADDR_STORAGE>()],
}

#[repr(transparent)]
pub struct SockAddrRef {
    buf: [u8],
}

impl SockAddrRef {
    pub unsafe fn new<'a>(addr: *const SOCKADDR, addrlen: i32) -> Option<&'a Self> {
        if addr.is_null() {
            return None;
        }
        match (unsafe { *(addr as *const u16) }, addrlen) {
            (AF_INET, addrlen) if addrlen >= mem::size_of::<SOCKADDR_IN>() as _ => {
                let buf = unsafe {
                    slice::from_raw_parts(addr as *const u8, mem::size_of::<SOCKADDR_IN>())
                };
                Some(unsafe { mem::transmute(buf) })
            }
            (AF_INET6, addrlen) if addrlen >= mem::size_of::<SOCKADDR_IN6>() as _ => {
                let buf = unsafe {
                    slice::from_raw_parts(addr as *const u8, mem::size_of::<SOCKADDR_IN6>())
                };
                Some(unsafe { mem::transmute(buf) })
            }
            (AF_IPX, addrlen) if addrlen >= mem::size_of::<SOCKADDR_IPX>() as _ => {
                let buf = unsafe {
                    slice::from_raw_parts(addr as *const u8, mem::size_of::<SOCKADDR_IPX>())
                };
                Some(unsafe { mem::transmute(buf) })
            }
            _ => None,
        }
    }

    pub unsafe fn from_socket_address<'a>(addr: *const SOCKET_ADDRESS) -> Option<&'a Self> {
        if addr.is_null() {
            return None;
        }
        unsafe {
            let addr = &*addr;
            Self::new(addr.lpSockaddr, addr.iSockaddrLength)
        }
    }

    pub unsafe fn from_sockaddr_unchecked<'a>(addr: *const SOCKADDR) -> Option<&'a Self> {
        unsafe { Self::new(addr, mem::size_of::<SOCKADDR_STORAGE>() as _) }
    }

    pub fn get_family(&self) -> u16 {
        unsafe { *(self.buf.as_ptr() as *const u16) }
    }

    pub fn is_ipv4(&self) -> bool {
        self.get_family() == AF_INET
    }

    pub fn is_ipv6(&self) -> bool {
        self.get_family() == AF_INET6
    }

    pub fn is_ipx(&self) -> bool {
        self.get_family() == AF_IPX
    }

    pub fn to_std(&self) -> Option<core::net::SocketAddr> {
        match self.get_family() {
            AF_INET => {
                let addr = unsafe { &*(self.buf.as_ptr() as *const SOCKADDR_IN) };
                let port = unsafe { htons(addr.sin_port) };
                let ip = unsafe { htonl(addr.sin_addr.S_un.S_addr) };
                Some(core::net::SocketAddr::new(
                    core::net::IpAddr::V4(core::net::Ipv4Addr::from_bits(ip)),
                    port,
                ))
            }
            AF_INET6 => {
                let addr = unsafe { &*(self.buf.as_ptr() as *const SOCKADDR_IN6) };
                let port = unsafe { htons(addr.sin6_port) };
                let ip: u128 = unsafe { mem::transmute(addr.sin6_addr) };
                Some(core::net::SocketAddr::new(
                    core::net::IpAddr::V6(core::net::Ipv6Addr::from_bits(ip)),
                    port,
                ))
            }
            _ => None,
        }
    }

    pub fn to_std_ip(&self) -> Option<core::net::IpAddr> {
        self.to_std().map(|addr| addr.ip())
    }

    pub fn as_sockaddr(&self) -> &SOCKADDR {
        unsafe { &*(self.buf.as_ptr() as *const SOCKADDR) }
    }

    pub fn as_sockaddr_in(&self) -> Option<&SOCKADDR_IN> {
        if self.is_ipv4() {
            Some(unsafe { &*(self.buf.as_ptr() as *const SOCKADDR_IN) })
        } else {
            None
        }
    }

    pub fn as_sockaddr_in6(&self) -> Option<&SOCKADDR_IN6> {
        if self.is_ipv4() {
            Some(unsafe { &*(self.buf.as_ptr() as *const SOCKADDR_IN6) })
        } else {
            None
        }
    }

    pub fn as_sockaddr_ipx(&self) -> Option<&SOCKADDR_IPX> {
        if self.is_ipx() {
            Some(unsafe { &*(self.buf.as_ptr() as *const SOCKADDR_IPX) })
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub unsafe fn clone_to_ptr(&self, p: *mut u8) {
        unsafe {
            mem_copy(self.buf.as_ptr(), p, self.len());
        }
    }
}

impl Display for SockAddrRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.get_family() {
            AF_INET | AF_INET6 => self.to_std().unwrap().fmt(f),
            AF_IPX => {
                let addr = self.as_sockaddr_ipx().unwrap();
                for i in addr.sa_netnum {
                    write!(f, "{:02X}", i)?;
                }
                write!(f, ".")?;
                for i in addr.sa_nodenum {
                    write!(f, "{:02X}", i)?;
                }
                write!(f, ":{}", unsafe { htons(addr.sa_socket) })
            }
            _ => unreachable!(),
        }
    }
}

impl AsRef<SockAddrRef> for SockAddr {
    fn as_ref(&self) -> &SockAddrRef {
        let len = match unsafe { *(self.buf.as_ptr() as *const u16) } {
            AF_INET => mem::size_of::<SOCKADDR_IN>(),
            AF_INET6 => mem::size_of::<SOCKADDR_IN6>(),
            AF_IPX => mem::size_of::<SOCKADDR_IPX>(),
            _ => unreachable!(),
        };
        unsafe { mem::transmute(&self.buf.as_slice()[0..len]) }
    }
}

impl Borrow<SockAddrRef> for SockAddr {
    fn borrow(&self) -> &SockAddrRef {
        self.as_ref()
    }
}

impl ToOwned for SockAddrRef {
    type Owned = SockAddr;

    fn to_owned(&self) -> Self::Owned {
        SockAddr {
            buf: self.buf.try_into().unwrap(),
        }
    }
}

impl Deref for SockAddr {
    type Target = SockAddrRef;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl SockAddr {
    pub fn new(family: u16) -> Option<Self> {
        if ![AF_INET, AF_INET6, AF_IPX].contains(&family) {
            return None;
        }
        let mut addr = Self {
            buf: [0u8; mem::size_of::<SOCKADDR_STORAGE>()],
        };
        let pfamily = unsafe { &mut *(addr.buf.as_mut_ptr() as *mut u16) };
        *pfamily = family;
        Some(addr)
    }

    pub unsafe fn view_as_mut<T>(&mut self) -> &T {
        unsafe { &*(self.buf.as_mut_ptr() as *mut T) }
    }
}
