extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::mem;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_IPX, INVALID_SOCKET, IPPROTO_UDP, SOCK_DGRAM, SOCKADDR_IN, SOCKADDR_IPX, SOCKET,
    WSAEADDRNOTAVAIL, WSAEFAULT, WSAEINVAL, bind, closesocket, getsockname, htonl, socket,
};

use crate::{
    MacAddr,
    adapter::{AdapterInfo, get_adapter_info},
    protocol::ProtocolInfo,
    sockaddr::SockAddrRef,
    util::wsa_error,
};

#[derive(Default)]
pub struct IPXSocketInfo {
    ipx_addr: Option<SOCKADDR_IPX>,
}

impl IPXSocketInfo {
    fn new() -> Self {
        Default::default()
    }

    pub fn get_ipx_address(&self) -> Option<&SOCKADDR_IPX> {
        self.ipx_addr.as_ref()
    }
}

unsafe impl Send for IPXSocketInfo {}
unsafe impl Sync for IPXSocketInfo {}

pub struct IPXEmu {
    protocol: ProtocolInfo,
    adapter: Vec<AdapterInfo>,
    socket: BTreeMap<SOCKET, IPXSocketInfo>,
}

impl IPXEmu {
    pub fn new() -> Self {
        let adapter = get_adapter_info();
        for (i, a) in adapter.iter().enumerate() {
            log::info!("[{i}] {a:?}");
        }
        Self {
            protocol: ProtocolInfo::new(),
            adapter,
            socket: BTreeMap::new(),
        }
    }

    pub fn get_protocol_info(&self) -> &ProtocolInfo {
        &self.protocol
    }

    pub fn get_adapter_info(&self) -> &[AdapterInfo] {
        &self.adapter
    }

    pub fn create_socket(&mut self) -> SOCKET {
        let s = unsafe { socket(AF_INET as _, SOCK_DGRAM, IPPROTO_UDP) };
        if s != INVALID_SOCKET {
            self.socket.insert(s, IPXSocketInfo::new());
        }
        s
    }

    pub fn close_socket(&mut self, s: SOCKET) -> i32 {
        self.socket.remove(&s);
        unsafe { closesocket(s) }
    }

    pub fn find_socket(&self, s: SOCKET) -> Option<&IPXSocketInfo> {
        self.socket.get(&s)
    }

    pub fn bind(&mut self, s: SOCKET, addr: &SOCKADDR_IPX) -> i32 {
        if let Some(info) = self.socket.get_mut(&s) {
            if info.ipx_addr.is_some() {
                return wsa_error(WSAEINVAL);
            }
            let idx = u32::from_le_bytes(unsafe { mem::transmute(addr.sa_netnum) });
            // 可能只是为了获取网卡信息，延迟绑定
            if idx == 0 && addr.sa_nodenum == [0, 0, 0, 0, 0, 0] && addr.sa_socket == 0 {
                log::info!("延迟绑定");
                return 0;
            }
            let adapter = self.adapter.get(idx as usize);
            if adapter.is_none() {
                return wsa_error(WSAEADDRNOTAVAIL);
            }
            let adapter = adapter.unwrap();
            let mac: &MacAddr = unsafe { mem::transmute(&addr.sa_nodenum) };
            if &adapter.mac != mac {
                return wsa_error(WSAEADDRNOTAVAIL);
            }
            let mut udp_addr = SOCKADDR_IN::default();
            udp_addr.sin_family = AF_INET;
            udp_addr.sin_port = addr.sa_socket;
            udp_addr.sin_addr.S_un.S_addr = unsafe { htonl(adapter.ip.first().unwrap().to_bits()) };
            let mut r = unsafe {
                bind(
                    s,
                    &udp_addr as *const _ as _,
                    mem::size_of::<SOCKADDR_IN>() as _,
                )
            };
            if r == 0 {
                let mut addr = addr.clone();
                if addr.sa_socket == 0 {
                    let mut udp_addr_len = mem::size_of::<SOCKADDR_IN>() as i32;
                    r = unsafe { getsockname(s, &mut udp_addr as *mut _ as _, &mut udp_addr_len) };
                    if r == 0 {
                        addr.sa_socket = udp_addr.sin_port;
                    }
                }
                info.ipx_addr = Some(addr);
                unsafe {
                    log::info!(
                        "bind {} => {}",
                        SockAddrRef::from_sockaddr_unchecked(&addr as *const _ as _).unwrap(),
                        SockAddrRef::from_sockaddr_unchecked(&udp_addr as *const _ as _).unwrap()
                    );
                }
            }
            return r;
        }
        return wsa_error(WSAEFAULT);
    }

    pub fn ensure_bind(&mut self, s: SOCKET) -> i32 {
        if let Some(info) = self.socket.get(&s)
            && info.get_ipx_address().is_none()
        {
            log::info!("触发延迟绑定");
            let mac = self.get_adapter_info()[0].mac.clone();
            return self.bind(
                s,
                &SOCKADDR_IPX {
                    sa_family: AF_IPX as _,
                    sa_netnum: [0, 0, 0, 0],
                    sa_nodenum: unsafe { mem::transmute(mac) },
                    sa_socket: 0,
                },
            );
        }
        0
    }
}
