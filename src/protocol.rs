extern crate alloc;

use alloc::{vec, vec::Vec};
use core::ptr;

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
    Networking::WinSock::{
        AF_IPX, EnumProtocolsA, NSPROTO_IPX, PROTOCOL_INFOA, SOCK_DGRAM, XP_CONNECTIONLESS,
        XP_FRAGMENTATION, XP_MESSAGE_ORIENTED, XP_SUPPORTS_BROADCAST, XP_SUPPORTS_MULTICAST,
    },
};

pub struct ProtocolInfo {
    p: Vec<PROTOCOL_INFOA>,
}

impl ProtocolInfo {
    pub fn new() -> Self {
        let mut result = Self { p: Vec::new() };
        result.p.clear();
        let mut buflen = 0u32;
        let mut n = unsafe { EnumProtocolsA(ptr::null(), ptr::null_mut(), &mut buflen) };
        if n < 0 && unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER {
            let mut buf = vec![0u8; buflen as _];
            n = unsafe { EnumProtocolsA(ptr::null(), buf.as_mut_ptr().cast(), &mut buflen) };
            if n < 0 {
                return result;
            }
            for i in 0..n as usize {
                let p = unsafe { &*(buf.as_ptr() as *const PROTOCOL_INFOA).add(i) };
                // 不使用系统的 IPX 协议
                if p.iProtocol == NSPROTO_IPX as _ {
                    continue;
                }
                result.p.push(p.clone());
            }
        }
        result.p.push(PROTOCOL_INFOA {
            dwServiceFlags: XP_CONNECTIONLESS
                | XP_MESSAGE_ORIENTED
                | XP_SUPPORTS_BROADCAST
                | XP_SUPPORTS_MULTICAST
                | XP_FRAGMENTATION,
            iAddressFamily: AF_IPX as _,
            iMaxSockAddr: 16,
            iMinSockAddr: 14,
            iSocketType: SOCK_DGRAM,
            iProtocol: NSPROTO_IPX as _,
            dwMessageSize: 576,
            lpProtocol: "IPX" as *const _ as _,
        });
        result
    }

    pub fn get(&self, protocols: Option<&[i32]>) -> Vec<PROTOCOL_INFOA> {
        if protocols.is_none() || protocols.is_some_and(|p| p.is_empty()) {
            return self.p.clone();
        }
        let protocols = protocols.unwrap();
        self.p
            .iter()
            .filter(|p| protocols.contains(&p.iProtocol))
            .cloned()
            .collect()
    }
}

unsafe impl Send for ProtocolInfo {}
unsafe impl Sync for ProtocolInfo {}
