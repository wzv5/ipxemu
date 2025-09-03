extern crate alloc;

use alloc::{format, vec, vec::Vec};
use core::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr},
    ptr,
};
use windows_strings::HSTRING;
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
    NetworkManagement::{
        IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH},
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::AF_INET,
};

use crate::{MacAddr, sockaddr::SockAddrRef, util::u16_to_hstring};

pub struct AdapterInfo {
    pub name: HSTRING,
    pub description: HSTRING,
    pub mac: MacAddr,
    pub ip: Vec<Ipv4Addr>,
}

impl Debug for AdapterInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {:?} {} ({})",
            self.mac
                .iter()
                .map(|i| format!("{i:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
            self.ip,
            self.name,
            self.description,
        )
    }
}

pub fn get_adapter_info() -> Vec<AdapterInfo> {
    let mut result = vec![];
    let mut len = 15_000_u32;
    let mut buf = vec![0u8; len as _];
    let mut r = unsafe {
        GetAdaptersAddresses(
            AF_INET as _,
            0,
            ptr::null(),
            buf.as_mut_ptr() as _,
            &mut len,
        )
    };
    if r == ERROR_BUFFER_OVERFLOW {
        buf.resize(len as _, 0);
        r = unsafe {
            GetAdaptersAddresses(
                AF_INET as _,
                0,
                ptr::null(),
                buf.as_mut_ptr() as _,
                &mut len,
            )
        };
    }
    if r != ERROR_SUCCESS {
        return result;
    }
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        let a = unsafe { &*p };
        if a.OperStatus == IfOperStatusUp && a.PhysicalAddressLength == 6 {
            let ip = get_ipv4(a.FirstUnicastAddress);
            if !ip.is_empty() {
                result.push(AdapterInfo {
                    name: unsafe { u16_to_hstring(a.FriendlyName) },
                    description: unsafe { u16_to_hstring(a.Description) },
                    mac: a.PhysicalAddress[0..6].try_into().unwrap(),
                    ip,
                });
            }
        }
        p = a.Next;
    }
    result
}

fn get_ipv4(mut p: *const IP_ADAPTER_UNICAST_ADDRESS_LH) -> Vec<Ipv4Addr> {
    let mut result = vec![];
    while !p.is_null() {
        let i = unsafe { &*p };
        let addr = unsafe { SockAddrRef::from_socket_address(&i.Address) };
        if let Some(ip) = addr.and_then(|addr| addr.to_std_ip()) {
            match ip {
                IpAddr::V4(ip) => result.push(ip),
                _ => {}
            };
        }
        p = i.Next;
    }
    result
}
