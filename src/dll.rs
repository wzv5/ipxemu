extern crate alloc;

use crate::{
    ipxemu::IPXEmu,
    logger::init_dbg_logger,
    mutex::Mutex,
    sockaddr::SockAddrRef,
    util::{mem_copy, mem_copy_as_u8, mem_equal, mem_set, wsa_error},
};
use alloc::{borrow::ToOwned, vec};
use core::mem;
use lazy_static::lazy_static;
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NO_DATA, HINSTANCE,
            SetLastError,
        },
        Networking::WinSock::{
            AF_INET, AF_IPX, INVALID_SOCKET, IPX_ADDRESS, IPX_ADDRESS_DATA, IPX_MAX_ADAPTER_NUM,
            NSPROTO_IPX, PROTOCOL_INFOA, SOCK_DGRAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IPX, SOCKET,
            SOCKET_ERROR, WINSOCK_SOCKET_TYPE, WSAEAFNOSUPPORT, WSAEFAULT, WSAENOPROTOOPT, bind,
            getsockname, getsockopt, recvfrom, sendto, setsockopt, socket,
        },
        System::SystemServices::DLL_PROCESS_ATTACH,
    },
    core::{PCSTR, PSTR},
};

unsafe extern "C" {
    unsafe fn LoadSysDll(instance: HINSTANCE);
}

lazy_static! {
    static ref IPXEMU: Mutex<IPXEmu> = Mutex::new(IPXEmu::new());
}

#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(instance: HINSTANCE, reason: u32, _: usize) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        init_dbg_logger();
        log::info!("已加载");
        unsafe { LoadSysDll(instance) };
    }
    true
}

fn ensure_bind(s: SOCKET) -> i32 {
    IPXEMU.lock().ensure_bind(s)
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_bind(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    let mut ipx = IPXEMU.lock();
    if ipx.find_socket(s).is_some() {
        let addr = unsafe { SockAddrRef::new(name, namelen) };
        if addr.is_none() {
            return wsa_error(WSAEFAULT);
        }
        let addr = addr.unwrap();
        log::info!("my_bind({}, {})", s, addr);
        if !addr.is_ipx() {
            return wsa_error(WSAEAFNOSUPPORT);
        }
        return ipx.bind(s, addr.as_sockaddr_ipx().unwrap());
    }
    unsafe { bind(s, name, namelen) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_closesocket(s: SOCKET) -> i32 {
    log::info!("my_closesocket({})", s);
    IPXEMU.lock().close_socket(s)
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_getsockname(s: SOCKET, name: *mut SOCKADDR, namelen: *mut i32) -> i32 {
    let r = ensure_bind(s);
    if r != 0 {
        return r;
    }
    let ipx = IPXEMU.lock();
    if let Some(info) = ipx.find_socket(s) {
        unsafe {
            if name.is_null() || *namelen < mem::size_of::<SOCKADDR_IPX>() as _ {
                return wsa_error(WSAEFAULT);
            }
            info.get_ipx_address()
                .unwrap()
                .clone_into(&mut *(name as *mut SOCKADDR_IPX));
            *namelen = mem::size_of::<SOCKADDR_IPX>() as _;
        }
    }
    unsafe { getsockname(s, name, namelen) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_getsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: PSTR,
    optlen: *mut i32,
) -> i32 {
    if level == NSPROTO_IPX as _ {
        let ipx = IPXEMU.lock();
        if ipx.find_socket(s).is_some() {
            return match optname {
                IPX_MAX_ADAPTER_NUM => {
                    unsafe { *(optval as *mut u32) = ipx.get_adapter_info().len() as _ };
                    0
                }
                IPX_ADDRESS => {
                    if optval.is_null()
                        || optlen.is_null()
                        || unsafe { *optlen } < mem::size_of::<IPX_ADDRESS_DATA>() as _
                    {
                        return wsa_error(WSAEFAULT);
                    }
                    let opt = unsafe { &mut *(optval as *mut IPX_ADDRESS_DATA) };
                    if opt.adapternum < 0 || opt.adapternum > ipx.get_adapter_info().len() as _ {
                        return wsa_error(ERROR_NO_DATA as _);
                    }
                    let adapter = &ipx.get_adapter_info()[opt.adapternum as usize];
                    unsafe {
                        mem_copy_as_u8(&opt.adapternum, opt.netnum.as_mut_ptr(), 4);
                        mem_copy(adapter.mac.as_ptr(), opt.nodenum.as_mut_ptr(), 6);
                    }
                    opt.wan = false;
                    opt.status = true;
                    opt.maxpkt = 1467;
                    opt.linkspeed = 10_000_000;
                    0
                }
                _ => {
                    return wsa_error(WSAENOPROTOOPT);
                }
            };
        }
    }
    unsafe { getsockopt(s, level, optname, optval, optlen) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_recvfrom(
    s: SOCKET,
    buf: PSTR,
    len: i32,
    flags: i32,
    from: *mut SOCKADDR,
    fromlen: *mut i32,
) -> i32 {
    let r = ensure_bind(s);
    if r != 0 {
        return r;
    }
    if let Some(info) = IPXEMU.lock().find_socket(s) {
        if from.is_null()
            || fromlen.is_null()
            || unsafe { *fromlen } < mem::size_of::<SOCKADDR_IPX>() as _
        {
            return wsa_error(WSAEFAULT);
        }
        let mut addr = SOCKADDR_IN::default();
        let mut addrlen = mem::size_of::<SOCKADDR_IN>() as i32;
        let r = unsafe { recvfrom(s, buf, len, flags, mem::transmute(&mut addr), &mut addrlen) };
        if r == SOCKET_ERROR {
            return r;
        }
        unsafe { mem_set(from as *mut u8, 0, *fromlen as _) };
        let fromlen = unsafe { &mut *fromlen };
        *fromlen = mem::size_of::<SOCKADDR_IPX>() as _;
        let from = unsafe { &mut *(from as *mut SOCKADDR_IPX) };
        let mut self_addr = SOCKADDR_IN::default();
        let mut self_addrlen = mem::size_of::<SOCKADDR_IN>() as i32;
        if unsafe { getsockname(s, mem::transmute(&mut self_addr), &mut self_addrlen) }
            == SOCKET_ERROR
        {
            return SOCKET_ERROR;
        }
        if unsafe { mem_equal(&addr, &self_addr, 1) } {
            unsafe { mem_copy(info.get_ipx_address().unwrap(), from, 1) };
        } else {
            from.sa_family = AF_IPX as _;
            from.sa_socket = addr.sin_port;
            unsafe { mem_copy_as_u8(&addr.sin_addr, from.sa_nodenum.as_mut_ptr(), 4) };
        }
        return r;
    }
    unsafe { recvfrom(s, buf, len, flags, from, fromlen) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_sendto(
    s: SOCKET,
    buf: PCSTR,
    len: i32,
    flags: i32,
    to: *const SOCKADDR,
    tolen: i32,
) -> i32 {
    let r = ensure_bind(s);
    if r != 0 {
        return r;
    }
    if IPXEMU.lock().find_socket(s).is_some() {
        let to = unsafe { SockAddrRef::new(to, tolen) };
        if to.is_none() {
            return wsa_error(WSAEFAULT);
        }
        let to = to.unwrap();
        if !to.is_ipx() {
            return wsa_error(WSAEAFNOSUPPORT);
        }
        let to = to.as_sockaddr_ipx().unwrap();
        let mut addr = SOCKADDR_IN::default();
        addr.sin_family = AF_INET;
        addr.sin_port = to.sa_socket;
        unsafe {
            mem_copy_as_u8(to.sa_nodenum.as_ptr(), &mut addr.sin_addr, 4);
            return sendto(
                s,
                buf,
                len,
                flags,
                mem::transmute(&addr),
                mem::size_of::<SOCKADDR_IN>() as _,
            );
        }
    }
    unsafe { sendto(s, buf, len, flags, to, tolen) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_setsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: PCSTR,
    optlen: i32,
) -> i32 {
    if level == NSPROTO_IPX as _ && IPXEMU.lock().find_socket(s).is_some() {
        return 0;
    }
    unsafe { setsockopt(s, level, optname, optval, optlen) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_socket(af: i32, typ: WINSOCK_SOCKET_TYPE, protocol: i32) -> SOCKET {
    if af == AF_IPX as _ && typ == SOCK_DGRAM && protocol == NSPROTO_IPX as _ {
        let mut ipx = IPXEMU.lock();
        if ipx.get_adapter_info().is_empty() {
            wsa_error(WSAEAFNOSUPPORT);
            return INVALID_SOCKET;
        }
        return ipx.create_socket();
    }
    unsafe { socket(af, typ, protocol) }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn my_EnumProtocolsA(
    lpiprotocols: *const i32,
    lpprotocolbuffer: *mut core::ffi::c_void,
    lpdwbufferlength: *mut u32,
) -> i32 {
    if lpdwbufferlength.is_null() {
        return -1;
    }
    let ipx = IPXEMU.lock();
    let info = ipx.get_protocol_info();
    let result = if lpiprotocols.is_null() {
        info.get(None)
    } else {
        let mut protocols = vec![];
        let mut p = lpiprotocols;
        unsafe {
            while *p != 0 {
                protocols.push(*p);
                p = p.add(1);
            }
        }
        info.get(Some(&protocols))
    };
    if result.is_empty() {
        return 0;
    }
    let minlen = mem::size_of::<PROTOCOL_INFOA>() * result.len();
    unsafe {
        if *lpdwbufferlength < minlen as _ {
            *lpdwbufferlength = minlen as _;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return -1;
        }
    }
    if lpprotocolbuffer.is_null() {
        unsafe { SetLastError(ERROR_INVALID_PARAMETER) };
        return -1;
    }
    unsafe { mem_copy(result.as_ptr(), lpprotocolbuffer as _, result.len()) };
    result.len() as _
}
