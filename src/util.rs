extern crate alloc;

use windows_strings::HSTRING;
use windows_sys::Win32::Networking::WinSock::{SOCKET_ERROR, WSASetLastError};

pub use core::ptr::copy_nonoverlapping as mem_copy;
pub use core::ptr::write_bytes as mem_set;

pub unsafe fn mem_copy_as_u8<T1: ?Sized, T2: ?Sized>(src: *const T1, dst: *mut T2, count: usize) {
    unsafe { mem_copy(src as *const u8, dst as *mut u8, count) };
}

pub unsafe fn mem_equal_as_u8<T1: ?Sized, T2: ?Sized>(
    src: *const T1,
    dst: *const T2,
    count: usize,
) -> bool {
    let src = unsafe { core::slice::from_raw_parts(src as *const u8, count) };
    let dst = unsafe { core::slice::from_raw_parts(dst as *const u8, count) };
    return src == dst;
}

pub unsafe fn mem_equal<T>(src: *const T, dst: *const T, count: usize) -> bool {
    unsafe { mem_equal_as_u8(src, dst, count * core::mem::size_of::<T>()) }
}

pub unsafe fn u16_to_hstring(s: *const u16) -> HSTRING {
    unsafe { windows_strings::PCWSTR::from_raw(s).to_hstring() }
}

pub fn wsa_error(err: i32) -> i32 {
    unsafe { WSASetLastError(err) };
    return SOCKET_ERROR;
}
