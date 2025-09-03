extern crate alloc;

use alloc::{
    alloc::{GlobalAlloc, Layout},
    string::String,
};
use windows_strings::HSTRING;
use windows_sys::Win32::{
    System::{
        Memory::{GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree, HeapReAlloc},
        Threading::ExitProcess,
    },
    UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW},
};

struct WindowsAlloc;

#[global_allocator]
static WINDOWS_ALLOC: WindowsAlloc = WindowsAlloc;

unsafe impl GlobalAlloc for WindowsAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { HeapAlloc(GetProcessHeap(), 0, layout.size()).cast() }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { HeapFree(GetProcessHeap(), 0, ptr.cast()) };
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size()).cast() }
    }
    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { HeapReAlloc(GetProcessHeap(), 0, ptr.cast(), new_size).cast() }
    }
}

#[cfg_attr(not(test), panic_handler)]
fn _panic(info: &core::panic::PanicInfo<'_>) -> ! {
    panic_msgbox(info);
    unsafe { ExitProcess(128) }
}

fn panic_msgbox(info: &core::panic::PanicInfo<'_>) {
    let loc = info
        .location()
        .map(|loc| alloc::format!("{}({})", loc.file(), loc.line()))
        .unwrap_or(String::from("<unknown>"));
    let s = alloc::format!("panic at {}: {}", loc, info.message());
    msgbox(&s);
}

fn msgbox(s: &str) {
    let hs = HSTRING::from(s);
    unsafe {
        MessageBoxW(
            core::ptr::null_mut(),
            hs.as_ptr(),
            windows_strings::w!("panic!").as_ptr(),
            MB_ICONERROR | MB_OK,
        );
    }
}
