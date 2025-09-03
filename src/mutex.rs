extern crate alloc;

use alloc::boxed::Box;
use core::{
    mem,
    ops::{Deref, DerefMut},
    pin::Pin,
};
use windows_sys::Win32::System::Threading::{
    CRITICAL_SECTION, DeleteCriticalSection, EnterCriticalSection, InitializeCriticalSection,
    LeaveCriticalSection, TryEnterCriticalSection,
};

pub struct RawMutex {
    cs: Pin<Box<CRITICAL_SECTION>>,
}

unsafe impl Sync for RawMutex {}
unsafe impl Send for RawMutex {}

impl RawMutex {
    fn new() -> Self {
        let m = Self {
            cs: Box::pin(CRITICAL_SECTION::default()),
        };
        unsafe { InitializeCriticalSection(m.get_cs()) };
        m
    }

    unsafe fn get_cs(&self) -> *mut CRITICAL_SECTION {
        unsafe { mem::transmute(self.cs.as_ref().get_ref()) }
    }
}

impl Drop for RawMutex {
    fn drop(&mut self) {
        unsafe { DeleteCriticalSection(self.get_cs()) };
    }
}

unsafe impl lock_api::RawMutex for RawMutex {
    const INIT: Self = unreachable!();

    type GuardMarker = lock_api::GuardNoSend;

    fn lock(&self) {
        unsafe {
            EnterCriticalSection(self.get_cs());
        }
    }

    fn try_lock(&self) -> bool {
        unsafe { TryEnterCriticalSection(self.get_cs()) != 0 }
    }

    unsafe fn unlock(&self) {
        unsafe {
            LeaveCriticalSection(self.get_cs());
        }
    }
}

pub struct Mutex<T> {
    inner: lock_api::Mutex<RawMutex, T>,
}

impl<T> Mutex<T> {
    pub fn new(v: T) -> Self {
        Self {
            inner: lock_api::Mutex::from_raw(RawMutex::new(), v),
        }
    }
}

impl<T> Deref for Mutex<T> {
    type Target = lock_api::Mutex<RawMutex, T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Mutex<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(test)]
mod test {
    use super::Mutex;
    extern crate std;

    #[test]
    fn test_lock() {
        let mut threads = std::vec![];
        let n = std::sync::Arc::new(Mutex::new(0u32));
        for _ in 0..100 {
            let n = n.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let mut n = n.lock();
                    std::thread::yield_now();
                    *n += 1;
                }
            }));
        }
        for t in threads.into_iter() {
            t.join().unwrap();
        }
        assert_eq!(100_000, *n.lock());
    }

    #[test]
    fn test_try_lock() {
        let mut threads = std::vec![];
        let n = std::sync::Arc::new(Mutex::new(0u32));
        for _ in 0..100 {
            let n = n.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let mut nn = n.try_lock();
                    while nn.is_none() {
                        std::thread::yield_now();
                        nn = n.try_lock();
                    }
                    std::thread::yield_now();
                    *nn.unwrap() += 1;
                }
            }));
        }
        for t in threads.into_iter() {
            t.join().unwrap();
        }
        assert_eq!(100_000, *n.lock());
    }
}
