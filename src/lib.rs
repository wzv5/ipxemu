#![no_std]

mod adapter;
mod dll;
mod ipxemu;
mod logger;
mod mutex;
mod protocol;
mod runtime;
mod sockaddr;
mod util;

type MacAddr = [u8; 6];
