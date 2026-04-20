#![no_std]
#![no_main]

mod helpers;
mod maps;
mod programs;

// Re-export all eBPF program entry points so aya can find them.
pub use programs::file_ops::{
    do_filp_open_entry, openat2_entry, vfs_open_entry, vfs_read_entry, vfs_write_entry,
};
pub use programs::tcp_connect::{tcp_connect, tcp_connect_ret};
pub use programs::tls_openssl::{ssl_read_entry, ssl_read_return, ssl_write_entry};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
