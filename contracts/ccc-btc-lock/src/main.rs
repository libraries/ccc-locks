#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

mod entry;
mod error;

#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!(4 * 1024, 1400 * 1024, 64);

use entry::entry;

pub fn program_entry() -> i8 {
    match entry() {
        Ok(_) => 0,
        Err(e) => e as i8,
    }
}
