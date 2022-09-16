#![no_main]
use libfuzzer_sys::fuzz_target;

use gdb_command::mappings::{MappedFiles, MappedFilesExt};
use gdb_command::memory::MemoryObject;
use gdb_command::registers::{Registers, RegistersExt};
use gdb_command::siginfo::Siginfo;
use gdb_command::stacktrace::{Stacktrace, StacktraceExt};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let s = String::from_utf8_lossy(&data[1..]);
    match data[0] % 5 {
        0 => _ = Stacktrace::from_gdb(&s),
        1 => _ = Registers::from_gdb(&s),
        2 => _ = MappedFiles::from_gdb(&s),
        3 => _ = Siginfo::from_gdb(&s),
        _ => _ = MemoryObject::from_gdb(&s),
    }
});
