use std::collections::HashMap;

use crate::error;

/// `Registers` is a map from register name to it's value.
pub type Registers = HashMap<String, u64>;

pub trait RegistersExt {
    /// Construct `Registers` from string
    ///
    /// # Arguments
    ///
    /// * 'registers' - gdb output string with registers
    fn from_gdb<T: AsRef<str>>(registers: T) -> error::Result<Registers>;
}

impl RegistersExt for Registers {
    fn from_gdb<T: AsRef<str>>(registers: T) -> error::Result<Registers> {
        let mut regs = HashMap::new();
        let splited = registers.as_ref().lines().map(|s| s.split_whitespace());
        for mut e in splited {
            if let Some(reg) = e.next() {
                if let Some(value) = e.next() {
                    regs.insert(
                        reg.to_string(),
                        u64::from_str_radix(value.get(2..).unwrap_or(&""), 16)?,
                    );
                }
            }
        }
        Ok(regs)
    }
}
