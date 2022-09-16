use crate::error;

/// `MemoryObject` represents raw data in memory.
#[derive(Clone, Debug)]
pub struct MemoryObject {
    /// Memory start address
    pub address: u64,
    /// Memory contents
    pub data: Vec<u8>,
}

impl MemoryObject {
    /// Construct `MemoryObject` from string
    ///
    /// # Arguments
    ///
    /// * 'memory' - gdb output string with memory contents (0xdeadbeaf: 0x01 0x02)
    pub fn from_gdb<T: AsRef<str>>(memory: T) -> error::Result<MemoryObject> {
        let mut mem = MemoryObject {
            address: 0,
            data: Vec::new(),
        };
        let mut lines = memory.as_ref().lines();
        if let Some(first) = lines.next() {
            // Get start address
            if let Some((address, data)) = first.split_once(':') {
                if let Some(address_part) = address.split_whitespace().next() {
                    mem.address = u64::from_str_radix(address_part.get(2..).unwrap_or(&""), 16)?;

                    // Get memory
                    for b in data.split_whitespace() {
                        mem.data
                            .push(u8::from_str_radix(b.get(2..).unwrap_or(&""), 16)?);
                    }
                } else {
                    return Err(error::Error::MemoryObjectParse(format!(
                        "Coudn't parse memory string: {}",
                        first
                    )));
                }
            } else {
                return Err(error::Error::MemoryObjectParse(format!(
                    "Coudn't parse memory string: {}",
                    first
                )));
            }

            for line in lines {
                if let Some((_, data)) = line.split_once(':') {
                    for b in data.split_whitespace() {
                        mem.data
                            .push(u8::from_str_radix(b.get(2..).unwrap_or(&""), 16)?);
                    }
                } else {
                    return Err(error::Error::MemoryObjectParse(format!(
                        "No memory values: {}",
                        line
                    )));
                }
            }
        }
        Ok(mem)
    }
}
