use std::fmt;

use crate::error;

/// `File` struct represents unit (segment) in proccess address space.
#[derive(Clone, Default, Debug)]
pub struct File {
    /// Start address of objfile
    pub start: u64,
    /// End address of objfile
    pub end: u64,
    /// Offset in file.
    pub offset: u64,
    /// Full path to binary module.
    pub name: String,
}

impl File {
    /// Constructs Mapped file from components.
    ///
    /// # Arguments
    ///
    /// * `start` - linear address of module load.
    ///
    /// * `end` - linear address of module end.
    ///
    /// * `offset` - offset in file.
    ///
    ///* `fname` - full path to binary module.
    pub fn new(start: u64, end: u64, offset: u64, fname: &str) -> Self {
        File {
            start,
            end,
            offset,
            name: String::from(fname),
        }
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "File {{ Start: 0x{:x}, End: 0x{:x}, offset: 0x{:x}, path: {} }}",
            self.start, self.end, self.offset, self.name
        )
    }
}

/// `MappedFiles` all mapped files in process.
pub type MappedFiles = Vec<File>;

pub trait MappedFilesExt {
    /// Construct `MappedFiels` from string
    ///
    /// # Arguments
    ///
    /// * 'mapping' - gdb output string with mapped files
    fn from_gdb<T: AsRef<str>>(mapping: T) -> error::Result<MappedFiles>;

    /// Determine which file contains the address
    ///
    /// # Arguments
    ///
    /// * 'addr' - given address
    fn find(&self, addr: u64) -> Option<File>;
}

impl MappedFilesExt for MappedFiles {
    fn from_gdb<T: AsRef<str>>(mapping: T) -> error::Result<MappedFiles> {
        let mut hlp = mapping
            .as_ref()
            .lines()
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();

        if let Some(pos) = hlp.iter().position(|x| x.contains("Start Addr")) {
            hlp.drain(0..pos + 1);
        }

        let mut files = MappedFiles::new();

        for x in hlp.iter() {
            let mut filevec = x
                .split_whitespace()
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>();
            filevec.retain(|x| !x.is_empty());
            if filevec.len() < 4 {
                return Err(error::Error::MappedFilesParse(format!(
                    "Expected at least 4 columns in {}",
                    x.to_string()
                )));
            }
            let hlp = File {
                start: u64::from_str_radix(filevec[0].get(2..).unwrap_or(&filevec[0]), 16)?,
                end: u64::from_str_radix(filevec[1].get(2..).unwrap_or(&filevec[1]), 16)?,
                offset: u64::from_str_radix(filevec[3].get(2..).unwrap_or(&filevec[3]), 16)?,
                name: if filevec.len() == 5 {
                    filevec[4].clone()
                } else {
                    String::new()
                },
            };
            files.push(hlp.clone());
        }

        Ok(files)
    }

    fn find(&self, addr: u64) -> Option<File> {
        self.iter()
            .find(|&x| (x.start <= addr as u64) && (x.end > addr as u64))
            .cloned()
    }
}
