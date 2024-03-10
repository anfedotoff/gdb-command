//! The `Stacktrace` struct represents gathered stacktrace.
use regex::Regex;
use std::hash::{Hash, Hasher};
use std::path::Path;

use crate::error;
use crate::mappings::{MappedFiles, MappedFilesExt};

/// `StacktraceEntry` struct represents the information about one line of the stack trace.
#[derive(Clone, Debug, Default)]
pub struct StacktraceEntry {
    /// Function address
    pub address: u64,
    /// Function name
    pub function: String,
    /// Module name
    pub module: String,
    /// Offset in module
    pub offset: u64,
    /// Debug information
    pub debug: DebugInfo,
}

/// `FrameDebug` struct represents the debug information of one frame in stack trace.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DebugInfo {
    /// Source file.
    pub file: String,
    /// Source line.
    pub line: u64,
    /// Source column.
    pub column: u64,
}

impl PartialEq for StacktraceEntry {
    fn eq(&self, other: &Self) -> bool {
        if !self.debug.file.is_empty() && !other.debug.file.is_empty() {
            return self.debug == other.debug;
        }
        if !self.module.is_empty()
            && !other.module.is_empty()
            && self.offset != 0
            && other.offset != 0
        {
            return self.module == other.module && self.offset == other.offset;
        }

        self.address == other.address
    }
}

impl Eq for StacktraceEntry {}

impl Hash for StacktraceEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if !self.debug.file.is_empty() {
            self.debug.file.hash(state);
            self.debug.line.hash(state);
            self.debug.column.hash(state);
            return;
        }
        if !self.module.is_empty() && self.offset != 0 {
            self.module.hash(state);
            self.offset.hash(state);
            return;
        }

        self.address.hash(state);
    }
}

impl StacktraceEntry {
    /// Returns 'StacktraceEntry' struct
    ///
    /// # Arguments
    ///
    /// * 'entry' - one line of stacktrace from gdb
    pub fn new<T: AsRef<str>>(entry: T) -> error::Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();

        // NOTE: the order of applying regexps is important.
        // 1. GDB source+line+column
        let re =
            Regex::new(r"^ *#[0-9]+ *(?:0x([0-9a-f]+) +in)? *(.+) +at +(.+):(\d+):(\d+)").unwrap();
        if let Some(caps) = re.captures(entry.as_ref()) {
            // Get address (optional).
            if let Some(address) = caps.get(1) {
                stentry.address = u64::from_str_radix(address.as_str(), 16)?;
            }
            // Get function name.
            stentry.function = caps.get(2).unwrap().as_str().trim().to_string();
            // Get source file.
            stentry.debug.file = caps.get(3).unwrap().as_str().trim().to_string();
            // Get source line.
            stentry.debug.line = caps.get(4).unwrap().as_str().parse::<u64>()?;
            // Get source column.
            stentry.debug.column = caps.get(5).unwrap().as_str().parse::<u64>()?;

            return Ok(stentry);
        }

        // 2. GDB source+line
        let re = Regex::new(r"^ *#[0-9]+ *(?:0x([0-9a-f]+) +in)? *(.+) +at +(.+):(\d+)").unwrap();
        if let Some(caps) = re.captures(entry.as_ref()) {
            // Get address (optional).
            if let Some(address) = caps.get(1) {
                stentry.address = u64::from_str_radix(address.as_str(), 16)?;
            }
            // Get function name.
            stentry.function = caps.get(2).unwrap().as_str().trim().to_string();
            // Get source file.
            stentry.debug.file = caps.get(3).unwrap().as_str().trim().to_string();
            // Get source line.
            stentry.debug.line = caps.get(4).unwrap().as_str().parse::<u64>()?;

            return Ok(stentry);
        }

        // 3. GDB source
        let re = Regex::new(r"^ *#[0-9]+ *(?:0x([0-9a-f]+) +in)? *(.+) +at +(.+)").unwrap();
        if let Some(caps) = re.captures(entry.as_ref()) {
            // Get address (optional).
            if let Some(address) = caps.get(1) {
                stentry.address = u64::from_str_radix(address.as_str(), 16)?;
            }
            // Get function name.
            stentry.function = caps.get(2).unwrap().as_str().trim().to_string();
            // Get source file.
            stentry.debug.file = caps.get(3).unwrap().as_str().trim().to_string();

            return Ok(stentry);
        }

        // 4. GDB from library (address is optional)
        let re = Regex::new(r"^ *#[0-9]+ *(?:0x([0-9a-f]+) +in)? *(.+) +from +(.+)").unwrap();
        if let Some(caps) = re.captures(entry.as_ref()) {
            // Get address (optional).
            if let Some(address) = caps.get(1) {
                stentry.address = u64::from_str_radix(address.as_str(), 16)?;
            }
            // Get function name.
            stentry.function = caps.get(2).unwrap().as_str().trim().to_string();
            // Get module name.
            stentry.module = caps.get(3).unwrap().as_str().trim().to_string();

            return Ok(stentry);
        }

        // 5. GDB no source (address is optional)
        let re = Regex::new(r"^ *#[0-9]+ *(?:0x([0-9a-f]+) +in)? *(.+)").unwrap();
        if let Some(caps) = re.captures(entry.as_ref()) {
            // Get address (optional).
            if let Some(address) = caps.get(1) {
                stentry.address = u64::from_str_radix(address.as_str(), 16)?;
            }
            // Get function name.
            stentry.function = caps.get(2).unwrap().as_str().trim().to_string();

            return Ok(stentry);
        }

        Err(error::Error::StacktraceParse(format!(
            "Couldn't parse stack trace entry: {}",
            entry.as_ref()
        )))
    }

    /// Strip prefix from source file path and module
    ///
    /// # Arguments
    ///
    /// * 'prefix' - path prefix
    pub fn strip_prefix<T: AsRef<str>>(&mut self, prefix: T) {
        if let Ok(stripped) = Path::new(&self.debug.file).strip_prefix(prefix.as_ref()) {
            self.debug.file = stripped.display().to_string();
        }
        if let Ok(stripped) = Path::new(&self.module).strip_prefix(prefix.as_ref()) {
            self.module = stripped.display().to_string();
        }
    }
}

/// Represents the information about stack trace
pub type Stacktrace = Vec<StacktraceEntry>;

pub trait StacktraceExt {
    /// Get stack trace as a string and converts it into 'Stacktrace'
    ///
    /// # Arguments
    ///
    /// * 'trace' - stack trace from gdb
    ///
    /// # Return value
    ///
    /// The return value is a 'Stacktrace' struct
    fn from_gdb<T: AsRef<str>>(trace: T) -> error::Result<Stacktrace>;

    /// Compute module offsets for stack trace entries based on mapped files.
    /// Gdb doesn't print module and offset in stack trace.
    ///
    /// # Arguments
    ///
    /// * 'mappings' - information about mapped files
    fn compute_module_offsets(&mut self, mappings: &MappedFiles);

    /// Strip prefix from source file path for all StacktraceEntry's
    ///
    /// # Arguments
    ///
    /// * 'prefix' - path prefix
    fn strip_prefix<T: AsRef<str>>(&mut self, prefix: T);
}

impl StacktraceExt for Stacktrace {
    fn from_gdb<T: AsRef<str>>(trace: T) -> error::Result<Stacktrace> {
        trace
            .as_ref()
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|trace| !trace.is_empty())
            .map(StacktraceEntry::new)
            .collect()
    }

    fn compute_module_offsets(&mut self, mappings: &MappedFiles) {
        self.iter_mut().for_each(|x| {
            if let Some(y) = mappings.find(x.address) {
                x.offset = x.address - y.start + y.offset;
                if !y.name.is_empty() {
                    x.module = y.name;
                }
            }
        });
    }

    fn strip_prefix<T: AsRef<str>>(&mut self, prefix: T) {
        *self = std::mem::take(self)
            .into_iter()
            .map(|mut e| {
                e.strip_prefix(prefix.as_ref());
                e
            })
            .collect();
    }
}
