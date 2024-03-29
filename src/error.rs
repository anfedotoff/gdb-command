//! A custom GdbCommand error.
use core::fmt;
use core::result;
use std::{error, io};

#[derive(Debug)]
/// A custom GdbCommand error
pub enum Error {
    /// Gdb output parsing error
    ParseOutput(String),
    /// No executable/core found to run under gdb.
    NoFile(String),
    /// An IO based error
    IO(io::Error),
    /// Error parsing stack trace
    StacktraceParse(String),
    /// Error parsing siginfo
    SiginfoParse(String),
    /// Error parsing mapped files
    MappedFilesParse(String),
    /// Error parsing memory object.
    MemoryObjectParse(String),
    /// An ParseInt based error
    IntParse(std::num::ParseIntError),
    /// GDB launch error.
    Gdb(String),
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::IO(ref io) => Some(io),
            Error::IntParse(ref pr) => Some(pr),
            Error::ParseOutput(_) => None,
            Error::NoFile(_) => None,
            Error::StacktraceParse(_) => None,
            Error::SiginfoParse(_) => None,
            Error::MappedFilesParse(_) => None,
            Error::MemoryObjectParse(_) => None,
            Error::Gdb(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Error {
        Error::IntParse(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref err) => write!(fmt, "{err}"),
            Error::IntParse(ref err) => write!(fmt, "{err}"),
            Error::ParseOutput(ref msg) => write!(fmt, "Gdb parsing output error: {msg}"),
            Error::NoFile(ref msg) => write!(fmt, "File not found: {msg}"),
            Error::StacktraceParse(ref msg) => write!(fmt, "Error parsing stack trace: {msg}"),
            Error::SiginfoParse(ref msg) => write!(fmt, "Error parsing siginfo: {msg}"),
            Error::MappedFilesParse(ref msg) => write!(fmt, "Error parsing mapped files: {msg}"),
            Error::MemoryObjectParse(ref msg) => {
                write!(fmt, "Error parsing memory object: {msg}")
            }
            Error::Gdb(ref msg) => write!(fmt, "Failed to launch GDB: {msg}"),
        }
    }
}

/// GdbCommand Result
pub type Result<T> = result::Result<T, Error>;
