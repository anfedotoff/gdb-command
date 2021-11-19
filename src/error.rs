//! A custom GdbCommand error
//!

use core::fmt;
use core::result;
use std::{error, io};

#[derive(Debug)]
/// A custom GdbCommand error
pub enum Error {
    /// Gdb output parsing error
    ParseOutput(String),
    /// Gdb exit status error
    ExitCode(i32),
    /// No executable/core found to run under gdb.
    NoFile(String),
    /// An IO based error
    IO(io::Error),
    /// Error parsing stacktrace
    StacktraceParse(String),
    /// Error parsing mapped files
    MappedFilesParse(String),
    /// An ParseInt based error
    IntParse(std::num::ParseIntError),
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::IO(ref io) => Some(io),
            Error::IntParse(ref pr) => Some(pr),
            Error::ParseOutput(_) => None,
            Error::NoFile(_) => None,
            Error::ExitCode(_) => None,
            Error::StacktraceParse(_) => None,
            Error::MappedFilesParse(_) => None,
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
            Error::IO(ref err) => write!(fmt, "{}", err),
            Error::IntParse(ref err) => write!(fmt, "{}", err),
            Error::ExitCode(code) => write!(fmt, "Gdb finished with exit code:{}", code),
            Error::ParseOutput(ref msg) => write!(fmt, "Gdb parsing output error: {}", msg),
            Error::NoFile(ref msg) => write!(fmt, "File not found: {}", msg),
            Error::StacktraceParse(ref msg) => write!(fmt, "Error parsing stack trace: {}", msg),
            Error::MappedFilesParse(ref msg) => write!(fmt, "Error parsing mapped files: {}", msg),
        }
    }
}

/// GdbCommand Result
pub type Result<T> = result::Result<T, Error>;
