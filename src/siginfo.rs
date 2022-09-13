use regex::Regex;

use crate::error;

/// Definition from https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/siginfo.h (not all fields are defined).
#[derive(Copy, Clone, Default)]
pub struct Siginfo {
    /// Signal number.
    pub si_signo: u32,
    pub si_errno: u32,
    pub si_code: u32,
    /// Address due to access to which an exception was occurred.
    pub si_addr: u64,
}

impl Siginfo {
    /// Construct `Siginfo` from string (integers are hex).
    ///
    /// # Arguments
    ///
    /// * 'info' - gdb output string with siginfo
    pub fn from_gdb<T: AsRef<str>>(info: T) -> error::Result<Siginfo> {
        let re =
            Regex::new(r"si_signo = 0x([0-9a-f]+).*si_errno = 0x([0-9a-f]+).*si_code = 0x([0-9a-f]+).*si_addr = 0x([0-9a-f]+)").unwrap();

        if let Some(caps) = re.captures(info.as_ref()) {
            Ok(Siginfo {
                si_signo: u32::from_str_radix(caps.get(1).unwrap().as_str(), 16)?,
                si_errno: u32::from_str_radix(caps.get(2).unwrap().as_str(), 16)?,
                si_code: u32::from_str_radix(caps.get(3).unwrap().as_str(), 16)?,
                si_addr: u64::from_str_radix(caps.get(4).unwrap().as_str(), 16)?,
            })
        } else {
            Err(error::Error::StacktraceParse(
                format!("Couldn't parse siginfo: {}", info.as_ref()).to_string(),
            ))
        }
    }

    /// Returns string representation of signo.
    pub fn signo_to_str(&self) -> &'static str {
        match self.si_signo {
            SIGINFO_SIGINT => "SIGINT",
            SIGINFO_SIGILL => "SIGILL",
            SIGINFO_SIGABRT => "SIGABRT",
            SIGINFO_SIGFPE => "SIGFPE",
            SIGINFO_SIGBUS => "SIGBUS",
            SIGINFO_SIGSEGV => "SIGSEGV",
            _ => "UNKNOWN",
        }
    }
    /// Returns string representation of code.
    pub fn code_to_str(&self) -> &'static str {
        match self.si_signo {
            SIGINFO_SIGSEGV => match self.si_code {
                SIGINFO_SEGV_MAPERR => "SEGV_MAPERR",
                SIGINFO_SEGV_ACCERR => "SEGV_ACCERR",
                _ => "UNKNOWN",
            },
            SIGINFO_SIGFPE => match self.si_code {
                SIGINFO_FPE_INTDIV => "FPE_INTDIV",
                SIGINFO_FPE_INTOVF => "FPE_INTOVF",
                SIGINFO_FPE_FLTDIV => "FPE_FLTDIV",
                SIGINFO_FPE_FLTOVF => "FPE_FLTOVF",
                SIGINFO_FPE_FLTUND => "FPE_FLTUND",
                SIGINFO_FPE_DECOVF => "FPE_DECOVF",
                SIGINFO_FPE_DECDIV => "FPE_DECDIV",
                _ => "UNKNOWN",
            },
            _ => "UNKNOWN",
        }
    }
}

// Signal numbers.
pub const SIGINFO_SIGINT: u32 = 1;
pub const SIGINFO_SIGILL: u32 = 4;
pub const SIGINFO_SIGABRT: u32 = 6;
pub const SIGINFO_SIGFPE: u32 = 8;
pub const SIGINFO_SIGBUS: u32 = 10;
pub const SIGINFO_SIGSEGV: u32 = 11;

// Signal codes.
// SIGSEGV
pub const SIGINFO_SEGV_MAPERR: u32 = 1;
pub const SIGINFO_SEGV_ACCERR: u32 = 2;
pub const SI_KERNEL: u32 = 0x80;
// SIGFPE
pub const SIGINFO_FPE_INTDIV: u32 = 1;
pub const SIGINFO_FPE_INTOVF: u32 = 2;
pub const SIGINFO_FPE_FLTDIV: u32 = 3;
pub const SIGINFO_FPE_FLTOVF: u32 = 4;
pub const SIGINFO_FPE_FLTUND: u32 = 5;
pub const SIGINFO_FPE_DECOVF: u32 = 9;
pub const SIGINFO_FPE_DECDIV: u32 = 10;
