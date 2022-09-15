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
}
