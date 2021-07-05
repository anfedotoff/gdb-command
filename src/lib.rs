//! # gdb-command
//!
//! `gdb-command` is a library providing API for manipulating gdb in batch mode. It supports:
//!
//! * Execution of target program (Local type).
//! * Opening core of target program (Core type).
//! * Attaching to remote process (Remote type).
//!
//! # Example
//!
//! ```rust
//! use std::process::Command;
//! use std::thread;
//! use std::time::Duration;
//! use gdb_command::*;
//!
//! fn main () -> error::Result<()> {
//!     // Get stacktrace from running program (stopped at crash)
//!     let result = GdbCommand::new(&ExecType::Local(&["tests/bins/test_abort", "A"])).bt().run()?;
//!
//!     // Get stacktrace from core
//!     let result = GdbCommand::new(
//!             &ExecType::Core {target: "tests/bins/test_canary",
//!                 core: "tests/bins/core.test_canary"})
//!         .bt().run()?;
//!
//!     // Get info from remote attach to process
//!     let mut child = Command::new("tests/bins/test_callstack_remote")
//!        .spawn()
//!        .expect("failed to execute child");
//!
//!     thread::sleep(Duration::from_millis(10));
//!
//!     // To run this test: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
//!     let result = GdbCommand::new(&ExecType::Remote(&child.id().to_string()))
//!         .bt()
//!         .regs()
//!         .disassembly()
//!         .run();
//!     child.kill().unwrap();
//!
//!     Ok(())
//! }
//!
//! ```

use std::path::Path;
use std::process::Command;
use std::fmt;
use regex::Regex;

/// `File` struct represents unit (segment) in proccess address space.
#[derive(Clone, Default, Debug)]
pub struct File {
    pub base_address: u64,
    pub end: u64,
    /// Offset in pages.
    pub file_ofs: u64,
    /// Full path to binary module.
    pub name: String,
}

impl File {
    /// Returns File struct.
    /// Constucts Mapped file from components.
    ///
    /// # Arguments
    ///
    /// * `base` - linear address of load.
    ///
    /// * `end` - linear address of end.
    ///
    /// * `offset` - page offset.
    ///
    ///* `fname` - full path to binary module.
    pub fn new(base: u64, end: u64, offset: u64, fname: &str) -> Self {
        File {
            base_address: base,
            end: end,
            file_ofs: offset,
            name: String::from(fname),
        }
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "File {{ Base: 0x{:x}, End: 0x{:x}, offset: 0x{:x}, path: {} }}",
            self.base_address, self.end, self.file_ofs, self.name
        )
    }
}

///`MappedFiles` all mapped files in crashed proccess.
#[derive(Clone, Default)]
pub struct MappedFiles {
    pub fcount: i32,
    pub page_size: i32,
    pub files: Vec<File>,
}

impl fmt::Display for MappedFiles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut files_string = String::new();
        for f in self.files.iter() {
            files_string.push_str(&f.to_string());
            files_string.push_str("; \n");
        }
        write!(
            f,
            "MappedFiles {{ Count:{}, Page_size:{};\n {} }}",
            self.fcount, self.page_size, files_string
        )
    }
}

impl MappedFiles {
    /// Returns MappedFiels struct
    ///
    /// # Arguments
    ///
    /// * 'mapping' - String of mapped files
    pub fn from_gdb(mapping: String) -> MappedFiles {
        let mut hlp = mapping.split('\n').map(|s| s.trim().to_string()).collect::<Vec<String>>();
        hlp.drain(0..5);
        hlp.remove(hlp.len() - 1);
        let mut some = Vec::<File>::new();

        for x in hlp.iter() {
            let mut filevec = x.split(' ').map(|s| s.trim().to_string()).collect::<Vec<String>>();
            filevec.retain(|x| x != "");
            let hlp = File {
                base_address: u64::from_str_radix(filevec[0].clone().drain(2..).collect::<String>().as_str(), 16).unwrap(),
                end: u64::from_str_radix(filevec[1].clone().drain(2..).collect::<String>().as_str(), 16).unwrap(),
                //size: u64::from_str_radix(filevec[2].clone().drain(2..).collect::<String>().as_str(), 16).unwrap(),
                file_ofs: u64::from_str_radix(filevec[3].clone().drain(2..).collect::<String>().as_str(), 16).unwrap(),
                name: match filevec.len() {
                        0..=4 => "No_file".to_string(),
                        _ => filevec[4].clone().to_string(),
                },
            };
            some.push(hlp.clone());
        }

        MappedFiles{fcount: some.len() as i32, page_size: 4096, files: some}
    }

    /// Method determines which file contains the address
    ///
    /// # Arguments
    ///
    /// * 'addr' - given address
    pub fn find(&self, addr: u64) -> Option<File> {
        let mut f = 0;
        for y in self.files.iter() {
            if (y.base_address < addr as u64) && (y.end > addr as u64) {
                break;
            }
            f += 1;
        }
        if f < self.files.len() {
            return Some(self.files[f].clone());
        } else {
            return None;
        }
    }
}

#[derive(Clone)]
pub enum ModuleInfo {
    Name(String),
    File(File) ,
}

/// `StacktraceEntry` struct represents the information about one line of the stacktrace.
pub struct StacktraceEntry {
   pub address: u64,
   pub module: ModuleInfo,
   pub debug: String,
}

impl fmt::Display for StacktraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Address: 0x{:x}, ModuleInfo: {}, DebugInfo: {}",
            self.address,
            match self.module.clone() {
                ModuleInfo::Name(x) => x,
                ModuleInfo::File(x) => x.to_string(),
            },
            self.debug

        )
    }
}

/// Fucntion gets the stacktrace as a string and converts it into vector of 'StacktraceEntry' structs
///
/// # Arguments
///
/// * 'trace' - stacktrace from gdb
///
/// # Return value
///
/// The return value is a vector of  'StacktraceEntry' structs
pub fn gettrace(trace: String) -> Vec<StacktraceEntry> {
    let mut some = Vec::<StacktraceEntry>::new();
    let mut hlp = trace.split('\n').map(|s| s.trim().to_string()).collect::<Vec<String>>();
    hlp.remove(0);
    hlp.remove(hlp.len() - 1);
    hlp.iter().for_each(|x| some.push(StacktraceEntry::new(x.clone())));
    some
}

impl StacktraceEntry {
    /// Returns 'StacktraceEntry' struct
    ///
    /// # Arguments
    ///
    /// * 'trace' - one line of stacktrace from gdb
    pub fn new(trace: String) -> StacktraceEntry {
        let mut vectrace = trace.split(' ').map(|s| s.trim().to_string()).collect::<Vec<String>>();
        vectrace.retain(|trace| trace != "");
        let normname: String;
        let addr = u64::from_str_radix(vectrace[1].clone().drain(2..).collect::<String>().as_str(), 16).unwrap_or(0);
        let mut debugg = vectrace[vectrace.len() - 1].clone();

        let first: usize;
        if addr == 0 {
            first = 1;
        } else {
            first = 3;
        }

        if debugg == "()" {
            normname = vectrace.clone().drain(first..vectrace.len()).collect::<String>();
            debugg = "No_file".to_string();
        } else {
            normname = vectrace.clone().drain(first..vectrace.len() - 2).collect::<String>();
        }

        StacktraceEntry{address: addr, module: ModuleInfo::Name(normname), debug: debugg}
    }

    /// Method attaches 'File" struct to module information
    ///
    /// # Arguments
    ///
    /// 'file' - struct 'File'
    pub fn upmodinfo(&mut self, file: &File) {
        self.module = ModuleInfo::File(file.clone());
    }

    /// Method compute the offset between the function and the start of the file
    pub fn getoffset(&self) -> u64 {
        match &self.module {
            ModuleInfo::Name(name) => {
                println!("No info, just name: {}", name);
                0
            }
            ModuleInfo::File(file) => {
                self.address as u64 - file.base_address + file.file_ofs
            }
        }
    }
}

pub mod error;
/// Type of `gdb` execution: Remote attach to process, local run with args, core.
#[derive(Debug, Clone)]
pub enum ExecType<'a> {
    /// Run target program via `gdb` (--args) option.
    Local(&'a [&'a str]),
    /// Attach to process via `gdb` (-p) option.
    Remote(&'a str),
    /// Run target via `gdb` with coredump.
    Core { target: &'a str, core: &'a str },
}

/// Struct contains information about arguments for `gdb` to run.
#[derive(Debug)]
pub struct GdbCommand<'a> {
    /// Gdb execution type.
    exec_type: ExecType<'a>,
    /// Execution parameters (-ex).
    args: Vec<&'a str>,
}

impl<'a> GdbCommand<'a> {
    /// Construct `GdbCommand` from given ExecType.
    /// # Arguments
    ///
    /// * `type` - execution type to run gdb.
    pub fn new(exec_type: &'a ExecType) -> GdbCommand<'a> {
        GdbCommand {
            exec_type: exec_type.clone(),
            args: Vec::new(),
        }
    }

    /// Add new gdb command to execute.
    /// # Arguments
    ///
    /// * `cmd` - gdb command parameter (-ex).
    pub fn ex(&mut self, cmd: &'a str) -> &'a mut GdbCommand {
        self.args.push("-ex");
        self.args.push("p \"gdb-command\"");
        self.args.push("-ex");
        self.args.push(cmd);
        self
    }

    /// Run gdb with provided commands and return raw stdout.
    pub fn raw(&self) -> error::Result<Vec<u8>> {
        let mut gdb = Command::new("gdb");
        let mut gdb_args = Vec::new();

        // Set quiet mode and confirm off
        gdb_args.push("--batch");
        gdb_args.push("-ex");
        gdb_args.push("set backtrace limit 2000");
        gdb_args.push("-ex");
        gdb_args.push("set disassembly-flavor intel");

        // Add parameters according to execution
        match &self.exec_type {
            ExecType::Local(args) => {
                // Check if binary exists (first element.)
                if !Path::new(args[0]).exists() {
                    return Err(error::Error::NoFile(args[0].to_string()));
                }

                gdb_args.push("-ex");
                gdb_args.push("r");
                gdb_args.append(&mut self.args.clone());
                gdb_args.push("--args");
                gdb_args.extend_from_slice(args);
            }
            ExecType::Remote(pid) => {
                gdb_args.push("-p");
                gdb_args.push(pid);
                gdb_args.append(&mut self.args.clone());
            }
            ExecType::Core { target, core } => {
                // Check if binary exists
                if !Path::new(target).exists() {
                    return Err(error::Error::NoFile(target.to_string()));
                }

                // Check if core exists
                if !Path::new(core).exists() {
                    return Err(error::Error::NoFile(core.to_string()));
                }
                gdb_args.append(&mut self.args.clone());
                gdb_args.push(&target);
                gdb_args.push(&core);
            }
        }

        // Run gdb and get output
        let output = gdb.args(&gdb_args).output()?;
        if output.status.success() {
            Ok(output.stdout.clone())
        } else {
            Err(error::Error::ExitCode(output.status.code().unwrap()))
        }
    }

    /// Add command to get backtrace (-ex bt)
    pub fn bt(&mut self) -> &'a mut GdbCommand {
        self.ex("bt")
    }

    /// Add command to get disassembly (-ex 'x/16i $pc')
    pub fn disassembly(&mut self) -> &'a mut GdbCommand {
        self.ex("x/16i $pc")
    }

    /// Add command to get registers (-ex 'i r')
    pub fn regs(&mut self) -> &'a mut GdbCommand {
        self.ex("i r")
    }

    /// Add command to get mappings (-ex 'info proc mappings')
    pub fn mappings(&mut self) -> &'a mut GdbCommand {
        self.ex("info proc mappings")
    }

    /// Add command to get cmd line.
    pub fn cmdline(&mut self) -> &'a mut GdbCommand {
        self.ex("info proc cmdline")
    }

    /// Add command to get environment variables
    pub fn env(&mut self) -> &'a mut GdbCommand {
        self.ex("show environment")
    }

    /// Add command to get process status
    pub fn status(&mut self) -> &'a mut GdbCommand {
        self.ex("info proc status")
    }

    /// Execute gdb and get result for each command.
    /// # Return value.
    ///
    /// The return value is a vector of strings for each command executed.
    pub fn run(&self) -> error::Result<Vec<String>> {
        let stdout = self.raw()?;
        let output = String::from_utf8(stdout).unwrap();
        let re = Regex::new(r#"(?m)^\$\d+\s*=\s*"gdb-command"$"#).unwrap();
        let mut result = re
            .split(&output)
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        result.remove(0);
        Ok(result)
    }
}
