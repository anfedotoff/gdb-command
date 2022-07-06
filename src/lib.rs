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

use regex::Regex;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// `File` struct represents unit (segment) in proccess address space.
#[derive(Clone, Default, Debug)]
pub struct File {
    /// Start address of objfile
    pub base_address: u64,
    /// End address of objfile
    pub end: u64,
    /// Offset in file.
    pub offset_in_file: u64,
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
    /// * `offset` - offset in file.
    ///
    ///* `fname` - full path to binary module.
    pub fn new(base: u64, end: u64, offset: u64, fname: &str) -> Self {
        File {
            base_address: base,
            end: end,
            offset_in_file: offset,
            name: String::from(fname),
        }
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "File {{ Base: 0x{:x}, End: 0x{:x}, offset: 0x{:x}, path: {} }}",
            self.base_address, self.end, self.offset_in_file, self.name
        )
    }
}

///`MappedFiles` all mapped files in proccess.
#[derive(Clone, Debug)]
pub struct MappedFiles {
    /// Vector of mapped files
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
            "MappedFiles {{ Count:{};\n {} }}",
            self.files.len(),
            files_string
        )
    }
}

impl MappedFiles {
    /// Returns MappedFiels struct
    ///
    /// # Arguments
    ///
    /// * 'mapping' - gdb output string with mapped files
    pub fn from_gdb(mapping: &str) -> error::Result<MappedFiles> {
        let mut hlp = mapping
            .split('\n')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        if hlp.len() < 6 {
            return Err(error::Error::MappedFilesParse(
                format!("cannot parse this string: {}", mapping).to_string(),
            ));
        }

        let pos = hlp.iter().position(|x| x.contains("Start Addr"));
        if pos.is_none() {
            return Err(error::Error::MappedFilesParse(
                format!("cannot parse this string: {}", mapping).to_string(),
            ));
        }
        hlp.drain(0..pos.unwrap() + 1);

        let mut some = Vec::<File>::new();

        for x in hlp.iter() {
            let mut filevec = x
                .split(' ')
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>();
            filevec.retain(|x| x != "");
            if filevec.len() < 4 {
                return Err(error::Error::MappedFilesParse(
                    format!("cannot parse this string: {}", mapping).to_string(),
                ));
            }
            let hlp = File {
                base_address: u64::from_str_radix(
                    filevec[0].clone().drain(2..).collect::<String>().as_str(),
                    16,
                )
                .unwrap(),
                end: u64::from_str_radix(
                    filevec[1].clone().drain(2..).collect::<String>().as_str(),
                    16,
                )
                .unwrap(),
                offset_in_file: u64::from_str_radix(
                    filevec[3].clone().drain(2..).collect::<String>().as_str(),
                    16,
                )
                .unwrap(),
                name: if filevec.len() == 5 {
                    filevec[4].clone().to_string()
                } else {
                    String::new()
                },
            };
            some.push(hlp.clone());
        }

        Ok(MappedFiles { files: some })
    }

    /// Method determines which file contains the address
    ///
    /// # Arguments
    ///
    /// * 'addr' - given address
    pub fn find(&self, addr: u64) -> Option<File> {
        self.files
            .iter()
            .find(|&x| (x.base_address < addr as u64) && (x.end > addr as u64))
            .cloned()
    }
}

/// 'ModuleInfo' enum represents the name of the module or contains information about the module.
#[derive(Clone, Debug)]
pub enum ModuleInfo {
    /// Module name
    Name(String),
    /// Module file
    File(File),
}

/// `StacktraceEntry` struct represents the information about one line of the stacktrace.
#[derive(Clone, Debug)]
pub struct StacktraceEntry {
    /// Function address
    pub address: u64,
    /// Information about the module
    pub module: ModuleInfo,
    /// Debug information
    pub debug: DebugInfo,
}

/// `FrameDebug` struct represents the debug information of one frame in stack trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugInfo {
    /// /path:123:456
    /// "/path"
    pub file_path: String,
    /// 123
    pub offset_in_file: Option<u64>,
    /// 456
    pub offset_in_line: u64,
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
            match &self.debug.offset_in_file {
                Some(oif) => [
                    self.debug.file_path.clone(),
                    oif.to_string(),
                    self.debug.offset_in_line.to_string()
                ]
                .join(":")
                .to_string(),
                None => self.debug.file_path.clone(),
            },
        )
    }
}

impl PartialEq for StacktraceEntry {
    fn eq(&self, other: &Self) -> bool {
        if self.debug.offset_in_file.is_some() && other.debug.offset_in_file.is_some() {
            return self.debug == other.debug;
        }
        match &self.module {
            ModuleInfo::Name(_) => self.address == other.address,
            ModuleInfo::File(file1) => {
                if let ModuleInfo::File(file2) = &other.module {
                    if (file1.name == file2.name)
                        && (self.offset().unwrap() == other.offset().unwrap())
                    {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }
}

impl Eq for StacktraceEntry {}

impl Hash for StacktraceEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(oif) = &self.debug.offset_in_file {
            self.debug.file_path.hash(state);
            oif.hash(state);
            self.debug.offset_in_line.hash(state);
            return;
        }
        match &self.module {
            ModuleInfo::Name(_) => {
                self.address.hash(state);
            }
            ModuleInfo::File(file) => {
                file.name.hash(state);
                self.offset().hash(state);
            }
        }
    }
}

impl StacktraceEntry {
    /// Returns 'StacktraceEntry' struct
    ///
    /// # Arguments
    ///
    /// * 'trace' - one line of stacktrace from gdb
    pub fn new(trace: &str) -> error::Result<StacktraceEntry> {
        let mut vectrace = trace
            .split(' ')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        vectrace.retain(|trace| trace != "");
        let addr = u64::from_str_radix(
            vectrace[1].clone().drain(2..).collect::<String>().as_str(),
            16,
        )
        .unwrap_or(0);
        let debug_line = match vectrace.last().clone() {
            Some(x) => x.clone().to_string(),
            None => "".to_string(),
        };
        let first: usize = if addr == 0 { 1 } else { 3 };

        // In some cases we can see '#0  0xf7fcf569 in __kernel_vsyscall ()', so, pretty good
        // technical solution below
        if debug_line == "()" {
            let func_with_args = if first <= vectrace.len() {
                vectrace
                    .clone()
                    .drain(first..vectrace.len())
                    .collect::<String>()
            } else {
                String::new()
            };

            return Ok(StacktraceEntry {
                address: addr,
                module: ModuleInfo::Name(func_with_args),
                debug: DebugInfo {
                    file_path: "".to_string(),
                    offset_in_file: None,
                    offset_in_line: 0 as u64,
                },
            });
        } else {
            let func_with_args = if first < vectrace.len() - 1 {
                vectrace
                    .clone()
                    .drain(first..vectrace.len() - 1)
                    .collect::<String>()
            } else {
                String::new()
            };
            // Find debug info about line and pos in line

            let dentries = &[
                // "(/path/to/bin+0x123)"
                r"\((?P<file_path_1>[^+]+)\+0x(?P<module_offset_1>[0-9a-fA-F]+)\)",
                // "/path:16:17"
                r"(?P<file_path_2>[^ ]+):(?P<file_line_1>\d+):(?P<offset_in_line>\d+)",
                // "/path:16"
                r"(?P<file_path_3>[^ ]+):(?P<file_line_2>\d+)",
                // "(/path/to/bin+0x123)"
                r"\((?P<file_path_4>.*)\+0x(?P<module_offset_2>[0-9a-fA-F]+)\)$",
                // "libc.so.6"
                r"(?P<file_path_5>[^ ]+)$",
            ];

            let asan_re = format!("^(?:{})$", dentries.join("|"));

            let asan_base =
                Regex::new(&asan_re).expect("Regex failed to compile while asan parsing");

            let asan_captures = asan_base.captures(&debug_line);
            if let Some(captures) = &asan_captures {
                let file_path = match captures
                    .name("file_path_1")
                    .or_else(|| captures.name("file_path_2"))
                    .or_else(|| captures.name("file_path_3"))
                    .or_else(|| captures.name("file_path_4"))
                    .or_else(|| captures.name("file_path_5"))
                    .map(|x| x.as_str().to_string())
                {
                    Some(x) => x,
                    None => String::new(),
                };

                let mut offset_in_file = match captures
                    .name("module_offset_1")
                    .or_else(|| captures.name("module_offset_2"))
                    .map(|x| x.as_str())
                {
                    Some(x) => Some(u64::from_str_radix(x, 16)?),
                    None => None,
                };

                if offset_in_file.is_none() {
                    offset_in_file = match captures
                        .name("file_line_1")
                        .or_else(|| captures.name("file_line_2"))
                        .map(|x| x.as_str())
                    {
                        Some(x) => Some(x.parse::<u64>()?),
                        None => None,
                    }
                }

                let offset_in_line = match captures
                    .name("offset_in_line")
                    .map(|x| x.as_str().to_string())
                {
                    Some(x) => x.parse::<u64>()?,
                    None => 0,
                };

                if let Some(off_in_f) = &offset_in_file {
                    return Ok(StacktraceEntry {
                        address: addr,
                        module: ModuleInfo::Name(func_with_args),
                        debug: DebugInfo {
                            file_path: file_path,
                            offset_in_file: Some(*off_in_f),
                            offset_in_line: offset_in_line,
                        },
                    });
                }
            }
            return Ok(StacktraceEntry {
                address: addr,
                module: ModuleInfo::Name(func_with_args),
                debug: DebugInfo {
                    file_path: debug_line,
                    offset_in_file: None,
                    offset_in_line: 0 as u64,
                },
            });
        }
    }

    /// Method attaches 'File' struct to module information
    ///
    /// # Arguments
    ///
    /// 'file' - struct 'File'
    pub fn update_module(&mut self, file: &File) {
        self.module = ModuleInfo::File(file.clone());
    }

    /// Method computes the offset between the function and the start of the file
    pub fn offset(&self) -> Option<u64> {
        match &self.module {
            ModuleInfo::Name(_) => None,
            ModuleInfo::File(file) => {
                Some(self.address as u64 - file.base_address + file.offset_in_file)
            }
        }
    }
}

/// Struct represents the information about stack trace
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Stacktrace {
    /// Vector of stack trace
    pub strace: Vec<StacktraceEntry>,
}

impl fmt::Display for Stacktrace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut entry_string = String::new();
        for en in self.strace.iter() {
            entry_string.push_str(&en.to_string());
            entry_string.push_str("; \n");
        }
        write!(f, "Stacktrace\n{}", entry_string)
    }
}

impl Stacktrace {
    /// Method gets the stacktrace as a string and converts it into vector of 'StacktraceEntry' structs
    ///
    /// # Arguments
    ///
    /// * 'trace' - stacktrace from gdb
    ///
    /// # Return value
    ///
    /// The return value is a vector of  'StacktraceEntry' structs
    pub fn from_gdb(trace: &str) -> error::Result<Stacktrace> {
        let mut some = Vec::<StacktraceEntry>::new();
        let mut entries = trace
            .split('\n')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        entries.retain(|trace| trace != "");

        if entries.len() < 1 {
            return Err(error::Error::StacktraceParse(
                format!("cannot get stack trace from this string: {}", trace).to_string(),
            ));
        }

        for x in entries.iter() {
            some.push(StacktraceEntry::new(&x.clone())?);
        }
        Ok(Stacktrace { strace: some })
    }

    /// Method updates information about function modules.
    ///
    /// # Arguments
    ///
    /// * 'mappings' - information about mapped files
    pub fn update_modules(&mut self, mappings: &MappedFiles) {
        self.strace.iter_mut().for_each(|x| {
            if let Some(y) = mappings.find(x.address) {
                x.update_module(&y);
            }
        });
    }
}

pub mod error;
/// Type of `gdb` execution: Remote attach to process, local run with args, core.
#[derive(Debug, Clone)]
pub enum ExecType<'a> {
    /// Run target program via `gdb` (--args) option.
    Local(&'a [&'a str]),
    /// Run target program built with address sanitizer via `gdb` (--args) option.
    ASan(&'a [&'a str]),
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
    /// Stdin file
    stdin: Option<&'a PathBuf>,
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
            stdin: None,
        }
    }

    /// Add stdin for executable
    /// # Arguments
    ///
    /// * `file` - path to stdin file
    pub fn stdin(&mut self, file: Option<&'a PathBuf>) -> &'a mut GdbCommand {
        self.stdin = file;
        self
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

        // Create run command
        let run_command = if let Some(stdin) = self.stdin {
            format!("r < {}", stdin.display())
        } else {
            "r".to_string()
        };

        // Add parameters according to execution
        match &self.exec_type {
            ExecType::Local(args) => {
                // Check if binary exists (first element.)
                if !Path::new(args[0]).exists() {
                    return Err(error::Error::NoFile(args[0].to_string()));
                }

                gdb_args.append(&mut self.args.clone());
                gdb_args.push("-ex");
                gdb_args.push("p \"gdb-command\"");
                gdb_args.push("--args");
                if let Some(pos) = gdb_args.iter().position(|&x| x == "r") {
                    gdb_args[pos] = run_command.as_str();
                } else {
                    gdb_args.insert(5, run_command.as_str());
                    gdb_args.insert(5, "-ex");
                }
                gdb_args.extend_from_slice(args);
            }
            ExecType::ASan(args) => {
                // Check if binary exists (first element.)
                if !Path::new(args[0]).exists() {
                    return Err(error::Error::NoFile(args[0].to_string()));
                }

                // We need to stop execution before using gdb user options due to sanitizer abort
                gdb_args.push("-ex");
                gdb_args.push("b main");
                gdb_args.append(&mut self.args.clone());
                gdb_args.push("-ex");
                gdb_args.push("c");
                gdb_args.push("-ex");

                // if we had a segfault we need to continue program running to get ASan report
                gdb_args.push("c");
                gdb_args.push("-ex");
                gdb_args.push("p \"gdb-command\"");
                gdb_args.push("--args");
                if let Some(pos) = gdb_args.iter().position(|&x| x == "r") {
                    gdb_args[pos] = run_command.as_str();
                } else {
                    gdb_args.insert(7, run_command.as_str());
                    gdb_args.insert(7, "-ex");
                }
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
        let mut output = gdb.args(&gdb_args).output()?;
        if output.status.success() {
            output.stdout.append(&mut output.stderr.clone());
            Ok(output.stdout)
        } else {
            Err(error::Error::ExitCode(output.status.code().unwrap()))
        }
    }

    /// Add command to run program
    pub fn r(&mut self) -> &'a mut GdbCommand {
        self.args.push("-ex");
        self.args.push("r");
        self
    }

    /// Add command to continue execution
    pub fn c(&mut self) -> &'a mut GdbCommand {
        self.args.push("-ex");
        self.args.push("c");
        self
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

    /// Add command to get info
    pub fn sources(&mut self) -> &'a mut GdbCommand {
        self.ex("info sources")
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
