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
//!     // Get stack trace from running program (stopped at crash)
//!     let result = GdbCommand::new(&ExecType::Local(&["tests/bins/test_abort", "A"])).r().bt().launch()?;
//!
//!     // Get stack trace from core
//!     let result = GdbCommand::new(
//!             &ExecType::Core {target: "tests/bins/test_canary",
//!                 core: "tests/bins/core.test_canary"})
//!         .bt().launch()?;
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
//!         .launch();
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
            .split('\n')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();

        let pos = hlp.iter().position(|x| x.contains("Start Addr"));
        if pos.is_none() {
            return Err(error::Error::MappedFilesParse(
                format!("Couldn't find Start Addr: {}", mapping.as_ref()).to_string(),
            ));
        }
        hlp.drain(0..pos.unwrap() + 1);

        let mut files = MappedFiles::new();

        for x in hlp.iter() {
            let mut filevec = x
                .split(' ')
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
                start: u64::from_str_radix(
                    filevec[0].clone().drain(2..).collect::<String>().as_str(),
                    16,
                )?,
                end: u64::from_str_radix(
                    filevec[1].clone().drain(2..).collect::<String>().as_str(),
                    16,
                )?,
                offset: u64::from_str_radix(
                    filevec[3].clone().drain(2..).collect::<String>().as_str(),
                    16,
                )?,
                name: if filevec.len() == 5 {
                    filevec[4].clone().to_string()
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

/// `StacktraceEntry` struct represents the information about one line of the stack trace.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// * 'trace' - one line of stacktrace from gdb
    pub fn new<T: AsRef<str>>(entry: T) -> error::Result<StacktraceEntry> {
        let _ = &[
            // 1. Asan module+offset case
            r"^ *#[0-9]+ *(0x[0-9a-f]+) *(?:in *(.+))? *\((.*)\+(0x[0-9a-f]+)\)",
            // 2. GDB source+line+column
            r"^ *#[0-9]+ *(?:(0x[0-9a-f]+) +in)? *(.+) +at +(.+)\:(\d+)\:(\d+)",
            // 3. GDB source+line
            r"^ *#[0-9]+ *(?:(0x[0-9a-f]+) +in)? *(.+) +at +(.+)\:(\d+)",
            // 4. GDB source
            r"^ *#[0-9]+ *(?:(0x[0-9a-f]+) +in)? *(.+) +at +(.+)",
            // 5. ASAN source+line+column
            r"^ *#[0-9]+ *(0x[0-9a-f]+) *in *([^ \(\)]+(?: *\(.*\))?) *([^\(\)]+)\:(\d+)\:(\d+)",
            // 6. ASAN source+line
            r"^ *#[0-9]+ *(0x[0-9a-f]+) *in *([^ \(\)]+(?: *\(.*\))?) *([^\(\)]+)\:(\d+)",
            // 7. ASAN source
            r"^ *#[0-9]+ *(0x[0-9a-f]+) *in *([^ \(\)]+(?: *\(.*\))?) *([^\(\)]+)$",
            // 8. GDB no source (address and from library are optional)
            r"^ *#[0-9]+ *(?:(0x[0-9a-f]+) +in)? *([^ \(\)]+ *\(.*\))(?: +from +(.+))?",
        ];

        let mut vectrace = entry
            .as_ref()
            .split(' ')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        vectrace.retain(|trace| !trace.is_empty());

        // OOB
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
                function: func_with_args,
                module: String::new(),
                offset: 0,
                debug: DebugInfo {
                    file: "".to_string(),
                    line: 0 as u64,
                    column: 0 as u64,
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
                        function: func_with_args,
                        module: String::new(),
                        offset: 0,
                        debug: DebugInfo {
                            file: file_path,
                            line: *off_in_f,
                            column: offset_in_line,
                        },
                    });
                }
            }
            return Ok(StacktraceEntry {
                address: addr,
                function: func_with_args,
                module: String::new(),
                offset: 0,
                debug: DebugInfo {
                    file: debug_line,
                    line: 0 as u64,
                    column: 0 as u64,
                },
            });
        }
    }
}

/// Struct represents the information about stack trace
pub type Stacktrace = Vec<StacktraceEntry>;

pub trait StacktraceExt {
    /// Get stack trace as a string and converts it into 'Stacktrace' struct
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
    ///
    /// # Arguments
    ///
    /// * 'mappings' - information about mapped files
    fn compute_module_offsets(&mut self, mappings: &MappedFiles);
}

impl StacktraceExt for Stacktrace {
    fn from_gdb<T: AsRef<str>>(trace: T) -> error::Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();
        let mut entries = trace
            .as_ref()
            .split('\n')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        entries.retain(|trace| !trace.is_empty());

        if entries.len() < 1 {
            return Err(error::Error::StacktraceParse(
                format!("Stack trace is empty: {}", trace.as_ref()).to_string(),
            ));
        }

        for x in entries.iter() {
            stacktrace.push(StacktraceEntry::new(&x.clone())?);
        }
        Ok(stacktrace)
    }

    fn compute_module_offsets(&mut self, mappings: &MappedFiles) {
        self.iter_mut().for_each(|x| {
            if let Some(y) = mappings.find(x.address) {
                x.offset = x.address - y.start + y.offset;
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
    args: Vec<String>,
    /// Stdin file
    stdin: Option<&'a PathBuf>,
    /// Commands to execute for result.
    commands_cnt: usize,
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
            commands_cnt: 0,
        }
    }

    /// Add stdin for executable.
    /// You should call this method before using `r` method.
    /// # Arguments
    ///
    /// * `file` - path to stdin file
    pub fn stdin<T: Into<Option<&'a PathBuf>>>(&mut self, file: T) -> &'a mut GdbCommand {
        self.stdin = file.into();
        self
    }

    /// Add new gdb command to execute.
    /// # Arguments
    ///
    /// * `cmd` - gdb command parameter (-ex).
    pub fn ex<T: Into<String>>(&mut self, cmd: T) -> &'a mut GdbCommand {
        self.args.push("-ex".to_string());
        self.args
            .push(format!("p \"gdb-command-start-{}\"", self.commands_cnt));
        self.args.push("-ex".to_string());
        self.args.push(cmd.into());
        self.args.push("-ex".to_string());
        self.args
            .push(format!("p \"gdb-command-end-{}\"", self.commands_cnt));
        self.commands_cnt += 1;
        self
    }

    /// Run gdb with provided commands and return raw stdout.
    pub fn raw(&self) -> error::Result<Vec<u8>> {
        let mut gdb = Command::new("gdb");
        let mut gdb_args = Vec::new();

        // Set quiet mode and confirm off
        gdb_args.push("--batch".to_string());
        gdb_args.push("-ex".to_string());
        gdb_args.push("set backtrace limit 2000".to_string());
        gdb_args.push("-ex".to_string());
        gdb_args.push("set disassembly-flavor intel".to_string());
        gdb_args.push("-ex".to_string());
        gdb_args.push("set filename-display absolute".to_string());

        // Add parameters according to execution
        match &self.exec_type {
            ExecType::Local(args) => {
                // Check if binary exists (first element.)
                if !Path::new(args[0]).exists() {
                    return Err(error::Error::NoFile(args[0].to_string()));
                }

                gdb_args.append(&mut self.args.clone());
                gdb_args.push("--args".to_string());
                args.iter().for_each(|a| gdb_args.push(a.to_string()));
            }
            ExecType::Remote(pid) => {
                gdb_args.push("-p".to_string());
                gdb_args.push(pid.to_string());
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
                gdb_args.push(target.to_string());
                gdb_args.push(core.to_string());
            }
        }

        // Run gdb and get output
        let mut output = gdb.args(&gdb_args).output()?;
        output.stdout.append(&mut output.stderr.clone());
        Ok(output.stdout)
    }

    /// Add command to run program
    /// # Arguments
    ///
    /// * `file` - path to stdin file
    pub fn r(&mut self) -> &'a mut GdbCommand {
        self.args.push("-ex".to_string());
        let run_command = if let Some(stdin) = self.stdin {
            format!("r < {}", stdin.display())
        } else {
            "r".to_string()
        };
        self.args.push(run_command);
        self
    }

    /// Add command to continue execution
    pub fn c(&mut self) -> &'a mut GdbCommand {
        self.args.push("-ex".to_string());
        self.args.push("c".to_string());
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

    /// Break at main
    pub fn bmain(&mut self) -> &'a mut GdbCommand {
        self.args.push("-ex".to_string());
        self.args.push("b main".to_string());
        self
    }

    /// List print lines from source file
    ///
    /// # Arguments
    ///
    /// * `location` - lines centered around the line specified by location.
    /// If None then location is current line.
    pub fn list<T: Into<Option<&'a str>>>(&mut self, location: T) -> &'a mut GdbCommand {
        if let Some(loc) = location.into() {
            self.ex(format!("list {}", loc))
        } else {
            self.ex("list")
        }
    }

    /// Execute gdb and get result for each command.
    /// # Return value.
    ///
    /// The return value is a vector of strings for each command executed.
    pub fn launch(&self) -> error::Result<Vec<String>> {
        // Get raw output from Gdb.
        let stdout = self.raw()?;

        // Split stdout into lines.
        let output = String::from_utf8_lossy(&stdout);
        let lines: Vec<String> = output.split('\n').map(|l| l.to_string()).collect();

        // Create empty results for each command.
        let mut results = Vec::new();
        (0..self.commands_cnt).for_each(|_| results.push(String::new()));

        let re_start = Regex::new(r#"^\$\d+\s*=\s*"gdb-command-start-(\d+)"$"#).unwrap();
        let re_end = Regex::new(r#"^\$\d+\s*=\s*"gdb-command-end-(\d+)"$"#).unwrap();
        let mut start = 0;
        let mut cmd_idx = 0;
        for (i, line) in lines.iter().enumerate() {
            // Find gdb-commnad-start guard and save command index.
            if let Some(caps) = re_start.captures(&line) {
                cmd_idx = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                start = i;
            }

            // Find gdb-commnad-end guard.
            if let Some(caps) = re_end.captures(&line) {
                let end_idx = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                // Check if gdb-commnad-end guard matches start guard.
                if end_idx == cmd_idx && cmd_idx < self.commands_cnt {
                    results[cmd_idx] = lines[start + 1..i].join("\n");
                }
            }
        }
        Ok(results)
    }
}
