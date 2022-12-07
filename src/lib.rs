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
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

pub mod error;
pub mod mappings;
pub mod memory;
pub mod registers;
pub mod siginfo;
pub mod stacktrace;

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
        let mut gdb_args: Vec<String> = vec![
            "--batch".to_string(),
            "-ex".to_string(),
            "set backtrace limit 2000".to_string(),
            "-ex".to_string(),
            "set disassembly-flavor intel".to_string(),
            "-ex".to_string(),
            "set filename-display absolute".to_string(),
        ];

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
        let output = gdb.args(&gdb_args).output();
        if let Err(e) = output {
            return Err(error::Error::Gdb(e.to_string()));
        }
        let mut output = output.unwrap();
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

    /// Print lines from source file
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

    /// Get memory contents (string of hex bytes)
    ///
    /// # Arguments
    ///
    /// * `expr` - expression that represents the start memory address.
    ///
    /// * `size` - size of memory in bytes to get.
    pub fn mem<T: AsRef<str>>(&mut self, expr: T, size: usize) -> &'a mut GdbCommand {
        self.ex(format!("x/{}bx {}", size, expr.as_ref()))
    }

    /// Add command to get siginfo
    pub fn siginfo(&mut self) -> &'a mut GdbCommand {
        self.ex("p/x $_siginfo")
    }

    /// Execute gdb and get result from raw stdout
    /// # Return value.
    ///
    /// The return value is a vector of strings for each command executed.
    pub fn launch(&self) -> error::Result<Vec<String>> {
        // Get raw output from Gdb.
        let stdout = self.raw()?;

        // Split stdout into lines.
        let output = String::from_utf8_lossy(&stdout);

        self.parse(output)
    }

    /// Result for each executed gdb command from raw gdb output.
    /// # Return value.
    ///
    /// The return value is a vector of strings for each command executed.
    pub fn parse<T: AsRef<str>>(&self, output: T) -> error::Result<Vec<String>> {
        let lines: Vec<String> = output.as_ref().lines().map(|l| l.to_string()).collect();

        // Create empty results for each command.
        let mut results = Vec::new();
        (0..self.commands_cnt).for_each(|_| results.push(String::new()));

        let re_start = Regex::new(r#"^\$\d+\s*=\s*"gdb-command-start-(\d+)"$"#).unwrap();
        let re_end = Regex::new(r#"^\$\d+\s*=\s*"gdb-command-end-(\d+)"$"#).unwrap();
        let mut start = 0;
        let mut cmd_idx = 0;
        for (i, line) in lines.iter().enumerate() {
            // Find gdb-commnad-start guard and save command index.
            if let Some(caps) = re_start.captures(line) {
                cmd_idx = caps.get(1).unwrap().as_str().parse::<usize>()?;
                start = i;
            }

            // Find gdb-commnad-end guard.
            if let Some(caps) = re_end.captures(line) {
                let end_idx = caps.get(1).unwrap().as_str().parse::<usize>()?;
                // Check if gdb-commnad-end guard matches start guard.
                if end_idx == cmd_idx && cmd_idx < self.commands_cnt {
                    results[cmd_idx] = lines[start + 1..i].join("\n");
                }
            }
        }
        Ok(results)
    }
}
