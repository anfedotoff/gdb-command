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

use regex::Regex;

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
