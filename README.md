# gdb-command

[![CI](https://github.com/xcoldhandsx/gdb-command/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/xcoldhandsx/gdb-command/actions/workflows/main.yml)
[![Crates.io](https://img.shields.io/crates/v/gdb-command)](https://crates.io/crates/gdb-command)

`gdb-command` is a library providing API for manipulating gdb in batch mode. It supports:

* Execution of target program (Local type).
* Opening core of target program (Core type).
* Attaching to remote process (Remote type).

# Example

```rust
use std::process::Command;
use std::thread;
use std::time::Duration;
use gdb_command::*;

fn main () -> error::Result<()> {
    // Get stacktrace from running program (stopped at crash)
    let result = GdbCommand::new(&ExecType::Local(&["tests/bins/test_abort", "A"])).r().bt().launch()?;

    // Get stacktrace from core
    let result = GdbCommand::new(
            &ExecType::Core {target: "tests/bins/test_canary",
                core: "tests/bins/core.test_canary"})
        .bt().launch()?;

    // Get info from remote attach to process
    let mut child = Command::new("tests/bins/test_callstack_remote")
       .spawn()
       .expect("failed to execute child");

    thread::sleep(Duration::from_millis(10));

    // To run this test: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
    let result = GdbCommand::new(&ExecType::Remote(&child.id().to_string()))
        .bt()
        .regs()
        .disassembly()
        .launch();
    child.kill().unwrap();

    Ok(())
}

```
## Installation

```toml
[dependencies]
gdb-command = "0.4.0"
```

## License

This crate is licensed under the [MIT license].

[MIT license]: LICENSE
