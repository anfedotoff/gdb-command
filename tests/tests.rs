use gdb_command::*;

/// Returns an absolute path for relative path.
fn abs_path<'a>(rpath: &'a str) -> String {
    use std::path::PathBuf;

    // Define paths.
    let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut path = PathBuf::new();
    path.push(&project_dir);
    path.push(rpath);

    path.as_os_str().to_str().unwrap().to_string()
}

#[test]
fn test_local_canary() {
    let mut args = Vec::new();
    let bin = abs_path("tests/bins/test_canary");
    let a = std::iter::repeat("A").take(200).collect::<String>();
    args.push(bin.as_str());
    args.push(a.as_str());
    let result = GdbCommand::new(&ExecType::Local(&args)).bt().run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("__stack_chk_fail"), true);
}

#[test]
fn test_local_safe_func() {
    let mut args = Vec::new();
    let bin = abs_path("tests/bins/test_safeFunc");
    let a = std::iter::repeat("A").take(200).collect::<String>();
    args.push(bin.as_str());
    args.push(a.as_str());
    let result = GdbCommand::new(&ExecType::Local(&args)).bt().run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("__strcpy_chk"), true);
}

#[test]
fn test_struct_mapped_files() {
    let bin = abs_path("tests/bins/test_abort");
    let result = GdbCommand::new(&ExecType::Local(&[&bin, "A"]))
        .mappings()
        .run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();

    let prmap = MappedFiles::from_gdb(&result[0]);
    if prmap.is_err() {
        assert!(false, "{}", prmap.err().unwrap());
    }
    let prmap = prmap.unwrap();

    assert_eq!(
        result[0]
            .contains(format!("0x{:x}", prmap.files[prmap.files.len() - 1].base_address).as_str()),
        true
    );
    assert_eq!(
        result[0].contains(format!("0x{:x}", prmap.files[prmap.files.len() - 1].end).as_str()),
        true
    );
    assert_eq!(
        result[0].contains(
            format!("0x{:x}", prmap.files[prmap.files.len() - 1].offset_in_file).as_str()
        ),
        true
    );
    if prmap.files[prmap.files.len() - 1].name != "No_file" {
        assert_eq!(
            result[0].contains(&prmap.files[prmap.files.len() - 1].name.clone()),
            true
        );
    }

    // Testing method 'find'
    let ffile = prmap.find(prmap.files[prmap.files.len() - 1].base_address + 2);
    if ffile.is_err() {
        assert!(false, "{}", ffile.err().unwrap());
    }
    let ffile = ffile.unwrap();

    assert_eq!(
        ffile.base_address,
        prmap.files[prmap.files.len() - 1].base_address
    );
    assert_eq!(
        ffile.offset_in_file,
        prmap.files[prmap.files.len() - 1].offset_in_file
    );
}

#[test]
fn test_stacktrace_structs() {
    let bin = abs_path("tests/bins/test_abort32");
    let result = GdbCommand::new(&ExecType::Local(&[&bin, "A"]))
        .bt()
        .mappings()
        .run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();

    let sttr = Stacktrace::from_gdb(&result[0]);
    if sttr.is_err() {
        assert!(false, "{}", sttr.err().unwrap());
    }
    let mut sttr = sttr.unwrap();

    assert_eq!(
        result[0].contains(format!("{:x}", sttr.strace[sttr.strace.len() - 1].address).as_str()),
        true
    );
    assert_eq!(
        result[0].contains(sttr.strace[sttr.strace.len() - 1].debug.as_str()),
        true
    );

    // Testing method 'up_stacktrace_info'

    let prmap = MappedFiles::from_gdb(&result[1]).unwrap();
    sttr.update_modules(&prmap);

    if let ModuleInfo::File(file) = &sttr.strace[sttr.strace.len() - 1].module {
        assert_eq!(
            result[1].contains(&format!("{:x}", file.base_address).to_string()),
            true
        );
        assert_eq!(
            result[1].contains(&format!("{:x}", file.end).to_string()),
            true
        );
        assert_eq!(
            result[1].contains(&format!("{:x}", file.offset_in_file).to_string()),
            true
        );
        assert_eq!(
            result[1].contains(&format!("{}", file.name).to_string()),
            true
        );
    } else {
        assert!(false, "No file...");
    }
}

#[test]
#[ignore] // To run this test: If Ubuntu 20.04 just remove ignore. Other systems: recollect the core.
fn test_core_canary() {
    let bin = abs_path("tests/bins/test_canary");
    let core = abs_path("tests/bins/core.test_canary");
    let result = GdbCommand::new(&ExecType::Core {
        target: &bin,
        core: &core,
    })
    .bt()
    .run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("__stack_chk_fail"), true);
}

#[test] // To run this test: If Ubuntu 20.04 just remove ignore. Other systems: recollect the core.
#[ignore]
fn test_core_safe_func() {
    let bin = abs_path("tests/bins/test_safeFunc");
    let core = abs_path("tests/bins/core.test_safeFunc");
    let result = GdbCommand::new(&ExecType::Core {
        target: &bin,
        core: &core,
    })
    .bt()
    .run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("__strcpy_chk"), true);
}

#[test] // To run this test: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
#[ignore]
fn test_remote_unwind() {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    let mut child = Command::new(abs_path("tests/bins/test_callstack_remote"))
        .spawn()
        .expect("failed to execute child");
    thread::sleep(Duration::from_millis(10));

    let result = GdbCommand::new(&ExecType::Remote(&child.id().to_string()))
        .bt()
        .run();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }

    let result = result.unwrap();
    assert_eq!(result[0].contains("third"), true);
    assert_eq!(result[0].contains("second"), true);
    assert_eq!(result[0].contains("first"), true);
    assert_eq!(result[0].contains("main"), true);

    child.kill().unwrap();
}
