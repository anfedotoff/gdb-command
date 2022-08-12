use gdb_command::*;

use std::collections::HashSet;
use std::process::Command;

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
    let result = GdbCommand::new(&ExecType::Local(&args)).r().bt().launch();
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
    let result = GdbCommand::new(&ExecType::Local(&args)).r().bt().launch();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("__strcpy_chk"), true);
}

#[test]
fn test_local_sources_stdin() {
    let mut args = Vec::new();
    let src = abs_path("tests/src/test.c");
    let input = abs_path("tests/bins/input");

    let status = Command::new("bash")
        .arg("-c")
        .arg(format!("gcc -g -c {} -o /tmp/test_local_sources", src))
        .status()
        .expect("failed to execute gcc");

    assert!(status.success());

    let input_buf = std::path::PathBuf::from(&input);
    args.push("/tmp/test_local_sources");
    args.push(input.as_str());
    let result = GdbCommand::new(&ExecType::Local(&args))
        .stdin(&input_buf)
        .bmain()
        .r()
        .sources()
        .list("test.c:18")
        .c()
        .launch();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("test.c"), true);
    assert_eq!(result[1].contains("buf[i++] = c;"), true);

    let _ = std::fs::remove_file("/tmp/test_local_sources");
}

#[test]
fn test_struct_mapped_files() {
    let bin = abs_path("tests/bins/test_abort");
    let result = GdbCommand::new(&ExecType::Local(&[&bin, "A"]))
        .r()
        .mappings()
        .launch();
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
    if ffile.is_none() {
        assert!(false, "File not found!");
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
    let bin = abs_path("tests/bins/test_abort");
    let result = GdbCommand::new(&ExecType::Local(&[&bin, "A"]))
        .r()
        .bt()
        .mappings()
        .launch();
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
        result[0].contains(format!("{:x}", sttr.strace.last().unwrap().address).as_str()),
        true
    );
    assert_eq!(
        result[0].contains(&sttr.strace.last().unwrap().debug.file_path),
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

    let mystacktrace = &[
        "#0  0x1123  __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:50",
        "#1  __GI_raise (sig=sig@entry=6) at (/path/to/bin+0x123)",
        "#2  __GI_raise () at /path:16:17",
        "#3  __GI_raise () at /path:16",
        "#4  (/path+0x10)",
        "#0  0x00007ffff7dd5859 in __GI_abort ()  at ../sysdeps/unix/sysv/linux/raise.c:50",
        "#1  0x00007ffff7dd5859 in __GI_abort () at (/path/to/bin+0x122)",
        "#2  0x00007ffff7dd5859 in __GI_abort () /path:16:17",
        "#3  0x00007ffff7dd5859 in __GI_abort () at /path:16",
        "#4  0x00007ffff7dd5859 /path:16",
        "#5  0x00007ffff7dd5859 in __GI_abort () at /path",
        "#6  0x55ebfc21e12d in classes bin_dyldcache.c",
        /*#6  in libc.so.6"*/
    ]
    .join("\n")
    .to_string();

    let sttr = Stacktrace::from_gdb(mystacktrace);
    if sttr.is_err() {
        assert!(false, "{}", sttr.err().unwrap());
    }
    let sttr = sttr.unwrap();

    // Eq check
    assert_eq!(sttr.strace[0], sttr.strace[5]);
    assert_eq!(sttr.strace[1] == sttr.strace[6], false);
    assert_eq!(sttr.strace[2], sttr.strace[7]);
    assert_eq!(sttr.strace[3], sttr.strace[8]);
    assert_eq!(sttr.strace[4], sttr.strace[9]);

    // Hash check
    let mut tracehash = HashSet::new();

    tracehash.insert(Stacktrace {
        strace: [sttr.strace[0].clone(), sttr.strace[2].clone()].to_vec(),
    });
    tracehash.insert(Stacktrace {
        strace: [sttr.strace[5].clone(), sttr.strace[7].clone()].to_vec(),
    });

    if tracehash.len() != 1 {
        assert!(false, "Hash check fail");
    }

    assert_eq!(
        sttr.strace[11].debug.file_path,
        "bin_dyldcache.c".to_string()
    );
    assert_eq!(sttr.strace[11].debug.line, 0);
}

#[test]
fn test_core() {
    let bin = abs_path("tests/bins/test_canary");
    let core = abs_path("tests/bins/core.test_canary");
    let result = GdbCommand::new(&ExecType::Core {
        target: &bin,
        core: &core,
    })
    .bt()
    .launch();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();
    assert_eq!(result[0].contains("__GI_abort"), true);
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
        .launch();
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
