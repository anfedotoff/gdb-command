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
        result[0].contains(format!("0x{:x}", prmap[prmap.len() - 1].start).as_str()),
        true
    );
    assert_eq!(
        result[0].contains(format!("0x{:x}", prmap[prmap.len() - 1].end).as_str()),
        true
    );
    assert_eq!(
        result[0].contains(format!("0x{:x}", prmap[prmap.len() - 1].offset).as_str()),
        true
    );
    if prmap[prmap.len() - 1].name != "No_file" {
        assert_eq!(
            result[0].contains(&prmap[prmap.len() - 1].name.clone()),
            true
        );
    }

    // Testing method 'find'
    let ffile = prmap.find(prmap[prmap.len() - 1].start + 2);
    if ffile.is_none() {
        assert!(false, "File not found!");
    }
    let ffile = ffile.unwrap();

    assert_eq!(ffile.start, prmap[prmap.len() - 1].start);
    assert_eq!(ffile.offset, prmap[prmap.len() - 1].offset);
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
        result[0].contains(format!("{:x}", sttr.last().unwrap().address).as_str()),
        true
    );
    assert_eq!(result[0].contains(&sttr.last().unwrap().debug.file), true);

    let prmap = MappedFiles::from_gdb(&result[1]).unwrap();
    sttr.compute_module_offsets(&prmap);

    assert_eq!(
        result[1].contains(&format!("{:x}", &sttr[sttr.len() - 1].offset).to_string()),
        true
    );
    assert_eq!(
        result[1].contains(&format!("{}", &sttr[sttr.len() - 1].module).to_string()),
        true
    );

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
    assert_eq!(sttr[0], sttr[5]);
    assert_eq!(sttr[1] == sttr[6], false);
    assert_eq!(sttr[2], sttr[7]);
    assert_eq!(sttr[3], sttr[8]);
    assert_eq!(sttr[4], sttr[9]);

    // Hash check
    let mut tracehash = HashSet::new();

    tracehash.insert([sttr[0].clone(), sttr[2].clone()].to_vec());
    tracehash.insert([sttr[5].clone(), sttr[7].clone()].to_vec());

    if tracehash.len() != 1 {
        assert!(false, "Hash check fail");
    }

    assert_eq!(sttr[11].debug.file, "bin_dyldcache.c".to_string());
    assert_eq!(sttr[11].debug.line, 0);
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
