use gdb_command::*;

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
        .arg(format!("gcc -g {} -o /tmp/test_local_sources", src))
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
fn test_registers() {
    let mut args = Vec::new();
    let src = abs_path("tests/src/test.c");
    let input = abs_path("tests/bins/input");

    let status = Command::new("bash")
        .arg("-c")
        .arg(format!("gcc -g {} -o /tmp/test_regs", src))
        .status()
        .expect("failed to execute gcc");

    assert!(status.success());

    let input_buf = std::path::PathBuf::from(&input);
    args.push("/tmp/test_regs");
    args.push(input.as_str());
    let result = GdbCommand::new(&ExecType::Local(&args))
        .stdin(&input_buf)
        .r()
        .regs()
        .launch();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();

    let regs = Registers::from_gdb(&result[0]);
    if regs.is_err() {
        assert!(false, "{}", regs.err().unwrap());
    }
    let regs = regs.unwrap();

    assert_eq!(regs["rax"], 0);
    assert_eq!(regs["rdx"], 0);
    assert_eq!(regs["eflags"], 0x246);

    let _ = std::fs::remove_file("/tmp/test_regs");
}

#[test]
fn test_memory() {
    let mut args = Vec::new();
    let src = abs_path("tests/src/test.c");
    let input = abs_path("tests/bins/input");

    let status = Command::new("bash")
        .arg("-c")
        .arg(format!("gcc -g {} -o /tmp/test_mem", src))
        .status()
        .expect("failed to execute gcc");

    assert!(status.success());

    let input_buf = std::path::PathBuf::from(&input);
    args.push("/tmp/test_mem");
    args.push(input.as_str());
    let result = GdbCommand::new(&ExecType::Local(&args))
        .stdin(&input_buf)
        .bmain()
        .r()
        .mem("$pc", 40)
        .c()
        .launch();
    if result.is_err() {
        assert!(false, "{}", result.err().unwrap());
    }
    let result = result.unwrap();

    let mem = MemoryObject::from_gdb(&result[0]);
    if mem.is_err() {
        assert!(false, "{}", mem.err().unwrap());
    }
    let mem = mem.unwrap();

    assert_eq!(mem.data[0], 0x64);
    assert_eq!(mem.data[1], 0x48);
    assert_eq!(mem.data[2], 0x8b);

    let _ = std::fs::remove_file("/tmp/test_mem");
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

    assert_eq!(sttr[sttr.len() - 1].offset, 0x72b);
    assert_eq!(result[1].contains(&sttr[sttr.len() - 1].module), true);

    let raw_stacktrace = &[
        "#0  __strncpy_avx2 () at ../sysdeps/x86_64/multiarch/strcpy-avx2.S:363:4",
        "#9  0x00007ffff7a9f083 in __libc_start_main (main=0x2168a0, argc=2, argv=0x7fffffffe668, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe658) at ../csu/libc-start.c:308",
        "#0  __strncpy_avx2 () at ../sysdeps/x86_64/multiarch/strcpy-avx2.S:363",
        "#0  __strncpy_avx2 () at ../sysdeps/x86_64/multiarch/strcpy-avx2.S",
        "#5  0x00005555555551d4 in main ()",
        "#1  0x0000000000216d07 in ?? ()",
        "#0  __strncpy_avx2 () from /lib/libc.so.6",
        "#0  0xf7fcf569 in __kernel_vsyscall ()",
        "#2  0x0000000000487c2c in (anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&) ()"
    ];

    let sttr = Stacktrace::from_gdb(&raw_stacktrace.join("\n"));
    if sttr.is_err() {
        assert!(false, "{}", sttr.err().unwrap());
    }

    let stacktrace = sttr.unwrap();

    assert_eq!(stacktrace[0].function, "__strncpy_avx2 ()".to_string());
    assert_eq!(
        stacktrace[0].debug.file,
        "../sysdeps/x86_64/multiarch/strcpy-avx2.S".to_string()
    );
    assert_eq!(stacktrace[0].debug.line, 363);
    assert_eq!(stacktrace[0].debug.column, 4);

    assert_eq!(stacktrace[1].address, 0x00007ffff7a9f083);
    assert_eq!(stacktrace[1].function, "__libc_start_main (main=0x2168a0, argc=2, argv=0x7fffffffe668, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe658)".to_string());
    assert_eq!(stacktrace[1].debug.file, "../csu/libc-start.c".to_string());
    assert_eq!(stacktrace[1].debug.line, 308);

    assert_eq!(stacktrace[2].function, "__strncpy_avx2 ()".to_string());
    assert_eq!(
        stacktrace[2].debug.file,
        "../sysdeps/x86_64/multiarch/strcpy-avx2.S".to_string()
    );
    assert_eq!(stacktrace[2].debug.line, 363);

    assert_eq!(stacktrace[3].function, "__strncpy_avx2 ()".to_string());
    assert_eq!(
        stacktrace[3].debug.file,
        "../sysdeps/x86_64/multiarch/strcpy-avx2.S".to_string()
    );

    assert_eq!(stacktrace[4].address, 0x00005555555551d4);
    assert_eq!(stacktrace[4].function, "main ()".to_string());

    assert_eq!(stacktrace[5].address, 0x0000000000216d07);
    assert_eq!(stacktrace[5].function, "?? ()".to_string());

    assert_eq!(stacktrace[6].module, "/lib/libc.so.6".to_string());
    assert_eq!(stacktrace[6].function, "__strncpy_avx2 ()".to_string());

    assert_eq!(stacktrace[7].address, 0xf7fcf569);
    assert_eq!(stacktrace[7].function, "__kernel_vsyscall ()".to_string());

    assert_eq!(stacktrace[8].address, 0x0000000000487c2c);
    assert_eq!(stacktrace[8].function, "(anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&) ()".to_string());
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
