//! Experimental implementation of [WinAFL](https://github.com/googleprojectzero/afl).
//! This supports DynamoRIO only.
//!
//! ## Usage
//!
//! 1. Build WinAFL ( See [Building WinAFL](https://github.com/googleprojectzero/winafl#building-winafl) )
//! 2. Copy winafl.dll to the same folder that contains this fuzzer executable.
//! 3. Run command
//!
//! If you want to run this fuzzer as well as winafl/afl-fuzz.exe with following options,
//!
//! ```shell
//! afl-fuzz.exe -i in -o out -D C:\path\to\the\DynamoRIO\bin32 -t 10000 -- -target_module crash_test_filename.exe -target_offset 0x1400 -nargs 2 -coverage_module crash_test_filename.exe -fuzz_iterations 5000 -- C:\test\crash_test_filename.exe @@
//! ```
//!
//! execute the following command.
//!
//! ```shell
//! run --package afl --bin afl -- --thread_num 1 -i in -o out -D C:\path\to\the\DynamoRIO\bin32 -t 10000 -fuzz_iterations 5000 -coverage_module crash_test_filename.exe -target_module crash_test_filename.exe -target_offset 0x1400 -nargs 2 -- C:\test\crash_test_filename.exe @@
//! ```
use env_logger;
use magne_flame::prelude::*;
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

mod mutator;
mod scheduler;
mod supervisor;
mod afl_util;

use crate::scheduler::{AFLScheduler, AFLContext};
use crate::supervisor::AFLSupervisor;
use magne_flame::util::util;

fn main() {

    // env::set_var("RUST_LOG","warn");
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    let mut client_params = "".to_string();
    let mut exec_cmd = "".to_string();
    let mut fuzz_iterations: u32 = 0;
    let mut timeout: u128 = 0;
    let mut dynamorio_dir = "".to_string();
    let mut i = 1;
    let mut out_dir = "out".to_string();
    let mut in_dir = "in".to_string();
    let mut thread_num = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-D" => {
                i += 1;
                dynamorio_dir = args[i].clone();
            }
            "-fuzz_iterations" => {
                i += 1;
                fuzz_iterations = u32::from_str(&args[i]).unwrap();
                client_params += " ";
                client_params += "-fuzz_iterations ";
                client_params += &args[i];
            }
            "-t" => {
                i += 1;
                timeout = u128::from_str(&args[i]).unwrap();
            }
            "-timeout" => {
                i += 1;
                timeout = u128::from_str(&args[i]).unwrap();
            }
            "--thread_num" => {
                i += 1;
                thread_num = usize::from_str(&args[i]).unwrap();
            }
            "-o" => {
                i += 1;
                out_dir = args[i].clone();
            }
            "-i" => {
                i += 1;
                in_dir = args[i].clone();
            }
            "--" => {
                i += 1;
                exec_cmd = args[i..].join(" ");
                break;
            }
            _ => {
                client_params += " ";
                client_params += &args[i];
            }
        }
        i += 1;
    }
    if fuzz_iterations == 0 || timeout == 0 || dynamorio_dir == "" {
        panic!("-fuzz_iterations and -timeout and -D are required!!");
    }
    println!("DynamoRIO_dir: {}", dynamorio_dir);
    println!("fuzz_iterations: {} times", fuzz_iterations);
    println!("timeout: {} ms", timeout);
    println!("thread_num: {}", thread_num);
    println!("client_params: {}", client_params);
    println!("in_dir: {}", in_dir);
    println!("out_dir: {}", out_dir);
    println!("exec_cmd: {}", exec_cmd);

    let virgin_bits = Arc::new(Mutex::new(vec![255; AFLContext::MAP_SIZE as usize]));
    let virgin_crash = Arc::new(Mutex::new(vec![255; AFLContext::MAP_SIZE as usize]));
    let virgin_tmout = Arc::new(Mutex::new(vec![255; AFLContext::MAP_SIZE as usize]));

    let mut scheduler = AFLScheduler::new();
    scheduler.set_out_dir(format!("{}", out_dir));
    FileSeed::set_out_dir(format!("{}", out_dir));
    util::create_directory(&format!("{}\\queue", out_dir)).unwrap();
    util::create_directory(&format!("{}\\crashes", out_dir)).unwrap();
    util::create_directory(&format!("{}\\hangs", out_dir)).unwrap();

    let mut ctx = AFLContext::new(virgin_bits.clone(), out_dir.clone());

    for file_path in util::read_directory(&in_dir).unwrap().iter() {
        let v = util::read_file(&file_path.display().to_string()).unwrap();
        scheduler.add_raw_fuzz(v, &mut ctx);
    }

    ctx.start_reporter(SimpleReporter::new());
    MTSupervisorController::setup_and_run(
        move || {
            AFLSupervisor::new(exec_cmd.clone(), out_dir.clone(),
                               dynamorio_dir.clone(),
                               client_params.clone(),
                               fuzz_iterations,
                               timeout,
                               virgin_bits.clone(),
                               virgin_crash.clone(),
                               virgin_tmout.clone(),
            )
        },
        scheduler,
        ctx.clone(),
        thread_num,
    );
}
