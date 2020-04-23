//! multithread.rs
//!
//! # Run
//!
//! ```bash
//! cargo run --example multithread -- --thread_num 2 -i [in_dir] -o [out_dir] test.exe @@
//! ```
use magne_flame::prelude::*;
use std::env;
use std::str::FromStr;
use std::process::exit;

struct RandomPrintableMutator;

impl Mutator for RandomPrintableMutator {
    fn mutate(&mut self, seed: &mut Vec<u8>) -> FuzzerResult<()> {
        /*
        // Black-box and random mutation fuzzing is not efficient.
        // If you want crash_test_filename to crash, uncomment these lines.
        if seed.len() >= 5 && util::gen_bool(0.5) {
            println!("crash");
            seed[0] = 'C' as u8;
            seed[1] = 'R' as u8;
            seed[2] = 'A' as u8;
            seed[3] = 'S' as u8;
            seed[4] = 'H' as u8;
            return Ok(());
        }
        */
        (0..util::gen_random(0, seed.len()))
            .try_for_each(|_|
                Printable::mutate(seed, util::gen_random(0, seed.len()), util::gen_random(0, Printable::v_len()))
            )
    }
}

fn usage(args: &Vec<String>) {
    println!("Multi thread example");
    println!("{} -i in_dir --thread_num 4 C:\\test.exe", args[0]);
    println!("\t-i [in_dir]\t specify input corpus directory");
    println!("\t-o [out_dir]\t specify output directory.");
    println!("\t-t [timeout]\t specify the number of seconds of timeout.");
    println!("\t--thread_num [thread_num] \t specify the number of threads");
    println!("\t-h \t show help");
}

fn parse_options(args: &Vec<String>) -> (usize, String, String, String, u128) {
    let mut exec_cmd = "".to_string();
    let mut in_dir = "".to_string();
    let mut out_dir = "out".to_string();
    let mut thread_num = 1; // The number of threads
    let mut timeout = 10000; // 10 seconds by default

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" => {
                i += 1;
                in_dir = args[i].clone();
            }
            "-o" => {
                i += 1;
                out_dir = args[i].clone();
            }
            "-t" => {
                i += 1;
                timeout = u128::from_str(&args[i]).unwrap();
            }
            "--thread_num" => {
                i += 1;
                thread_num = usize::from_str(&&args[i]).unwrap();
            }
            "-h" => {
                usage(&args);
                exit(0);
            }
            _ => {
                exec_cmd += " ";
                exec_cmd += &args[i];
            }
        }
        i += 1;
    }
    (thread_num, exec_cmd, in_dir, out_dir, timeout)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (thread_num, exec_cmd, in_dir, out_dir, timeout) = parse_options(&args);

    if exec_cmd == "" || in_dir == "" {
        println!("exec_cmd and in_dir required!");
        return;
    }
    println!("exec_cmd: {}", exec_cmd);
    println!("in_dir: {}", in_dir);
    println!("out_dir: {}", out_dir);
    println!("timeout: {}", timeout);

    FileSeed::set_out_dir(format!("{}\\queue", out_dir)); // Output corpus directory.
    let mut scheduler: SimpleScheduler<_, FileArgvSupervisor<_, FileSeed>, _> = SimpleScheduler::new(
        SimpleMutationStrategy::new(RandomPrintableMutator),
        false, // Do not store any new fuzz inputs.
    ); // Create a Scheduler.

    scheduler.add_raw_fuzzes(&util::read_directory(&in_dir).unwrap().iter().map(|file_path| {
        util::read_file(&file_path.display().to_string()).unwrap()
    }).collect::<Vec<Vec<u8>>>());

    let ctx = SimpleFuzzerContext::new(out_dir.clone()); // Create a FuzzerContext.
    ctx.start_reporter(); // Start a reporter.
    MTSupervisorController::setup_and_run(
        move || {
            FileArgvSupervisor::new(
                exec_cmd.clone(),
                format!("{}/.cur_input", out_dir),
                "".to_string(),
                true,
                timeout,
            )
        },
        scheduler,
        ctx.clone(),
        thread_num,
    );
}
