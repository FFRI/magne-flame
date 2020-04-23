# MagneFlame
MagneFlame: Multi Supervisor Fuzzing Framework

MagneFlame is a fast and extensible fuzzing framework.

Current version is only available for Windows.
When you compile MagneFlame on Linux, it does not work properly.

# Install

Add the following lines to your Cargo.toml:

```
[dependencies]
magne-flame = { git = "https://github.com/ffri/magne-flame" }
```

# Example

```rust
use magne_flame::prelude::*;

struct RandomPrintableMutator;

impl Mutator for RandomPrintableMutator {
    fn mutate(&mut self, seed: &mut Vec<u8>) -> FuzzerResult<()> {
        for _ in 0..util::gen_random(0, seed.len()) {
            Printable::mutate(seed, util::gen_random(0, seed.len()), util::gen_random(0, Printable::v_len())).unwrap();
        }
        Ok(())
    }
}

fn main(){
    let exec_cmd = "examples\\target_programs\\bin\\crash_test_filename.exe @@".to_string();
    let in_dir = "in".to_string();
    let out_dir = "out".to_string();
    let timeout = 10000;
    let thread_num = 4;

    FileSeed::set_out_dir(format!("{}\\queue", out_dir)); // Output corpus directory.
    let mut scheduler: SimpleScheduler<_, FileArgvSupervisor<_, FileSeed>, _> = SimpleScheduler::new(
        SimpleMutationStrategy::new(RandomPrintableMutator),
        false, // Do not store any new fuzz inputs.
    ); // Create a Scheduler.

    scheduler.add_raw_fuzzes(&util::read_directory(&in_dir).expect("Failed to read the directory.").iter().map(|file_path| {
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

```

Output: 

```

+----------------+
|      1 sec     |
|    181 exec    |
| 181.00 exec/sec|
|      0 crashes |
|      0 hangs   |
+----------------+

+----------------+
|      2 sec     |
|    363 exec    |
| 181.50 exec/sec|
|      0 crashes |
|      0 hangs   |
+----------------+

+----------------+
|      3 sec     |
|    527 exec    |
| 175.67 exec/sec|
|      0 crashes |
|      0 hangs   |
+----------------+

+----------------+
|      4 sec     |
|    701 exec    |
| 175.25 exec/sec|
|      0 crashes |
|      0 hangs   |
+----------------+

+----------------+
|      5 sec     |
|    883 exec    |
| 176.60 exec/sec|
|      0 crashes |
|      0 hangs   |
+----------------+

```
For more information, see [Get Started](book/src/GetStarted.md)
