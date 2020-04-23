# Get Started

# Install

Add the following lines to your Cargo.toml:

```
[dependencies]
magne-flame = { git = "https://github.com/FFRI/magne-flame" }
```

# Implement Fuzzers

Let's develop a simple black-box fuzzer that fuzzes an executable that reads a file.

First, we use FileSeed.

FileSeed saves and reads corpus inputs to a directory, so specify the output directory.

```rust
let out_dir = "out".to_string(); // Output directory

FileSeed::set_out_dir(format!("{}\\queue", out_dir)); // Set corpus queue directory.
```

Next, create Scheduler, MutationStrategy and Mutator.

Scheduler implements a strategy to get the fuzz input from the data structure. 

SimpleScheduler selects and fetches the fuzz data in the order in which they were queued.

MutationStrategy implements a strategy to mutate the fuzz input. 

SimpleMutationStrategy can set and use 1 Mutator.

Here we implement RandomPrintableMutator to replace bytes with printable characters at random.

```rust
struct RandomPrintableMutator;

impl Mutator for RandomPrintableMutator {
    fn mutate(&mut self, seed: &mut Vec<u8>) -> Result<(), FuzzerError> {
        (0..util::gen_random(0, seed.len()))
            .try_for_each(|_|
                Printable::mutate(seed, util::gen_random(0, seed.len()), util::gen_random(0, Printable::v_len()))
            )
    }
}
```

Pass the MutationStrategy to the SimpleScheduler.

```rust
let mut scheduler: SimpleScheduler<_, FileArgvSupervisor<FileSeed, _>, _> = SimpleScheduler::new(
    SimpleMutationStrategy::new(RandomPrintableMutator),
    false, // Do not save any new fuzz inputs.
);
```

Because the scheduler does not have any input corpuses yet, we give them to the scheduler.
So use files in the in_dir directory as corpuses.

```rust
let in_dir = "in".to_string(); // Input corpuses directory

scheduler.add_raw_fuzzes(Util::read_directory(&in_dir).unwrap().iter().map(|file_path| {
    Util::read_file(&file_path.display().to_string()).unwrap()
}).collect::<Vec<Vec<u8>>>());
```

Then, create FuzzerContext.
FuzzerContext contains statistics information of the whole fuzzer.

SimpleFuzzerContext contains the execution time, the number of fuzzing executions, the number of crashes and the number of hangs.
It also has a reporter that outputs a fuzzing progress report to stdout every second.

```
let ctx = SimpleFuzzerContext::new(out_dir.clone()); // Create a FuzzerContext.
ctx.start_reporter(); // Start a reporter.
```

## Single-thread
Note: This implementation is available at [singlethread.rs](../blob/master/examples/singlethread.rs).

Create SupervisorController and Supervisor.

SupervisorController controls Supervisor.
Supervisor executes and monitors a target.

FileArgvSupervisor fuzzes the target taking fuzz from the file.

`@@` in exec_cmd will be replaced with the fuzz file path by FileArgvSupervisor.

```rust
let exec_cmd = "path\\to\\the\\executable @@".to_string(); // Execution command
let timeout = 10000; // timeout after 10 seconds.

SupervisorController::setup_and_run(
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
);
```

### Running singlethread.rs Example

Let's fuzz the example program.

First, build crash_test_filename.c.

For Windows, examples/target_programs/crash_test_filename.vcxproj is available to build the source file.

Then fuzz it!

```bash
mkdir in
echo HELLO > in\1.txt
cargo run --example singlethread -- -i in -o out examples\target_programs\bin\crash_test_filename.exe @@
```

## Multi-thread
Note: This implementation is available at [multithread.rs](../blob/master/examples/multithread.rs).

MagneFlame can execute SupervisorController with multiple threads and fuzz the target in parallel.

Let's rewrite the above single-threaded example to be multi-threaded.

Replace SupervisorController with MTSupervisorController.
MTSupervisorController requires the number of threads.

```rust
let thread_num = 2; // The number of threads.
let timeout = 10000; // timeout after 10 seconds.

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
```

That's all!

### Running multithread.rs Example

Let's fuzz the example program.

First, build crash_test_filename.c.

For Windows, examples/target_programs/crash_test_filename.vcxproj is available to build the source.

```bash
mkdir in
echo HELLO > in\1.txt
pushd examples\target_programs
make
popd
cargo run --example multithread -- --thread_num 2 -i in -o out examples\target_programs\bin\crash_test_filename.exe @@
```

