use crate::prelude::*;
use std::io::{stdout, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::fmt::Formatter;

/// Holds the state and statistics of the whole fuzzer.
pub trait FuzzerContext: 'static + Unpin + Send + Sync + Clone {
    /// Called before Supervisor::fuzz_one function.
    fn pre_fuzz_one(&mut self) {}
    /// Called after Supervisor::fuzz_one function.
    fn post_fuzz_one(&mut self) {}
}

/// Checks the target status after fuzzing.
pub trait TargetStatus: FuzzerContext {
    fn check_target_status(&mut self, status: &ProcessStatus);
}

/// Stores the fuzz input when the target crashes or hangs.
pub trait StoreFuzz<T: Supervisor>: FuzzerContext {
    fn store_crash(&mut self, fuzz: &T::Fuzz);
    fn store_hang(&mut self, fuzz: &T::Fuzz);
}

/// Statistics for FuzzerContext.
pub struct Stats {
    /// Time when fuzzing started.
    pub start_time: Instant,
    /// The number of fuzzing executions.
    pub fuzzed: u64,
    /// The number of crash inputs.
    pub crashes: u64,
    /// The number of hang inputs.
    pub hangs: u64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            fuzzed: 0,
            crashes: 0,
            hangs: 0,
        }
    }
}

#[derive(Clone)]
/// Logs the execution time and the number of executions, crashes and hangs.
pub struct SimpleFuzzerContext {
    out_dir: String,
    crashes_id: u64,
    hangs_id: u64,
    pub stats: Arc<Mutex<Stats>>,
}

impl FuzzerContext for SimpleFuzzerContext {
    fn pre_fuzz_one(&mut self) { self.stats.lock().unwrap().fuzzed += 1; }
}

impl TargetStatus for SimpleFuzzerContext {
    fn check_target_status(&mut self, status: &ProcessStatus) {
        match status {
            ProcessStatus::Crash => self.stats.lock().unwrap().crashes += 1,
            ProcessStatus::TimeOut => self.stats.lock().unwrap().hangs += 1,
            _ => {}
        }
    }
}

impl<T: Supervisor> StoreFuzz<T> for SimpleFuzzerContext {
    /// Saves a crashed fuzz input to file.
    fn store_crash(&mut self, fuzz: &T::Fuzz) {
        util::write_file(&format!("{}/crashes/id_{:>05}", self.out_dir, self.crashes_id), fuzz.get_fuzz()).unwrap();
        self.crashes_id += 1;
    }

    /// Saves a hanged fuzz input to file.
    fn store_hang(&mut self, fuzz: &T::Fuzz) {
        util::write_file(&format!("{}/hangs/id_{:>05}", self.out_dir, self.hangs_id), fuzz.get_fuzz()).unwrap();
        self.hangs_id += 1;
    }
}

impl SimpleFuzzerContext {
    /// Creates SimpleFuzzerContext and output directories.
    pub fn new(out_dir: String) -> Self {
        util::create_directory(&out_dir).unwrap();
        util::create_directory(&format!("{}/crashes", out_dir)).unwrap();
        util::create_directory(&format!("{}/hangs", out_dir)).unwrap();
        Self {
            out_dir,
            crashes_id: 0,
            hangs_id: 0,
            stats: Arc::new(Mutex::new(Stats::default())),
        }
    }

    /// Starts a reporter.
    ///
    /// The reporter outputs the elapsed time since fuzzing started, the number of fuzzed, crashes and hangs.
    pub fn start_reporter(&self) {
        let stats = self.stats.clone();

        let reporter = SimpleReporter::new();
        Reporter::start(reporter, move |_| {
            let s = stats.lock().unwrap();
            let elapsed = s.start_time.elapsed().as_secs();
            let out = stdout();
            let mut out = BufWriter::new(out.lock());
            writeln!(out, "+----------------+").unwrap();
            writeln!(out, "|  {:>5} sec     |", elapsed).unwrap();
            writeln!(out, "|  {:>5} exec    |", s.fuzzed).unwrap();
            writeln!(out, "|{:>7.02} exec/sec|", s.fuzzed as f64 / elapsed as f64).unwrap();
            writeln!(out, "|  {:>5} crashes |", s.crashes).unwrap();
            writeln!(out, "|  {:>5} hangs   |", s.hangs).unwrap();
            writeln!(out, "+----------------+").unwrap();
        });
    }
}

#[derive(Clone, Default)]
/// Does nothing (for debugging).
pub struct MockFuzzerContext;

impl FuzzerContext for MockFuzzerContext {}

impl TargetStatus for MockFuzzerContext { fn check_target_status(&mut self, _: &ProcessStatus) {} }

impl<T: Supervisor> StoreFuzz<T> for MockFuzzerContext {
    fn store_crash(&mut self, _: &<T as Supervisor>::Fuzz) {}
    fn store_hang(&mut self, _: &<T as Supervisor>::Fuzz) {}
}

pub type OsResult<T> = Result<T, OsError>;

pub type FuzzerResult<T> = Result<T, FuzzerError>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Represents an OS-intrinsic error.
pub struct OsError(pub u32);

impl std::fmt::Display for OsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        format!("OsError: {}",self.0).fmt(f)
    }
}

#[derive(Debug, PartialEq, Eq)]
/// Represents a fuzzer error.
pub struct FuzzerError(pub String);

impl std::error::Error for FuzzerError {}

impl std::fmt::Display for FuzzerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<std::io::Error> for FuzzerError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<Box<std::io::Error>> for FuzzerError {
    fn from(err: Box<std::io::Error>) -> Self {
        Self(err.to_string())
    }
}

impl From<OsError> for FuzzerError {
    fn from(err: OsError) -> Self {
        Self(err.to_string())
    }
}

