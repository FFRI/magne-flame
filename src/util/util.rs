//! Utilities
use std::fs::{File, read_dir, create_dir_all, remove_dir_all};
use std::io::{Read, Write};
use std::{mem, thread};
use std::path::PathBuf;
use rand::distributions::uniform::SampleUniform;
use rand::{thread_rng, Rng};
use crate::prelude::*;
use std::ffi::CString;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};

/// Executes and monitors a target.
pub trait Target: Send + Sync + 'static + Unpin {
    /// Runs the target.
    fn run(&mut self) -> FuzzerResult<()>;
    /// Is the target running?
    fn is_running(&self) -> FuzzerResult<bool>;
    /// Destroys the target.
    fn destroy(&mut self) -> FuzzerResult<()>;
    /// Communicates the target.
    fn communicate(&mut self) -> FuzzerResult<ProcessStatus>;
}

/// Executes a function in `timeout` seconds.
pub struct Watchdog {
    enable: Arc<Mutex<bool>>,
    time: Arc<Mutex<Instant>>,
    timeout: u128,
    is_timeout: Arc<Mutex<bool>>,
}

impl Watchdog {
    /// The unit of timeout is millisecond.
    pub fn new<F>(timeout: u128, f: F) -> Self
        where F: Fn(),
              F: Send + Sync + 'static
    {
        let wd = Self {
            enable: Arc::new(Mutex::new(false)),
            time: Arc::new(Mutex::new(Instant::now())),
            timeout,
            is_timeout: Arc::new(Mutex::new(false)),
        };
        wd.spawn(f);
        wd
    }

    fn spawn<F>(&self, f: F)
        where F: Fn(),
              F: Send + Sync + 'static
    {
        let enable = self.enable.clone();
        let time = self.time.clone();
        let is_timeout = self.is_timeout.clone();
        let timeout = self.timeout;

        thread::spawn(move || {
            loop {
                thread::sleep(Duration::new(1, 0));
                let mut enable = enable.lock().unwrap();
                if *enable {
                    let wt = time.lock().unwrap();
                    if wt.elapsed().as_millis() > timeout {
                        *is_timeout.lock().unwrap() = true;
                        *enable = false;
                        f();
                    }
                }
            }
        });
    }

    /// Starts the watchdog.
    pub fn start(&self) {
        let mut time = self.time.lock().unwrap();
        *time = Instant::now();
        let mut enable = self.enable.lock().unwrap();
        *enable = true;
        *self.is_timeout.lock().unwrap() = false;
    }

    /// Stops the watchdog.
    pub fn stop(&self) {
        let mut enable = self.enable.lock().unwrap();
        *enable = false;
    }

    /// Did it time out?
    pub fn is_timeout(&self) -> bool {
        *self.is_timeout.lock().unwrap()
    }
}

struct UnsafeTargetWrapper<T: Target>(UnsafeCell<T>);

unsafe impl<T: Target> Send for UnsafeTargetWrapper<T> {}

unsafe impl<T: Target> Sync for UnsafeTargetWrapper<T> {}

impl<T: Target> UnsafeTargetWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self { 0: UnsafeCell::new(inner) }
    }

    pub unsafe fn deref_mut_inner(&self) -> &mut T {
        &mut *self.0.get()
    }
}

impl<T: Target> Deref for UnsafeTargetWrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0.get() }
    }
}

impl<T: Target> DerefMut for UnsafeTargetWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.0.get() }
    }
}

/// Monitors a target.
///
/// If the target hangs, destroys the target.
pub struct TargetWatchdog<T: Target> {
    target: Arc<UnsafeTargetWrapper<T>>,
    watchdog: Watchdog,
}

impl<T: Target> TargetWatchdog<T> {
    pub fn new(target: T, timeout: u128) -> Self {
        let target = Arc::new(UnsafeTargetWrapper::new(target));
        Self {
            target: target.clone(),
            watchdog: Watchdog::new(timeout, move || {
                trace!("Timeout");
                unsafe { let _ = target.deref_mut_inner().destroy(); }
            }),
        }
    }

    ///  Starts the watchdog's timer.
    pub fn start_watchdog(&self) { self.watchdog.start(); }

    ///  Stops the watchdog's timer.
    pub fn stop_watchdog(&self) { self.watchdog.stop(); }

    /// Did the target time out?
    pub fn is_timeout(&self) -> bool { self.watchdog.is_timeout() }

    /// Measures the time for watchdog's timer.
    pub fn watch<F: FnOnce(&mut T) -> FuzzerResult<ProcessStatus>>(&mut self, f: F) -> FuzzerResult<ProcessStatus> {
        self.start_watchdog();
        let status = unsafe { f(self.target.deref_mut_inner()) };
        self.stop_watchdog();
        match status {
            Ok(mut status) => {
                if self.is_timeout() { status = ProcessStatus::TimeOut; }
                Ok(status)
            }
            Err(x) => { Err(x) }
        }
    }
}

impl<T: Target> Deref for TargetWatchdog<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.target.deref()
    }
}

impl<T: Target> DerefMut for TargetWatchdog<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.target.deref_mut_inner() }
    }
}

/// Executes and monitors a target process.
pub trait Process: Target {
    /// Sets a command.
    fn set_command(&mut self, cmd: CString);
}

/// Generates a random value in the range [low, high).
pub fn gen_random<R: SampleUniform>(low: R, high: R) -> R {
    let mut rng = thread_rng();
    rng.gen_range(low, high)
}

/// Generates a bool value.
pub fn gen_bool(p: f64) -> bool {
    let mut rng = thread_rng();
    rng.gen_bool(p)
}

/// memmove implementation.
pub fn mem_move(v1: &mut Vec<u8>, offset_to: usize, offset_from: usize, mut len: usize) -> Result<(), ()> {
    if offset_from + len > v1.len() || offset_to + len > v1.len() {
        len = std::cmp::min(v1.len() - offset_from, v1.len() - offset_to);
    }
    if offset_to <= offset_from {
        for i in 0..len { v1[offset_to + i] = v1[offset_from + i]; }
    } else {
        let mut i = len - 1;
        loop {
            v1[offset_to + i] = v1[offset_from + i];
            if i == 0 { break; }
            i -= 1;
        }
    }
    Ok(())
}

/// memcpy implementation.
pub fn mem_copy(v1: &mut Vec<u8>, v2: &mut Vec<u8>, offset: usize) -> Result<(), ()> {
    if v1.len() <= offset { return Err(()); }
    let x = if offset + v2.len() >= v1.len() { v1.len() - offset } else { v2.len() };
    for i in 0..x { v1[i + offset] = v2[i]; }
    Ok(())
}

/// Reads `Vec<u8>` from a file.
pub fn read_file(filepath: impl AsRef<str>) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(filepath.as_ref())?;
    let mut buf: Vec<u8> = Vec::new();

    let _ = file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Writes a `Vec<u8>` to a file.
pub fn write_file(filepath: impl AsRef<str>, fuzz: &Vec<u8>) -> Result<(), std::io::Error> {
    let mut file = File::create(filepath.as_ref())?;
    file.write_all(fuzz)?;
    file.flush()
}

/// Removes a file.
pub fn remove_file(filepath: impl AsRef<str>) -> Result<(), std::io::Error> {
    std::fs::remove_file(filepath.as_ref())
}

/// Gets files in a directory.
pub fn read_directory(dir_path: impl AsRef<str>) -> Result<Vec<PathBuf>, std::io::Error> {
    let paths = read_dir(dir_path.as_ref())?;
    let mut v: Vec<PathBuf> = Vec::new();
    for path in paths {
        v.push(path.unwrap().path());
    }
    Ok(v)
}

/// Creates directories.
pub fn create_directory(dir_path: impl AsRef<str>) -> Result<(), std::io::Error> {
    create_dir_all(dir_path.as_ref())
}

/// Removes all files and directories in a directory.
pub fn clear_directory(dir_path: impl AsRef<str>) -> Result<(), std::io::Error> {
    remove_dir_all(dir_path.as_ref())
}

/// Generates a fuzzer id ( 64 bit ).
pub fn gen_fuzzer_id() -> String {
    let mut rng = rand::thread_rng();
    let id = rng.gen::<u64>();
    format!("{:x}", id)
}

/// Initializes with 0.
pub fn zero_initialize<T>() -> T { unsafe { mem::zeroed::<T>() } }
