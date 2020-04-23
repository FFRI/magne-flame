use magne_flame::prelude::*;
use std::cell::Cell;
use std::ffi::CString;
use std::mem::size_of;
use std::ptr;
use winapi::shared::minwindef::{DWORD, TRUE, FALSE, LPCVOID, LPDWORD, LPVOID};
use winapi::shared::winerror::{ERROR_IO_PENDING, WAIT_TIMEOUT, ERROR_PIPE_CONNECTED};
use winapi::um::processthreadsapi::{STARTUPINFOA, PROCESS_INFORMATION};
use winapi::um::winbase::{STARTF_USESTDHANDLES, PIPE_ACCESS_DUPLEX, FILE_FLAG_OVERLAPPED, WAIT_OBJECT_0, INFINITE};
use winapi::shared::winerror::ERROR_ALREADY_EXISTS;
use winapi::um::winnt::HANDLE;
use winapi::um::minwinbase::{LPOVERLAPPED, OVERLAPPED};
use magne_flame::util::util::{Target, Process};
use crate::scheduler::AFLContext;

pub struct AFLProcess {
    cmd: CString,
    exec_cmd: String,
    si: Cell<STARTUPINFOA>,
    pi: Cell<PROCESS_INFORMATION>,
    child_pid: DWORD,
    pipe: AFLPipe,
    client_params: String,
    sinkhole_handle: HANDLE,
    wait_time: DWORD,
    timeout: u128,
    drioless: bool,
    dynamorio_dir: String,
    persist_dr_cache: bool,
    is_destroying_when_drop: bool,
    fuzzer_id: String,
    fuzz_iterations: u32,
    fuzz_iterations_count: u32,
    trace_bits: SharedMemory,
}

unsafe impl Send for AFLProcess {}

unsafe impl Sync for AFLProcess {}

impl AFLProcess {
    pub fn new(exec_cmd: String, fuzzer_id: String, client_params: String, drioless: bool, is_sinkhole: bool, dynamorio_dir: String, is_destroying_when_drop: bool, timeout: u128, fuzz_iterations: u32) -> Self {
        let mut ret = Self {
            cmd: Default::default(),
            exec_cmd,
            si: Cell::new(util::zero_initialize()),
            pi: Cell::new(util::zero_initialize()),
            child_pid: 0,
            pipe: AFLPipe::new(fuzzer_id.clone()),
            client_params,
            sinkhole_handle: if is_sinkhole { get_sinkhole().expect("Failed to get a sinkhole.") } else { util::zero_initialize() },
            wait_time: 0,
            timeout,
            drioless,
            dynamorio_dir,
            persist_dr_cache: false,
            is_destroying_when_drop,
            fuzzer_id,
            fuzz_iterations,
            fuzz_iterations_count: 0,
            trace_bits: SharedMemory::new(CString::new("").unwrap(), 0),
        };
        match ret.setup_shm() {
            Ok(()) => {}
            Err(x) => {
                panic!("setup_shm failed! {}", x);
            }
        }
        ret
    }

    fn dispose(&mut self) {
        let _ = WinWrap::close_handle(self.pi.get().hProcess); // Ignore an error
        let _ = WinWrap::close_handle(self.pi.get().hThread);
        self.pi.get_mut().hProcess = ptr::null_mut();
        self.pi.get_mut().hProcess = ptr::null_mut();
    }

    pub fn get_trace_bits(&self) -> &Vec<u8> {
        &self.trace_bits.v
    }

    pub fn get_mut_trace_bits(&mut self) -> &mut Vec<u8> {
        &mut self.trace_bits.v
    }

    fn setup_shm(&mut self) -> FuzzerResult<()> {
        let attempts: u8 = 0;
        while attempts < 5 {
            let shm_str = CString::new(format!("afl_shm_{}", self.fuzzer_id)).unwrap();
            self.trace_bits = SharedMemory::new(shm_str, AFLContext::MAP_SIZE as DWORD);
            match self.trace_bits.create() {
                Ok(_) => { break; }
                Err(OsError(ERROR_ALREADY_EXISTS)) => {
                    panic!("Failed to create a shared memory.");
                    // TODO: Retry.
                    // self.set_fuzzer_id(util::gen_fuzzer_id());
                    // attempts += 1;
                    // continue;
                }
                Err(x) => {
                    warn!("CreateFileMappingA failed. err:{} retry:{}", x, attempts);
                    return Err(FuzzerError::from(x));
                }
            }
        }
        if attempts == 5 {
            return Err(FuzzerError(format!("setup_shm failed: {}", WinWrap::get_last_error())));
        }
        Ok(())
    }

    fn setup_pipe(&mut self) -> FuzzerResult<()> {
        self.pipe.dispose();
        self.pipe.create()
    }

    pub fn write_command_to_pipe(&self, cmd: char) -> FuzzerResult<()> {
        self.pipe.write_command(cmd as u8)
    }

    pub fn read_command_from_pipe(&self, timeout: u128) -> FuzzerResult<char> {
        if !self.is_running()? { return Ok('\0'); }
        let a: u8 = self.pipe.read_command(timeout as u32)?;
        Ok(a as char)
    }

    pub fn overlapped_connect_named_pipe(&mut self) -> FuzzerResult<()> {
        self.pipe.overlapped_connect()
    }

    pub fn create_target_process(&mut self) -> FuzzerResult<()> {
        match self.setup_pipe() {
            Ok(_) => {}
            Err(x) => {
                error!("setup_pipe failed. err: {}", x);
                return Err(x);
            }
        }

        let pidfile = format!("childpid_{}.txt", self.fuzzer_id);
        self.cmd = CString::new(if self.drioless {
            let s = CString::new("AFL_STATIC_CONFIG").unwrap();
            let val = CString::new(format!("{}:{}", self.fuzzer_id, self.fuzz_iterations)).unwrap();
            let _ = WinWrap::set_environment_variableA(s.as_ptr(), val.as_ptr());
            self.exec_cmd.clone()
        } else {
            if self.persist_dr_cache {
                format!("{}\\drrun.exe -pidfile {} -no_follow_children -persist -persistent_dir \"XX\\drcache\" -c winafl.dll {} -fuzzer_id {} -drpersist -- {}",
                        self.dynamorio_dir,
                        pidfile,
                        self.client_params,
                        self.fuzzer_id,
                        self.exec_cmd)
            } else {
                format!("{}\\drrun.exe -pidfile {} -no_follow_children -c winafl.dll {} -fuzzer_id {} -- {}",
                        self.dynamorio_dir,
                        pidfile,
                        self.client_params,
                        self.fuzzer_id,
                        self.exec_cmd)
            }
        }).unwrap();
        self.run_process()?;
        let _ = self.overlapped_connect_named_pipe().or_else(|x| {
            error!("overlapped_connect_named_pipe failed. GLE: {}", x);
            Err(x)
        });
        self.child_pid = if self.drioless {
            self.pi.get().dwProcessId
        } else {
            match util::read_file(&pidfile) {
                Ok(x) => {
                    let s = String::from_utf8(x).expect("Failed to read a PID from the pidfile.");
                    let _ = util::remove_file(&pidfile);
                    s[..s.len() - 2].parse().expect("Failed to read a PID from the pidfile.") // Remove CRLF
                }
                Err(x) => {
                    panic!("Failed to read the pidfile: {}", x.to_string());
                }
            }
        };
        self.fuzz_iterations_count = 0;
        Ok(())
    }

    fn run_process(&mut self) -> FuzzerResult<()> {
        trace!("AFLProcess cmd: {:?}", self.cmd);
        self.si.set(util::zero_initialize());
        self.si.get_mut().cb = size_of::<STARTUPINFOA>() as u32;
        self.pi.set(util::zero_initialize());
        let inherit_handles = if self.sinkhole_handle != ptr::null_mut() {
            self.si.get_mut().hStdOutput = self.sinkhole_handle;
            self.si.get_mut().hStdError = self.sinkhole_handle;
            self.si.get_mut().dwFlags |= STARTF_USESTDHANDLES;
            TRUE
        } else {
            FALSE
        };
        WinWrap::create_process_abb(self.cmd.as_ptr() as *mut i8,
                                    inherit_handles,
                                    self.si.as_ptr() as *mut STARTUPINFOA,
                                    self.pi.as_ptr() as *mut PROCESS_INFORMATION)?;
        let ppi = self.pi.get();
        trace!("AFLProcess child pid: {}", ppi.dwProcessId);
        let _ = WinWrap::resume_thread(ppi.hThread);
        Ok(())
    }

    fn destroy_target_process(&mut self) {
        let _ = self.destroy();
    }
}

impl Target for AFLProcess {
    fn destroy(&mut self) -> FuzzerResult<()> {
        let ppi = self.pi.get();
        if ppi.hProcess == ptr::null_mut() {
            return Ok(());
        }
        if WinWrap::wait_for_single_object(ppi.hProcess, self.wait_time) != Ok(WAIT_TIMEOUT) {
            self.dispose();
            return Ok(());
        }
        if self.drioless {
            let _ = WinWrap::terminate_process(ppi.hProcess, 0);
        } else {
            let mut drconfig_proc = SimpleProcess::new(CString::new(format!("{}\\drconfig.exe -nudge_pid {} 0 1", self.dynamorio_dir, self.child_pid)).unwrap(),
                                                       false,
                                                       false);
            let _ = drconfig_proc.run();
        }

        let still_alive = WinWrap::wait_for_single_object(ppi.hProcess, 2000) == Ok(WAIT_TIMEOUT);

        if still_alive {
            let mut taskkill_proc = SimpleProcess::new(CString::new(format!("taskkill /PID {} /F", self.child_pid)).unwrap(), false, false);
            let _ = taskkill_proc.run();
            match WinWrap::wait_for_single_object(ppi.hProcess, 20000) {
                Ok(WAIT_TIMEOUT) => {
                    error!("Cannot kill child process pid:{}\n", ppi.dwProcessId);
                }
                _ => {}
            };
        }
        self.dispose();
        Ok(())
    }

    fn run(&mut self) -> FuzzerResult<()> {
        self.trace_bits.clear();
        if !self.is_running()? {
            let _ = self.destroy();
            self.create_target_process()?;
            self.fuzz_iterations_count = 0;
        }
        Ok(())
    }

    fn is_running(&self) -> FuzzerResult<bool> {
        let ppi = self.pi.get();
        Ok((ppi.hProcess != ptr::null_mut()) && (WinWrap::wait_for_single_object(ppi.hProcess, 0) == Ok(WAIT_TIMEOUT)))
    }

    fn communicate(&mut self) -> FuzzerResult<ProcessStatus> {
        let result = self.read_command_from_pipe(self.timeout)?; // 'K' or 'P' or 0
        let result = if result == 'K' { self.read_command_from_pipe(self.timeout)? } else { result };
        match result {
            'P' => { /* Success (Do nothing) */ }
            '\0' => {
                self.destroy_target_process();
                return Ok(ProcessStatus::TimeOut);
            }
            x => {
                panic!("Unexpected result from pipe! expected 'P', instead received '{}'", x);
            }
        }

        match self.write_command_to_pipe('F') {
            Err(x) => {
                panic!("write_command_to_pipe 'F' failed: {}", x);
            }
            _ => {}
        }
        let res = self.read_command_from_pipe(self.timeout)?;

        self.fuzz_iterations_count += 1;
        if self.fuzz_iterations_count == self.fuzz_iterations {
            self.wait_time = 2000;
            let _ = self.destroy();
            self.wait_time = 0;
        }

        match res {
            'K' => Ok(ProcessStatus::Finish),
            'C' => {
                let _: DWORD = self.pipe.read_command(self.timeout as u32)?; // TODO: Use WinAFL exception code.
                self.wait_time = 2000;
                let _ = self.destroy_target_process();
                self.wait_time = 0;
                Ok(ProcessStatus::Crash)
            }
            _ => {
                let _ = self.destroy_target_process();
                Ok(ProcessStatus::TimeOut)
            }
        }
    }
}

impl Process for AFLProcess {
    fn set_command(&mut self, cmd: CString) {
        self.cmd = cmd;
    }
}

impl Drop for AFLProcess {
    fn drop(&mut self) {
        if self.is_destroying_when_drop { let _ = self.destroy(); }
        self.dispose();
        let _ = WinWrap::close_handle(self.sinkhole_handle);
    }
}

pub struct AFLPipe {
    id: String,
    handle: HANDLE,
    overlapped: Cell<OVERLAPPED>,
}

impl AFLPipe {
    pub fn new(id: String) -> Self {
        Self { id, handle: util::zero_initialize(), overlapped: Cell::new(util::zero_initialize()) }
    }

    pub fn create(&mut self) -> FuzzerResult<()> {
        let pipe_name = CString::new(format!("\\\\.\\pipe\\afl_pipe_{}", self.id)).unwrap();
        self.handle = WinWrap::create_named_pipe(pipe_name.as_ptr(),
                                                 PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                                 0,
                                                 1,
                                                 512,
                                                 512,
                                                 20000,
                                                 ptr::null_mut())?;
        Ok(())
    }

    pub fn write_command<T: Copy>(&self, val: T) -> FuzzerResult<()> {
        let num_written: Cell<DWORD> = Cell::new(0);
        let cmd: Cell<T> = Cell::new(val);
        WinWrap::write_file(self.handle, cmd.as_ptr() as LPCVOID, size_of::<T>() as u32, num_written.as_ptr() as LPDWORD, self.overlapped.as_ptr() as LPOVERLAPPED)?;
        if num_written.get() != 1 { return Err(FuzzerError("Failed to read a byte from the pipe.".to_string())); }
        Ok(())
    }

    pub fn read_command<T: Copy>(&self, timeout: u32) -> FuzzerResult<T> {
        let num_read: Cell<DWORD> = Cell::new(0);
        let result: Cell<T> = Cell::new(util::zero_initialize());
        match WinWrap::read_file(self.handle, result.as_ptr() as LPVOID, size_of::<T>() as u32, num_read.as_ptr() as LPDWORD, self.overlapped.as_ptr()) {
            Ok(_) | Err(OsError(ERROR_IO_PENDING)) => {
                if WinWrap::wait_for_single_object(self.overlapped.get().hEvent, timeout) != Ok(WAIT_OBJECT_0) {
                    let _ = WinWrap::cancel_io(self.handle); // Ignore an error
                    let _ = WinWrap::wait_for_single_object(self.overlapped.get().hEvent, INFINITE);
                    return Ok(util::zero_initialize());
                }
            }
            _ => {}
        }
        Ok(result.get())
    }
    pub fn overlapped_connect(&mut self) -> FuzzerResult<()> {
        self.overlapped.set(util::zero_initialize());
        self.overlapped.get_mut().hEvent = WinWrap::create_eventA(ptr::null_mut(),
                                                                  TRUE,
                                                                  TRUE,
                                                                  ptr::null_mut())?;
        match WinWrap::connect_named_pipe(self.handle, self.overlapped.as_ptr()) {
            Ok(_) => {
                panic!("Succeeded ConnectNamedPipe unexpectedly");
            }
            Err(OsError(ERROR_IO_PENDING)) => {
                WinWrap::wait_for_single_object(self.overlapped.get().hEvent, INFINITE)?;
                Ok(())
            }
            Err(OsError(ERROR_PIPE_CONNECTED)) => Ok(()),
            Err(x) => Err(FuzzerError(format!("Failed to create pipe: {}", x)))
        }
    }

    pub fn dispose(&mut self) {
        if self.handle != ptr::null_mut() {
            let _ = WinWrap::disconnect_named_pipe(self.handle);
            let _ = WinWrap::close_handle(self.handle);
            let _ = WinWrap::close_handle(self.overlapped.get().hEvent);
            self.handle = ptr::null_mut();
            self.overlapped.get().hEvent = ptr::null_mut();
        }
    }
}

impl Drop for AFLPipe {
    fn drop(&mut self) {
        self.dispose();
    }
}
