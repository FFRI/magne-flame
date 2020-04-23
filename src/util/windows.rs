//! Windows-intrinsic utilities
use crate::prelude::*;
use std::cell::Cell;
use std::ffi::CString;
use std::ptr;
use winapi::_core::mem::size_of;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{BOOL, DWORD, LPDWORD, LPCVOID, LPVOID, UINT, TRUE, FALSE};
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{WriteFile, ReadFile, CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::ioapiset::CancelIo;
use winapi::um::jobapi2::{SetInformationJobObject, AssignProcessToJobObject};
use winapi::um::memoryapi::{UnmapViewOfFile, MapViewOfFile, FILE_MAP_ALL_ACCESS};
use winapi::um::minwinbase::{LPOVERLAPPED, LPSECURITY_ATTRIBUTES};
use winapi::um::namedpipeapi::{ConnectNamedPipe, DisconnectNamedPipe};
use winapi::um::processenv::SetEnvironmentVariableA;
use winapi::um::processthreadsapi::{CreateProcessA, LPSTARTUPINFOA, LPPROCESS_INFORMATION, GetExitCodeProcess, TerminateProcess, ResumeThread};
use winapi::um::processthreadsapi::{STARTUPINFOA, PROCESS_INFORMATION};
use winapi::um::synchapi::{CreateEventA, WaitForSingleObject};
use winapi::um::winbase::{CreateNamedPipeA, WAIT_FAILED, CreateFileMappingA, INFINITE, STARTF_USESTDHANDLES, CreateJobObjectA};
use winapi::um::winnt::{HANDLE, LPCSTR, LPSTR, GENERIC_WRITE, GENERIC_READ, FILE_SHARE_WRITE, FILE_SHARE_READ, PAGE_READWRITE, JOBOBJECTINFOCLASS};
use crate::fuzzer::OsError;
use crate::util::util::{Target, Process};

/// Gets a nul handle.
pub fn get_sinkhole() -> OsResult<HANDLE> {
    let n = CString::new("nul").unwrap();
    WinWrap::create_fileA(
        n.as_ptr() as *const i8,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        ptr::null_mut(),
        OPEN_EXISTING,
        0,
        ptr::null_mut())
}

/// Represents a shared memory wrapper.
pub struct SharedMemory {
    pub name: CString,
    handle: HANDLE,
    pub v: Vec<u8>,
    map_size: DWORD,
}

impl SharedMemory {
    /// Creates SharedMemory object.
    pub fn new(name: CString, map_size: DWORD) -> Self {
        Self {
            name,
            handle: util::zero_initialize(),
            v: vec![],
            map_size,
        }
    }

    /// Zero clears the shared memory.
    pub fn clear(&mut self) {
        for x in &mut self.v { *x = 0; }
    }

    /// Creates and maps a shared memory.
    pub fn create(&mut self) -> OsResult<()> {
        self.handle = WinWrap::create_file_mappingA(INVALID_HANDLE_VALUE,
                                                    ptr::null_mut(),
                                                    PAGE_READWRITE,
                                                    0,
                                                    self.map_size,
                                                    self.name.as_ptr())?;

        let p = WinWrap::map_view_of_file(self.handle,
                                          FILE_MAP_ALL_ACCESS,
                                          0,
                                          0,
                                          self.map_size as usize)?;
        unsafe {
            self.v = Vec::from_raw_parts(p as *mut u8, self.map_size as usize, self.map_size as usize);
        }
        Ok(())
    }

    pub fn dispose(&mut self) -> FuzzerResult<()> {
        if self.handle != ptr::null_mut() {
            let _ = WinWrap::unmap_view_of_file(self.v.as_ptr() as *const c_void);
            let _ = WinWrap::close_handle(self.handle);
            self.handle = ptr::null_mut();
        }
        Ok(())
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        let _ = self.dispose();
    }
}

/// Represents a Simple process executor and monitor.
///
/// Creates and runs a process each time, and waits for it to terminate.
pub struct SimpleProcess {
    si: Cell<STARTUPINFOA>,
    pi: Cell<PROCESS_INFORMATION>,
    sinkhole_handle: HANDLE,
    is_destroying_when_drop: bool,
    cmd: CString,
}

unsafe impl Send for SimpleProcess {}

unsafe impl Sync for SimpleProcess {}

impl SimpleProcess {
    /// Creates a process object.
    pub fn new(cmd: CString, is_sinkhole: bool, is_destroying_when_drop: bool) -> Self {
        Self {
            si: Cell::new(util::zero_initialize()),
            pi: Cell::new(util::zero_initialize()),
            cmd,
            sinkhole_handle: if is_sinkhole { get_sinkhole().expect("Failed to get a sinkhole.") } else { util::zero_initialize() },
            is_destroying_when_drop,
        }
    }

    /// Disposes handles.
    fn dispose(&mut self) {
        let _ = WinWrap::close_handle(self.pi.get().hProcess); // Ignore an error
        let _ = WinWrap::close_handle(self.pi.get().hThread);
        self.pi.get_mut().hProcess = ptr::null_mut();
        self.pi.get_mut().hThread = ptr::null_mut();
    }

    /// Waits for the process to terminate.
    fn wait(&self) -> FuzzerResult<()> {
        WinWrap::wait_for_single_object(self.pi.get().hProcess, INFINITE)?;
        Ok(())
    }

    /// Gets the process status.
    fn get_status(&self) -> FuzzerResult<ProcessStatus> {
        let exit_code: Cell<DWORD> = Cell::new(0);
        if self.is_running() == Ok(true) { return Ok(ProcessStatus::Running); }
        let _ = WinWrap::get_exit_code_process(self.pi.get().hProcess, exit_code.as_ptr() as LPDWORD); // Ignore an error
        if exit_code.get() >= 0x100 { return Ok(ProcessStatus::Crash); }
        Ok(ProcessStatus::Finish)
    }
}

impl Target for SimpleProcess {
    /// Executes a command and create a process.
    fn run(&mut self) -> FuzzerResult<()> {
        trace!("cmd: {:?}", self.cmd);
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
        let _ = WinWrap::resume_thread(ppi.hThread);
        Ok(())
    }

    /// Is the process still alive?
    fn is_running(&self) -> FuzzerResult<bool> {
        let ppi = self.pi.get();
        Ok((ppi.hProcess != ptr::null_mut()) && (WinWrap::wait_for_single_object(ppi.hProcess, 0) == Ok(WAIT_TIMEOUT)))
    }

    /// Destroys the process.
    fn destroy(&mut self) -> FuzzerResult<()> {
        let _ = WinWrap::terminate_process(self.pi.get().hProcess, 0); // Ignore an error
        self.dispose();
        Ok(())
    }

    /// Waits for the process to terminate.
    fn communicate(&mut self) -> FuzzerResult<ProcessStatus> {
        self.wait()?;
        self.get_status()
    }
}

impl Process for SimpleProcess {
    /// Sets a command.
    fn set_command(&mut self, cmd: CString) {
        self.cmd = cmd;
    }
}

impl Drop for SimpleProcess {
    fn drop(&mut self) {
        if self.is_destroying_when_drop { let _ = self.destroy(); }
        self.dispose();
        let _ = WinWrap::close_handle(self.sinkhole_handle);
    }
}

/// WinAPI Wrapper.
pub struct WinWrap {}

impl WinWrap {
    pub fn get_last_error() -> DWORD {
        unsafe { GetLastError() }
    }

    #[allow(non_snake_case)]
    pub fn create_fileA(lpFileName: LPCSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttributes: LPSECURITY_ATTRIBUTES, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: HANDLE) -> OsResult<HANDLE> {
        unsafe {
            let file_handle = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            if file_handle == INVALID_HANDLE_VALUE {
                return Err(OsError(Self::get_last_error()));
            }
            Ok(file_handle)
        }
    }
    #[allow(non_snake_case)]
    pub fn create_named_pipe(lpName: LPCSTR, dwOpenMode: DWORD, dwPipeMode: DWORD, nMaxInstances: DWORD, nOutBufferSize: DWORD, nInBufferSize: DWORD, nDefaultTimeOut: DWORD, lpSecurityAttributes: LPSECURITY_ATTRIBUTES) -> OsResult<HANDLE> {
        unsafe {
            let pipe_handle = CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
            if pipe_handle == INVALID_HANDLE_VALUE {
                return Err(OsError(Self::get_last_error()));
            }
            Ok(pipe_handle)
        }
    }

    #[allow(non_snake_case)]
    pub fn create_eventA(lpEventAttributes: LPSECURITY_ATTRIBUTES, bManualReset: BOOL, bInitialState: BOOL, lpName: LPCSTR) -> OsResult<HANDLE> {
        unsafe {
            let handle = CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
            if handle == ptr::null_mut() {
                return Err(OsError(Self::get_last_error()));
            }
            Ok(handle)
        }
    }

    #[allow(non_snake_case)]
    pub fn connect_named_pipe(hNamedPipe: HANDLE, lpOverlapped: LPOVERLAPPED) -> OsResult<()> {
        unsafe {
            match ConnectNamedPipe(hNamedPipe, lpOverlapped) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn disconnect_named_pipe(hNamedPipe: HANDLE) -> OsResult<()> {
        unsafe {
            match DisconnectNamedPipe(hNamedPipe) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn wait_for_single_object(hHandle: HANDLE, dwMilliseconds: DWORD) -> OsResult<DWORD> {
        unsafe {
            match WaitForSingleObject(hHandle, dwMilliseconds) {
                WAIT_FAILED => Err(OsError(Self::get_last_error())),
                g => Ok(g)
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn close_handle(hHandle: HANDLE) -> OsResult<()> {
        unsafe {
            match CloseHandle(hHandle) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn get_exit_code_process(hProcess: HANDLE, exit_code: LPDWORD) -> OsResult<()> {
        unsafe {
            match GetExitCodeProcess(hProcess, exit_code) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn create_process(lpApplicationName: LPCSTR, lpCommandLine: LPSTR, lpProcessAttributes: LPSECURITY_ATTRIBUTES, lpThreadAttributes: LPSECURITY_ATTRIBUTES, bInheritHandles: BOOL, dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCSTR, lpStartupInfo: LPSTARTUPINFOA, lpProcessInformation: LPPROCESS_INFORMATION) -> OsResult<()> {
        unsafe {
            match CreateProcessA(lpApplicationName,
                                 lpCommandLine,
                                 lpProcessAttributes,
                                 lpThreadAttributes,
                                 bInheritHandles,
                                 dwCreationFlags,
                                 lpEnvironment,
                                 lpCurrentDirectory,
                                 lpStartupInfo,
                                 lpProcessInformation,
            ) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn resume_thread(hThread: HANDLE) -> OsResult<DWORD> {
        unsafe {
            match ResumeThread(hThread) {
                std::u32::MAX => Err(OsError(Self::get_last_error())),
                b => Ok(b)
            }
        }
    }

    pub fn create_process_abb(cmd: LPSTR, inherit_handles: i32, si: LPSTARTUPINFOA, pi: LPPROCESS_INFORMATION) -> OsResult<()> {
        Self::create_process(ptr::null_mut(),
                             cmd,
                             ptr::null_mut(),
                             ptr::null_mut(),
                             inherit_handles,
                             0,
                             ptr::null_mut(),
                             ptr::null_mut(),
                             si,
                             pi,
        )
    }

    #[allow(non_snake_case)]
    pub fn terminate_process(hProcess: HANDLE, uExitCode: UINT) -> OsResult<()> {
        unsafe {
            match TerminateProcess(hProcess, uExitCode) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn write_file(hFile: HANDLE, lpBuffer: LPCVOID, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: LPDWORD, lpOverlapped: LPOVERLAPPED) -> OsResult<()> {
        unsafe {
            match WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn read_file(hFile: HANDLE, lpBuffer: LPVOID, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: LPDWORD, lpOverlapped: LPOVERLAPPED) -> OsResult<()> {
        unsafe {
            match ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn cancel_io(hFile: HANDLE) -> OsResult<()> {
        unsafe {
            match CancelIo(hFile) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn create_file_mappingA(hFile: HANDLE, lpAttributes: LPSECURITY_ATTRIBUTES, flProtect: DWORD, dwMaximumSizeHigh: DWORD, dwMaximumSizeLow: DWORD, lpName: LPCSTR,
    ) -> OsResult<HANDLE> {
        unsafe {
            let handle = CreateFileMappingA(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
            if handle == ptr::null_mut() {
                return Err(OsError(Self::get_last_error()));
            }
            Ok(handle)
        }
    }

    #[allow(non_snake_case)]
    pub fn map_view_of_file(hFileMappingObject: HANDLE, dwDesiredAccess: DWORD, dwFileOffsetHigh: DWORD, dwFileOffsetLow: DWORD, dwNumberOfBytesToMap: SIZE_T) -> OsResult<LPVOID> {
        unsafe {
            let e = MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
            if e == ptr::null_mut() {
                return Err(OsError(Self::get_last_error()));
            }
            Ok(e)
        }
    }

    #[allow(non_snake_case)]
    pub fn unmap_view_of_file(lpBaseAddress: LPCVOID) -> OsResult<()> {
        unsafe {
            match UnmapViewOfFile(lpBaseAddress) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn create_job_object(lpJobAttributes: LPSECURITY_ATTRIBUTES, lpName: LPCSTR) -> OsResult<HANDLE> {
        unsafe {
            let handle = CreateJobObjectA(lpJobAttributes, lpName);
            if handle == ptr::null_mut() { return Err(OsError(Self::get_last_error())); }
            Ok(handle)
        }
    }
    #[allow(non_snake_case)]
    pub fn set_information_job_object(hJob: HANDLE, JobObjectInformationClass: JOBOBJECTINFOCLASS, lpJobObjectInformation: LPVOID, cbJovObjectInformationLength: DWORD) -> OsResult<()> {
        unsafe {
            match SetInformationJobObject(hJob, JobObjectInformationClass, lpJobObjectInformation, cbJovObjectInformationLength) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(()),
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn assign_process_to_job_object(hJob: HANDLE, hProcess: HANDLE) -> OsResult<()> {
        unsafe {
            match AssignProcessToJobObject(hJob, hProcess) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(()),
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn set_environment_variableA(lpName: LPCSTR, lpValue: LPCSTR) -> OsResult<()> {
        unsafe {
            match SetEnvironmentVariableA(lpName, lpValue) {
                0 => Err(OsError(Self::get_last_error())),
                _ => Ok(()),
            }
        }
    }
}
