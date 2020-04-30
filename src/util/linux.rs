//! Linux version is under construction now. Sorry!
#[doc(hidden)]
use crate::prelude::*;
use nix::errno::errno;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::sys::wait::*;
use nix::unistd::*;
use std::ffi::CString;
use std::os::raw::c_int;
use crate::util::util::Target;

/// Gets /dev/null fd.
pub fn get_sinkhole() -> Result<c_int, u32> {
    let s = "/dev/null";
    let fd = nix::fcntl::open(s, OFlag::O_RDWR, Mode::S_IWUSR).unwrap();
    if fd < 0 { return Err(errno() as u32); }
    Ok(fd)
}

/// Simple Process.
///
/// This does not work currently.
pub struct SimpleProcess {
    sinkhole_handle: c_int,
    is_destroying_when_drop: bool,
    child_pid: Pid,
    status: ProcessStatus,
    pub cmd: CString,
}

unsafe impl Send for SimpleProcess {}

unsafe impl Sync for SimpleProcess {}

impl SimpleProcess {
    pub fn new(cmd: CString, is_sinkhole: bool, is_destroying_when_drop: bool) -> Self {
        Self {
            cmd,
            sinkhole_handle: if is_sinkhole { Util::get_sinkhole().unwrap() } else { 0 },
            is_destroying_when_drop,
            child_pid: Pid::this(),
            status: ProcessStatus::Finish,
        }
    }

    pub fn is_running(&self) -> Result<bool, u32> {}

    pub fn destroy(&mut self) {
        self.dispose();
    }

    fn dispose(&mut self) {
        let _ = close(self.sinkhole_handle);
    }

    pub fn wait(&mut self) -> FuzzerResult<ProcessStatus> {
        trace!("child pid: {:?}", self.child_pid);
        self.status = match waitpid(self.child_pid, Some(WaitPidFlag::WEXITED)).expect("waitpid failed") {
            WaitStatus::Exited(_, _) => ProcessStatus::Finish,
            WaitStatus::Signaled(_, _, _) => ProcessStatus::Crash,
            _ => ProcessStatus::Crash,
        };
        Ok(self.status)
    }

    pub fn get_status(&self) -> FuzzerResult<ProcessStatus> {
        Ok(self.status)
    }
}

impl Drop for SimpleProcess {
    fn drop(&mut self) {
        if self.is_destroying_when_drop { self.destroy(); }
        self.dispose();
    }
}

impl Target for SimpleProcess {
    fn run(&mut self) -> FuzzerResult<()> {
        match fork().expect("fork failed") {
            ForkResult::Parent { child } => {
                self.child_pid = child;
                self.status = ProcessStatus::Running;
                self.wait()?;
            }
            ForkResult::Child => {
                trace!("Linux cmd: {:?}", self.cmd);
                let mut args: Vec<CString> = vec![];
                let c = self.cmd.clone().into_bytes();
                for x in &mut c.split(|x| *x == 0x20) {
                    args.push(CString::new(x).unwrap());
                }
            }
        }
        Ok(())
    }

    fn is_running(&self) -> FuzzerResult<bool> {
        match self.status {
            ProcessStatus::Running => Ok(true),
            _ => Ok(false)
        }
    }

    fn destroy(&mut self) -> FuzzerResult<()> {
        self.dispose()
    }

    fn communicate(&mut self) -> FuzzerResult<ProcessStatus> {
        self.wait()
    }
}
