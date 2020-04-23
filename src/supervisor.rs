//! Execute and monitor the target, and collect the instrumentation.
extern crate libc;

use actix::{Actor, Message, Handler, Addr, SyncContext, Context, SyncArbiter, System};
use crate::prelude::*;
use std::ffi::CString;
use std::marker::PhantomData;
use crate::util::util::{Target, TargetWatchdog, Process};

#[derive(Copy, Clone, Debug, PartialEq)]
/// Represents a status of a process.
pub enum ProcessStatus {
    /// The process is suspending.
    Suspend,
    /// The process is running.
    Running,
    /// The process exited normally.
    Finish,
    /// The process crashed.
    Crash,
    /// The process didn't exit in time (maybe hang?).
    TimeOut,
}

/// Executes and monitors a target, collects an instrumentation.
pub trait Supervisor: Unpin + 'static
{
    /// Fuzz type
    type Fuzz: Fuzz;
    /// FuzzerContext type
    type FuzzerContext: FuzzerContext;
    /// Executes and monitors the target.
    fn fuzz_one(&mut self, fuzz: &mut Self::Fuzz, ctx: &mut Self::FuzzerContext) -> FuzzerResult<ProcessStatus>;
}

/// Controls a supervisor.
pub trait SupervisorControllerT<T: Supervisor> {
    /// Fuzz once.
    fn exec_fuzzing(&mut self, fuzz: &mut T::Fuzz) -> FuzzerResult<()>;
    /// Receives the fuzz input after fuzzing and returns feedback.
    fn handle_feedback(&mut self, fuzz: T::Fuzz) -> FuzzerResult<()>;
}

/// Multi-thread SupervisorController.
///
/// Runs SupervisorControllers with multi-thread to support parallel fuzzing.
pub trait MTSupervisorControllerT<T: Supervisor>: Actor + Handler<FuzzReadyMes> {}

/// Multi-thread Supervisor Actor.
pub trait MTSupervisorT: Actor<Context=SyncContext<Self>> + Handler<FuzzMes<<<Self as MTSupervisorT>::Supervisor as Supervisor>::Fuzz>> {
    /// Supervisor wrapper.
    type Supervisor: Supervisor;
}

/// Notifies a MTSupervisorController that a supervisor finished current fuzzing and is ready to the next fuzz.
pub struct FuzzReadyMes;

impl Message for FuzzReadyMes { type Result = (); }

/// Sends the next fuzz input to a SupervisorController.
pub struct FuzzMes<T: Fuzz> { pub fuzz: T }

impl<T: Fuzz> Message for FuzzMes<T> { type Result = FuzzerResult<()>; }

/// Contains a fuzz input with an instrumentation after fuzzing.
pub struct FuzzResultMes<T: Fuzz> { pub fuzz: T }

impl<T: Fuzz> Message for FuzzResultMes<T> { type Result = (); }

/// Notifies a SupervisorController address to MTSupervisorController.
pub struct SupervisorInitializeMes<S>
    where
        S: MTSupervisorT,
{
    pub thread_num: usize,
    pub sv_addr: Addr<S>,
}

impl<S> SupervisorInitializeMes<S>
    where
        S: MTSupervisorT,
{
    pub fn new(thread_num: usize, sv_addr: Addr<S>) -> Self {
        Self {
            thread_num,
            sv_addr,
        }
    }
}

impl<S> Message for SupervisorInitializeMes<S>
    where
        S: MTSupervisorT,
{
    type Result = ();
}

/// Passes a fuzz input from command line arguments.
///
/// If the fuzz input contains spaces, the command line argument will be split.
pub struct ArgvSupervisor<F, T>
    where
        F: FuzzerContext + TargetStatus,
        T: Seed,
{
    bin_path: String,
    target: TargetWatchdog<SimpleProcess>,
    phantom: PhantomData<F>,
    phantom2: PhantomData<T>,
}

impl<F, T> ArgvSupervisor<F, T>
    where
        F: FuzzerContext + TargetStatus,
        T: Seed,
{
    /// Creates an ArgvSupervisor.
    ///
    /// This executes bin_path command with a fuzz input.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use magne_flame::supervisor::ArgvSupervisor;
    /// ArgvSupervisor::new("test.exe".to_string(), true, 10000);
    /// ```
    ///
    /// will execute `test.exe {fuzz}`.
    pub fn new(bin_path: String, is_sinkhole: bool, timeout: u128) -> Self {
        Self {
            bin_path: bin_path.trim().to_string(),
            target: TargetWatchdog::new(SimpleProcess::new(CString::new(bin_path).unwrap(), is_sinkhole, true), timeout),
            phantom: PhantomData,
            phantom2: PhantomData,
        }
    }
}

impl<F, T> Supervisor for ArgvSupervisor<F, T>
    where
        T: Seed,
        F: FuzzerContext + TargetStatus,
{
    type Fuzz = SimpleFuzz<T>;
    type FuzzerContext = F;

    fn fuzz_one(&mut self, fuzz: &mut Self::Fuzz, ctx: &mut Self::FuzzerContext) -> FuzzerResult<ProcessStatus> {
        let mut fuzz_cmd: Vec<u8> = self.bin_path.clone().into_bytes();
        fuzz_cmd.append(&mut vec![0x20]); // Insert a space.
        fuzz_cmd.extend(&fuzz.get_mut_fuzz()[..]);
        for (i, val) in fuzz_cmd.iter().enumerate() { // Remove \0.
            if *val == 0 {
                fuzz_cmd.drain(i..);
                break;
            }
        }

        let status = self.target.watch(move |target| {
            target.set_command(CString::new(fuzz_cmd).unwrap());
            target.run()?;
            target.communicate()
        })?;
        ctx.check_target_status(&status);
        Ok(status)
    }
}

/// Fuzzes a target that takes a file path from the command line argument.
pub struct FileArgvSupervisor<F, T>
    where
        F: FuzzerContext + TargetStatus,
        T: Seed,
{
    fuzz_filepath: String,
    target: TargetWatchdog<SimpleProcess>,
    phantom: PhantomData<T>,
    phantom2: PhantomData<F>,
}

impl<F, T> FileArgvSupervisor<F, T>
    where
        F: FuzzerContext + TargetStatus,
        T: Seed,
{
    /// Creates FileArgvSupervisor.
    ///
    /// `@@` in bin_path will be replaced with fuzz filepath.
    /// fuzz filepath is `fuzz_file_prefix + "_" + fuzzer_id + fuzz_file_postfix`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use magne_flame::supervisor::FileArgvSupervisor;
    /// FileArgvSupervisor::new("test.exe /I @@".to_string(), "fuzz".to_string(), ".bin".to_string(), true, 10000);
    /// ```
    /// will execute `test.exe /I fuzz_{random 64bit hex}.bin`.
    pub fn new(bin_path: String, fuzz_file_prefix: String, fuzz_file_postfix: String, is_sinkhole: bool, timeout: u128) -> Self {
        let fuzz_filepath = format!("{}_{}{}", fuzz_file_prefix, util::gen_fuzzer_id(), fuzz_file_postfix);
        debug!("fuzz_filepath: {}", fuzz_filepath);
        let exec_cmd = bin_path.replace("@@", &fuzz_filepath);
        if exec_cmd == bin_path { panic!("Insert @@!!"); }
        let exec_cmd = exec_cmd.trim();
        debug!("exec_cmd: {}", exec_cmd);

        Self {
            fuzz_filepath,
            target: TargetWatchdog::new(SimpleProcess::new(CString::new(exec_cmd).unwrap(), is_sinkhole, true), timeout),
            phantom: PhantomData,
            phantom2: PhantomData,
        }
    }
}

impl<F, T> Supervisor for FileArgvSupervisor<F, T>
    where
        F: FuzzerContext + TargetStatus,
        T: Seed,
{
    type Fuzz = SimpleFuzz<T>;
    type FuzzerContext = F;

    fn fuzz_one(&mut self, fuzz: &mut Self::Fuzz, ctx: &mut Self::FuzzerContext) -> FuzzerResult<ProcessStatus> {
        match util::write_file(&self.fuzz_filepath, &fuzz.get_mut_fuzz()) {
            Ok(_) => {}
            Err(x) => { error!("{}", x.to_string()); }
        }
        let status = self.target.watch(|target| {
            target.run()?;
            target.communicate()
        })?;
        ctx.check_target_status(&status);
        Ok(status)
    }
}

/// Controls a supervisor.
pub struct SupervisorController<T, S>
    where
        T: Supervisor,
        S: Scheduler<T>,
{
    supervisor: T,
    scheduler: Option<S>,
    ctx: T::FuzzerContext,
    svc_addr: Option<Addr<MTSupervisorController<S, T>>>,
}

impl<T, S> SupervisorController<T, S>
    where
        T: Supervisor,
        S: Scheduler<T>,
{
    /// Creates SupervisorController.
    ///
    /// If you want to do single-thread fuzzing, use this.
    pub fn new(supervisor: T, scheduler: S, ctx: T::FuzzerContext) -> Self {
        Self {
            supervisor,
            scheduler: Some(scheduler),
            ctx,
            svc_addr: None,
        }
    }

    /// Creates a SupervisorController and starts fuzzing.
    pub fn setup_and_run<F>(f: F, scheduler: S, ctx: T::FuzzerContext)
        where
            F: Fn() -> T,
            F: Send + Sync + 'static,
    {
        let mut svc = Self::new(f(), scheduler, ctx);
        svc.start_fuzzing();
    }

    fn new_multi(supervisor: T, ctx: T::FuzzerContext, svc_addr: Addr<MTSupervisorController<S, T>>) -> Self {
        Self {
            supervisor,
            scheduler: None,
            ctx,
            svc_addr: Some(svc_addr),
        }
    }
    /// Infinite fuzzing loop for single-thread.
    pub fn start_fuzzing(&mut self) {
        loop {
            let scheduler = self.scheduler.as_mut().expect("Scheduler is None.");
            let mut fuzz = scheduler.get_fuzz(&mut self.ctx).unwrap();
            self.exec_fuzzing(&mut fuzz).unwrap();
            self.handle_feedback(fuzz).unwrap();
        }
    }
}

impl<T, S> SupervisorControllerT<T> for SupervisorController<T, S>
    where
        T: Supervisor,
        S: Scheduler<T>,
{
    fn exec_fuzzing(&mut self, fuzz: &mut T::Fuzz) -> FuzzerResult<()> {
        self.ctx.pre_fuzz_one();
        match self.supervisor.fuzz_one(fuzz, &mut self.ctx) {
            Ok(status) => { fuzz.set_status(status); }
            Err(x) => {
                error!("Failed to fuzz_one: {}", x);
                return Err(x);
            }
        }
        self.ctx.post_fuzz_one();
        Ok(())
    }
    fn handle_feedback(&mut self, fuzz: T::Fuzz) -> FuzzerResult<()> {
        self.scheduler.as_mut().expect("Scheduler is None.").evaluate_fuzz(fuzz, &mut self.ctx);
        Ok(())
    }
}

impl<T, S> MTSupervisorT for SupervisorController<T, S>
    where
        T: Supervisor,
        S: Scheduler<T>,
{ type Supervisor = T; }

impl<T, S> Handler<FuzzMes<T::Fuzz>> for SupervisorController<T, S>
    where
        T: Supervisor,
        S: Scheduler<T>,
{
    type Result = FuzzerResult<()>;

    fn handle(&mut self, msg: FuzzMes<T::Fuzz>, _: &mut Self::Context) -> Self::Result {
        // Starts fuzzing.
        let mut fuzz = msg.fuzz;
        self.exec_fuzzing(&mut fuzz)?;
        let svc_addr = self.svc_addr.as_ref().expect("svc_addr is None.");
        svc_addr.do_send(FuzzResultMes { fuzz });
        svc_addr.do_send(FuzzReadyMes);
        Ok(())
    }
}

impl<T, S> Actor for SupervisorController<T, S>
    where
        T: Supervisor,
        S: Scheduler<T>,
{
    type Context = SyncContext<Self>;

    fn started(&mut self, _: &mut Self::Context) {
        trace!("Supervisor thread: {:?}", std::thread::current().id());
    }
}

/// Supervisor Controller for multi-thread.
pub struct MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor,
{
    sv_addr: Option<Addr<SupervisorController<U, S>>>,
    scheduler: S,
    phantom: PhantomData<U>,
    ctx: U::FuzzerContext,
}

impl<S, U> MTSupervisorControllerT<U> for MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor,
{}

impl<S, U> Actor for MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor,
{ type Context = Context<Self>; }

impl<S, U> MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor,
{
    /// Creates a MTSupervisorController and a SupervisorController, and runs fuzzing.
    pub fn setup_and_run<F>(f: F, scheduler: S, ctx: U::FuzzerContext, thread_num: usize)
        where
            F: Fn() -> U,
            F: Send + Sync + 'static,
    {
        let system = System::new("fuzzer");

        Self::setup(f, scheduler, ctx, thread_num);

        system.run().unwrap();
    }

    /// Creates a MTSupervisorController and a SupervisorController.
    pub fn setup<F>(f: F, scheduler: S, ctx: U::FuzzerContext, thread_num: usize)
        where
            F: Fn() -> U,
            F: Send + Sync + 'static,
    {
        let svc = Self::new(scheduler, ctx.clone()).start();

        let svc2 = svc.clone();
        // Create Supervisors
        let sv_addr = SyncArbiter::start(thread_num, move || {
            SupervisorController::new_multi(
                f(),
                ctx.clone(),
                svc2.clone(),
            )
        });

        svc.do_send(SupervisorInitializeMes::new(thread_num, sv_addr));
    }

    /// Creates a MTSupervisorController.
    pub fn new(scheduler: S, ctx: U::FuzzerContext) -> Self {
        Self {
            sv_addr: None,
            scheduler,
            phantom: PhantomData,
            ctx,
        }
    }

    fn exec_fuzzing(&mut self, fuzz: U::Fuzz) -> FuzzerResult<()> {
        self.sv_addr.as_ref().expect("mt_sv_addr is empty.").do_send(FuzzMes { fuzz });
        Ok(())
    }

    fn handle_feedback(&mut self, fuzz: U::Fuzz) -> FuzzerResult<()> {
        self.scheduler.evaluate_fuzz(fuzz, &mut self.ctx);
        Ok(())
    }
}

impl<S, U> Handler<FuzzReadyMes> for MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor
{
    type Result = ();

    fn handle(&mut self, _: FuzzReadyMes, _: &mut Self::Context) -> Self::Result {
        let fuzz = self.scheduler.get_fuzz(&mut self.ctx).unwrap();
        self.exec_fuzzing(fuzz).unwrap();
    }
}

impl<S, U> Handler<FuzzResultMes<U::Fuzz>> for MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor
{
    type Result = ();

    fn handle(&mut self, mes: FuzzResultMes<U::Fuzz>, _: &mut Self::Context) -> Self::Result {
        self.handle_feedback(mes.fuzz).unwrap();
    }
}

impl<S, U> Handler<SupervisorInitializeMes<SupervisorController<U, S>>> for MTSupervisorController<S, U>
    where
        S: Scheduler<U>,
        U: Supervisor,
{
    type Result = ();

    fn handle(&mut self, msg: SupervisorInitializeMes<SupervisorController<U, S>>, _: &mut Self::Context) -> Self::Result {
        // Initialize
        for _ in 0..msg.thread_num * 2 { // Send fuzz inputs
            let c = self.scheduler.get_fuzz(&mut self.ctx).unwrap();
            msg.sv_addr.do_send(FuzzMes { fuzz: c });
        }
        self.sv_addr = Some(msg.sv_addr);
    }
}
