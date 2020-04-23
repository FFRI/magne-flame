use crate::mutator::AFLMutationStrategy;
use magne_flame::prelude::*;
use std::cell::{Cell, RefCell, Ref, RefMut};
use std::io::{stdout, BufWriter, Write};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::supervisor::AFLSupervisor;

#[derive(Clone)]
pub struct AFLStats {
    pub start_time: Instant,
    pub total_execs: u64,
    pub queued_favored: u32,
    pub pending_favored: u32,
    pub pending_not_fuzzed: u32,
    pub queued_paths: u32,
    pub queued_variable: u32,
    pub queued_with_cov: u32,
    pub queued_discovered: u32,
    pub cur_entry_id: String,
    pub cur_favored: bool,
    pub cur_depth: u32,
    pub cur_bitmap_size: u32,
    pub virgin_bits: Arc<Mutex<Vec<u8>>>,
    pub max_depth: u32,
    pub var_byte_count: u32,
    pub total_crashes: u32,
    pub unique_crashes: u32,
    pub total_tmouts: u32,
    pub unique_tmouts: u32,
    pub last_path_time: Instant,
    pub last_crash_time: Instant,
    pub last_tmout_time: Instant,
    pub queue_cycle: u32,
    pub total_cal_us: u128,
    pub total_cal_cycles: u32,
    pub total_bitmap_size: u32,
    pub total_bitmap_entries: u32,
    pub stage_name: String,
    pub stage_max: u32,
    pub now_trying: String,
}

impl AFLStats {
    pub fn new(virgin_bits: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            start_time: Instant::now(),
            total_execs: 0,
            queued_favored: 0,
            pending_favored: 0,
            pending_not_fuzzed: 0,
            queued_paths: 0,
            queued_variable: 0,
            queued_with_cov: 0,
            queued_discovered: 0,
            cur_entry_id: "".to_string(),
            cur_favored: false,
            cur_depth: 0,
            cur_bitmap_size: 0,
            virgin_bits,
            max_depth: 0,
            var_byte_count: 0,
            total_crashes: 0,
            unique_crashes: 0,
            total_tmouts: 0,
            unique_tmouts: 0,
            last_path_time: Instant::now(),
            last_crash_time: Instant::now(),
            last_tmout_time: Instant::now(),
            queue_cycle: 0,
            total_cal_us: 0,
            total_cal_cycles: 0,
            total_bitmap_size: 0,
            total_bitmap_entries: 0,
            stage_name: "".to_string(),
            stage_max: 0,
            now_trying: "".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct AFLContext {
    pub stats: Arc<Mutex<AFLStats>>,
    pub out_dir: String,
}

impl FuzzerContext for AFLContext {}

impl AFLContext {
    pub const MAP_SIZE_POW2: usize = 16;
    pub const MAP_SIZE: usize = (1 << Self::MAP_SIZE_POW2);
    pub fn new(virgin_bits: Arc<Mutex<Vec<u8>>>, out_dir: String) -> Self {
        Self { stats: Arc::new(Mutex::new(AFLStats::new(virgin_bits))), out_dir }
    }

    pub fn write_bitmap(out_dir: impl AsRef<str>, bits: &Vec<u8>) {
        let _ = util::write_file(&format!("{}\\fuzz_bitmap", out_dir.as_ref()), bits);
    }

    /*
    pub fn read_bitmap(out_dir: impl AsRef<str>) -> Vec<u8> {
        let x = util::read_file(&format!("{}\\fuzz_bitmap", out_dir.as_ref())).unwrap();
        x
    }
    */

    pub fn start_reporter<T: Reporter>(&self, reporter: T) {
        let stats = self.stats.clone();

        let out_dir = self.out_dir.clone();
        Reporter::start(reporter, move |_| {
            let s = stats.lock().unwrap();
            let (t_bits, t_bytes) = {
                let vb = s.virgin_bits.lock().unwrap();
                Self::write_bitmap(&out_dir, &*vb);
                ((Self::MAP_SIZE << 3) - Self::count_bits(&*vb), Self::count_non_255_bytes(&*vb))
            };
            let t_byte_ratio = t_bytes as f64 * 100.0 / Self::MAP_SIZE as f64;
            let elapsed = s.start_time.elapsed().as_secs();
            let queued_paths = if s.queued_paths == 0 { 1 } else { s.queued_paths };
            let out = stdout();
            let mut out = BufWriter::new(out.lock());
            let cur_entry_id = if s.cur_entry_id.len() <= 18 { &s.cur_entry_id } else { &s.cur_entry_id[s.cur_entry_id.len() - 18..] };
            writeln!(out, "+-------------------------------------------------------------------------------+").unwrap();
            writeln!(out, "|                                 AFL on MagneFlame                             |").unwrap();
            writeln!(out, "+- process timing --------------------------------------+- overall results -----+").unwrap();
            writeln!(out, "|         run time : {:>5} sec                          |  cycles done : {:>5}  |", elapsed, s.queue_cycle).unwrap();
            writeln!(out, "|    last new path : {:>5} sec                          |  total paths : {:>5}  |", s.last_path_time.elapsed().as_secs(), queued_paths).unwrap();
            writeln!(out, "|  last uniq crash : {:>5} sec                          | uniq crashes : {:>5}  |", s.last_crash_time.elapsed().as_secs(), s.unique_crashes).unwrap();
            writeln!(out, "|   last uniq hang : {:>5} sec                          |   uniq hangs : {:>5}  |", s.last_tmout_time.elapsed().as_secs(), s.unique_tmouts).unwrap();
            writeln!(out, "+- cycle progress ---------------------+- map coverage -+-----------------------+").unwrap();
            writeln!(out, "|  now processing : {:>18}{}|     map density : {:>6.02}% / {:>6.02}%    |", cur_entry_id, if s.cur_favored { "*" } else { " " }, s.cur_bitmap_size as f64 * 100.0 / Self::MAP_SIZE as f64, t_byte_ratio).unwrap();
            writeln!(out, "|                                      |  count coverage :{:>7.02} bits/tuple    |", if t_bytes != 0 { t_bits as f64 / t_bytes as f64 } else { 0.0 }).unwrap();
            writeln!(out, "+- stage progress ---------------------+- finding in depth ---------------------+").unwrap();
            writeln!(out, "|   now trying : {:<22}|  favored paths : {:>5} <{:>6.02}%>       |", s.now_trying, s.queued_favored, s.queued_favored as f32 * (100 / queued_paths) as f32).unwrap();
            writeln!(out, "|                                      |   new edges on : {:>5} <{:>6.02}%>       |", s.queued_with_cov, s.queued_with_cov as f32 * (100 / queued_paths) as f32).unwrap();
            writeln!(out, "|  total execs : {:>5}                 |  total crashes : {:>5} <{:>5} unique>  |", s.total_execs, s.total_crashes, s.unique_crashes).unwrap();
            writeln!(out, "|   exec speed : {:>9.02}/sec         |   total tmouts : {:>5} <{:>5} unique>  |", s.total_execs as f64 / elapsed as f64, s.total_tmouts, s.unique_tmouts).unwrap();
            writeln!(out, "+-------------------------------------------------------------------------------+").unwrap();
        });
    }

    fn count_non_255_bytes(bits: &Vec<u8>) -> usize {
        let ret = bits.iter().fold(0, |sum, x| sum + if *x != 0xFF { 1 } else { 0 });
        ret
    }

    fn count_bits(bits: &Vec<u8>) -> usize {
        let ret: usize = bits.iter().fold(0, |sum, x| sum + x.count_ones() as usize);
        ret
    }
}

pub struct AFLScheduler {
    top_rated: Vec<Option<Rc<RefCell<<AFLSupervisor as Supervisor>::Fuzz>>>>,
    queue: Vec<Rc<RefCell<<AFLSupervisor as Supervisor>::Fuzz>>>,
    evacuation: Rc<RefCell<<AFLSupervisor as Supervisor>::Fuzz>>,
    score_changed: bool,
    file_id: Cell<usize>,
    crash_file_id: Cell<usize>,
    hang_file_id: Cell<usize>,
    idx: usize,
    out_dir: String,
    queue_cycle: usize,
    mutation_strategy: AFLMutationStrategy,
    pub is_saved: bool,
}

impl AFLScheduler {
    pub fn set_out_dir(&mut self, out_dir: String) {
        self.out_dir = out_dir;
    }

    fn gen_file_path(&self) -> String {
        let ret = format!("queue\\id_{:>05}", self.file_id.get());
        self.file_id.set(self.file_id.get() + 1);
        ret
    }

    fn gen_crash_file_path(&self) -> String {
        let ret = format!("crashes\\id_{:>05}", self.crash_file_id.get());
        self.crash_file_id.set(self.crash_file_id.get() + 1);
        ret
    }

    fn gen_hang_file_path(&self) -> String {
        let ret = format!("hangs\\id_{:>05}", self.hang_file_id.get());
        self.hang_file_id.set(self.hang_file_id.get() + 1);
        ret
    }
}

impl AFLScheduler {
    const SKIP_TO_NEW_PROB: f64 = 0.99;
    const SKIP_NFAV_OLD_PROB: f64 = 0.95;
    const SKIP_NFAV_NEW_PROB: f64 = 0.75;

    pub fn new() -> Self {
        Self {
            top_rated: vec![None; AFLContext::MAP_SIZE],
            queue: Vec::new(),
            evacuation: Rc::new(RefCell::new(<AFLSupervisor as Supervisor>::Fuzz::from(vec![]))),
            score_changed: false,
            file_id: Cell::new(0),
            crash_file_id: Cell::new(0),
            hang_file_id: Cell::new(0),
            idx: 0,
            out_dir: "".to_string(),
            queue_cycle: 1,
            mutation_strategy: AFLMutationStrategy::new(),
            is_saved: true,
        }
    }

    fn front(&self) -> Ref<<AFLSupervisor as Supervisor>::Fuzz> {
        match self.queue.get(self.idx) {
            Some(fuzz) => fuzz.borrow(),
            None => self.evacuation.borrow(),
        }
    }

    fn front_mut(&mut self) -> RefMut<<AFLSupervisor as Supervisor>::Fuzz> {
        match self.queue.get(self.idx) {
            Some(fuzz) => fuzz.borrow_mut(),
            None => self.evacuation.borrow_mut(),
        }
    }

    fn next(&mut self, ctx: &mut AFLContext) {
        self.idx += 1;
        if self.queue.len() <= self.idx {
            self.idx = 0;
            self.queue_cycle += 1;
            self.mutation_strategy.queue_cycle = self.queue_cycle;
            ctx.stats.lock().unwrap().queue_cycle += 1;
        }
    }

    pub fn check_fuzz(&mut self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> bool {
        // Use current fuzz?
        let (queued_paths, pending_favored) = {
            let s = ctx.stats.lock().unwrap();
            (s.queued_paths, s.pending_favored)
        };
        let buf = self.front();
        if pending_favored != 0 {
            if (buf.was_fuzzed() || !buf.is_favored()) && util::gen_bool(Self::SKIP_TO_NEW_PROB) { return false; }
        } else if !buf.is_favored() && queued_paths > 10 {
            if self.queue_cycle > 1 && !buf.was_fuzzed() {
                if util::gen_bool(Self::SKIP_NFAV_NEW_PROB) { return false; }
            } else {
                if util::gen_bool(Self::SKIP_NFAV_OLD_PROB) { return false; }
            }
        }
        true
    }

    pub fn enqueue_fuzz(&mut self, seed: Rc<RefCell<<AFLSupervisor as Supervisor>::Fuzz>>, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) {
        let status = seed.borrow().get_status();
        seed.borrow_mut().set_id(match status {
            ProcessStatus::Crash => self.gen_crash_file_path(),
            ProcessStatus::TimeOut => self.gen_hang_file_path(),
            _ => self.gen_file_path(),
        });
        if self.is_saved { seed.borrow_mut().store().unwrap(); }
        let mut s = ctx.stats.lock().unwrap();
        match status {
            ProcessStatus::Crash => {
                s.last_crash_time = Instant::now();
            }
            ProcessStatus::TimeOut => {
                s.last_tmout_time = Instant::now();
            }
            _ => {
                self.queue.push(seed.clone());
                self.mutation_strategy.queue.push(seed);
                s.queued_paths = self.queue.len() as u32;
                s.pending_not_fuzzed += 1;
                s.last_path_time = Instant::now();
            }
        }
    }

    pub fn cull_queue(&mut self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) {
        if !self.score_changed { return; }
        self.score_changed = false;
        let mut temp_v: Vec<u8> = vec![255; AFLContext::MAP_SIZE >> 3];
        let mut c = ctx.stats.lock().unwrap();
        c.queued_favored = 0;
        c.pending_favored = 0;
        for k in self.queue.iter() {
            k.borrow_mut().set_favored(false);
        }
        for i in 0..AFLContext::MAP_SIZE {
            match &self.top_rated[i] {
                Some(x) => {
                    let mut x = x.borrow_mut();

                    if (temp_v[i >> 3] & (1 << (i & 7) as u8) as u8) != 0 {
                        let x_trace_mini = x.get_trace_mini();
                        for j in (0..temp_v.len()).rev() {
                            if x_trace_mini[j] != 0 {
                                temp_v[j] &= !(x_trace_mini[j]);
                            }
                        }
                        x.set_favored(true);
                        c.queued_favored += 1;
                        if !x.was_fuzzed() { c.pending_favored += 1; }
                    }
                }
                None => {}
            }
        }
    }

    pub fn update_bitmap_score(&mut self, fuzz: Rc<RefCell<<AFLSupervisor as Supervisor>::Fuzz>>) {
        let mut challenger = fuzz.borrow_mut();
        let fav_factor = challenger.get_fav_factor();
        for i in 0..AFLContext::MAP_SIZE {
            let now = challenger.get_trace_bits()[i];
            if now != 0 {
                match &self.top_rated[i] {
                    Some(top) => {
                        let ptr = top.clone();
                        let mut top = ptr.borrow_mut();
                        if fav_factor > top.get_fav_factor() { continue; }
                        // Update top_rated[i]
                        let new_tc_ref = top.get_tc_ref() - 1;
                        top.set_tc_ref(new_tc_ref);
                        if top.get_tc_ref() == 0 { top.set_trace_mini(&vec![]); }
                    }
                    _ => {}
                }

                if challenger.get_trace_mini().len() == 0 {
                    challenger.set_trace_mini_from_bits();
                }
                let new_tc_ref = challenger.get_tc_ref() + 1;
                challenger.set_tc_ref(new_tc_ref);
                self.top_rated[i] = Some(fuzz.clone());
                self.score_changed = true;
            }
        }
        challenger.set_trace_bits(vec![]);
    }

    fn check_dry_run(&mut self) -> Option<<AFLSupervisor as Supervisor>::Fuzz> {
        let buf = self.front();
        if buf.is_instrumented() { return None; }
        let z = buf.clone();
        Some(z)
    }

    pub fn add_raw_fuzz(&mut self, seed: Vec<u8>, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) {
        let fuzz = <AFLSupervisor as Supervisor>::Fuzz::from(seed);
        self.enqueue_fuzz(Rc::new(RefCell::new(fuzz)), ctx);
    }
}

impl Scheduler<AFLSupervisor> for AFLScheduler {
    fn evaluate_fuzz(&mut self, seed: <AFLSupervisor as Supervisor>::Fuzz, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) {
        if seed.is_valuable() {
            let status = seed.get_status();
            let seed = Rc::new(RefCell::new(seed));
            match status {
                ProcessStatus::TimeOut | ProcessStatus::Crash => {}
                _ => { self.update_bitmap_score(seed.clone()); }
            }
            self.enqueue_fuzz(seed, ctx);
        }
    }

    fn get_fuzz(&mut self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> FuzzerResult<<AFLSupervisor as Supervisor>::Fuzz> {
        match self.check_dry_run() {
            Some(x) => {
                // Perform dry run
                match self.queue.get(self.idx) {
                    Some(f) => {
                        self.evacuation = f.clone();
                        self.queue.remove(self.idx);
                        self.mutation_strategy.queue.remove(self.idx);
                        ctx.stats.lock().unwrap().queued_paths = self.queue.len() as u32;
                    }
                    None => {}
                }
                return Ok(x);
            }
            None => {}
        }

        loop {
            let mut z = self.front_mut().clone();
            match self.mutation_strategy.mutate(&mut z, ctx) {
                Ok(_) => { return Ok(z); }
                Err(_) => {
                    loop {
                        if !self.front_mut().was_fuzzed() {
                            self.front_mut().set_fuzzed(true);
                            let is_favored = self.front_mut().is_favored();

                            let mut s = ctx.stats.lock().unwrap();
                            s.pending_not_fuzzed -= 1;
                            if is_favored { s.pending_favored -= 1; }
                        }

                        self.next(ctx);
                        self.cull_queue(ctx);
                        if self.check_fuzz(ctx) {
                            let mut s = ctx.stats.lock().unwrap();
                            let x = self.front();
                            s.cur_entry_id = x.get_id().clone();
                            s.cur_favored = x.get_favored();
                            s.cur_bitmap_size = x.get_bitmap_size();
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct AFLInstrument {
    pub exec_us: u128,
    pub has_new_bits: bool,
    pub has_new_cov: bool,
    pub handicap: u32,
    pub depth: u32,
    pub bitmap_size: u32,
    pub cksum: u32,
    pub ctx: AFLContext,
}

impl AFLInstrument {
    pub fn calculate_score(&mut self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> i32 {
        const HAVOC_MAX_MULT: i32 = 16;
        let stats = ctx.stats.lock().unwrap();
        let avg_exec_us = stats.total_cal_us / stats.total_cal_cycles as u128;
        let avg_bitmap_size = stats.total_bitmap_size / stats.total_bitmap_entries;

        let mut perf_score: f32 = if self.exec_us / 10 > avg_exec_us { 10 } else if self.exec_us / 4 > avg_exec_us { 25 } else if self.exec_us / 2 > avg_exec_us { 50 } else if self.exec_us * 3 / 4 > avg_exec_us { 75 } else if self.exec_us * 4 < avg_exec_us { 300 } else if self.exec_us * 3 < avg_exec_us { 200 } else if self.exec_us * 2 < avg_exec_us { 150 } else { 100 } as f32;
        perf_score *= if self.bitmap_size * 3 / 10 > avg_bitmap_size { 3.0 } else if self.bitmap_size / 2 > avg_bitmap_size { 2.0 } else if self.bitmap_size * 3 / 4 > avg_bitmap_size { 1.5 } else if self.bitmap_size * 3 < avg_bitmap_size { 0.25 } else if self.bitmap_size * 2 < avg_bitmap_size { 0.5 } else if self.bitmap_size * 3 / 2 < avg_bitmap_size { 0.75 } else { 1.0 } as f32;

        if self.handicap >= 4 {
            perf_score *= 4 as f32;
            self.handicap -= 4;
        } else if self.handicap != 0 {
            perf_score *= 2 as f32;
            self.handicap -= 1;
        }
        if self.depth >= 4 {
            perf_score = if self.depth < 8 { 2 } else if self.depth < 14 { 3 } else if self.depth < 26 { 4 } else { 5 } as f32;
        }
        if perf_score > (HAVOC_MAX_MULT * 100) as f32 { perf_score = (HAVOC_MAX_MULT * 100) as f32; }
        perf_score as i32
    }

    pub fn count_bitmap_size(trace_bits: &Vec<u8>) -> u32 {
        let k = trace_bits.iter().fold(0, |sum, x| {
            if x & 0xFF > 0 { sum + 1 } else { sum }
        });
        k
    }
}

impl Instrument for AFLInstrument {}

pub struct AFLFuzz {
    seed: FileSeed,
    fuzz: Vec<u8>,
    status: ProcessStatus,
    instrument: Option<AFLInstrument>,
    pub favored: bool,
    was_fuzzed: bool,
    pub trace_mini: Vec<u8>,
    pub trace_bits: Vec<u8>,
    pub tc_ref: usize,
}

impl AFLFuzz {
    fn minimize_bits(src: &Vec<u8>) -> Vec<u8> {
        if src.len() == 0 { return vec![]; }
        let mut ret = vec![0; src.len() >> 3];
        for i in 0..src.len() {
            if src[i] != 0 {
                ret[i >> 3] |= (1 << (i & 7)) as u8;
            }
        }
        ret
    }
}

impl Clone for AFLFuzz {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
            fuzz: self.fuzz.clone(),
            status: ProcessStatus::Suspend,
            instrument: self.instrument.clone(),
            favored: self.favored,
            was_fuzzed: self.was_fuzzed,
            trace_mini: vec![],
            trace_bits: vec![],
            tc_ref: self.tc_ref,
        }
    }
}

pub trait AFLFuzzT: Fuzz + InstrumentedFuzz {
    fn calculate_score(&mut self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> i32;
    fn was_fuzzed(&self) -> bool;
    fn is_favored(&self) -> bool;
    fn set_fuzzed(&mut self, fuzzed: bool);
    fn get_fav_factor(&self) -> u128;
    fn get_trace_mini(&self) -> &Vec<u8>;
    fn set_trace_mini(&mut self, trace_bits: &Vec<u8>);
    fn set_trace_mini_from_bits(&mut self);
    fn get_trace_bits(&self) -> &Vec<u8>;
    fn set_trace_bits(&mut self, trace_bits: Vec<u8>);
    fn set_favored(&mut self, favored: bool);
    fn get_favored(&self) -> bool;
    fn get_bitmap_size(&self) -> u32;
    fn get_tc_ref(&self) -> usize;
    fn set_tc_ref(&mut self, tc_ref: usize);
}

impl AFLFuzzT for AFLFuzz {
    fn calculate_score(&mut self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> i32 {
        match &mut self.instrument {
            Some(inst) => inst.calculate_score(ctx),
            None => 10000000,
        }
    }

    fn was_fuzzed(&self) -> bool { self.was_fuzzed }

    fn is_favored(&self) -> bool { self.favored }

    fn set_fuzzed(&mut self, fuzzed: bool) { self.was_fuzzed = fuzzed; }

    fn get_fav_factor(&self) -> u128 {
        self.get_instrument().unwrap().exec_us * self.fuzz.len() as u128
    }

    fn get_trace_mini(&self) -> &Vec<u8> { &self.trace_mini }

    fn set_trace_mini(&mut self, trace_bits: &Vec<u8>) { self.trace_mini = Self::minimize_bits(trace_bits); }

    fn set_trace_mini_from_bits(&mut self) { self.trace_mini = Self::minimize_bits(&self.trace_bits); }

    fn get_trace_bits(&self) -> &Vec<u8> { &self.trace_bits }

    fn set_trace_bits(&mut self, trace_bits: Vec<u8>) { self.trace_bits = trace_bits; }

    fn set_favored(&mut self, favored: bool) { self.favored = favored; }

    fn get_favored(&self) -> bool { self.favored }

    fn get_bitmap_size(&self) -> u32 { self.get_instrument().unwrap().bitmap_size }

    fn get_tc_ref(&self) -> usize { self.tc_ref }

    fn set_tc_ref(&mut self, tc_ref: usize) { self.tc_ref = tc_ref; }
}

impl From<Vec<u8>> for AFLFuzz {
    fn from(fuzz: Vec<u8>) -> Self {
        Self {
            seed: FileSeed::default(),
            fuzz,
            status: ProcessStatus::Suspend,
            instrument: None,
            favored: false,
            was_fuzzed: false,
            trace_mini: vec![],
            trace_bits: vec![],
            tc_ref: 0,
        }
    }
}

impl InstrumentedFuzz for AFLFuzz {
    type Instrument = AFLInstrument;

    fn is_valuable(&self) -> bool {
        match self.get_instrument() {
            Some(inst) => inst.has_new_bits,
            None => false,
        }
    }

    fn set_instrument(&mut self, instrument: Self::Instrument) {
        self.instrument = Some(instrument);
    }

    fn get_instrument(&self) -> Option<&Self::Instrument> {
        match &self.instrument {
            Some(x) => Some(x),
            None => None,
        }
    }

    fn get_mut_instrument(&mut self) -> Option<&mut Self::Instrument> {
        match &mut self.instrument {
            Some(x) => Some(x),
            None => None,
        }
    }

    fn is_instrumented(&self) -> bool { self.instrument.is_some() }
}

impl Fuzz for AFLFuzz {
    fn get_mut_fuzz(&mut self) -> &mut Vec<u8> { &mut self.fuzz }

    fn get_fuzz(&self) -> &Vec<u8> { &self.fuzz }

    fn store(&self) -> FuzzerResult<()> { self.seed.store(&self.fuzz) }

    fn get_id(&self) -> &String { self.seed.get_id() }

    fn set_id(&mut self, id: String) { self.seed.set_id(id); }

    fn get_status(&self) -> ProcessStatus { self.status }

    fn set_status(&mut self, status: ProcessStatus) { self.status = status; }
}
