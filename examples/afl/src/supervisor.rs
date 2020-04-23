use crate::scheduler::{AFLInstrument, AFLFuzz, AFLContext};
use crate::afl_util::AFLProcess;
use magne_flame::prelude::*;
use std::sync::{Mutex, Arc};
use std::time::Instant;
use magne_flame::util::util::{Target, TargetWatchdog};

pub struct AFLSupervisor {
    fuzz_filepath: String,
    process_status: ProcessStatus,
    proc: TargetWatchdog<AFLProcess>,
    virgin_bits: Arc<Mutex<Vec<u8>>>,
    virgin_crash: Arc<Mutex<Vec<u8>>>,
    virgin_tmout: Arc<Mutex<Vec<u8>>>,
}

impl AFLSupervisor {
    pub const HASH_CONST: u32 = 0xa5b35705;
    #[allow(non_snake_case)]
    pub fn new(mut exec_cmd: String, out_dir: String, dynamorio_dir: String, client_params: String, fuzz_iterations: u32, timeout: u128, virgin_bits: Arc<Mutex<Vec<u8>>>, virgin_crash: Arc<Mutex<Vec<u8>>>, virgin_tmout: Arc<Mutex<Vec<u8>>>) -> Self {
        let fuzzer_id = util::gen_fuzzer_id();

        let fuzz_filepath = format!("{}\\.cur_input_{}", out_dir, fuzzer_id);
        exec_cmd = exec_cmd.replace("@@", &fuzz_filepath);
        let proc = TargetWatchdog::new(
            AFLProcess::new(exec_cmd, fuzzer_id.clone(), client_params, false, true, dynamorio_dir.clone(), true, timeout, fuzz_iterations),
            timeout);

        Self {
            fuzz_filepath,
            process_status: ProcessStatus::Suspend,
            proc,
            virgin_bits,
            virgin_crash,
            virgin_tmout,
        }
    }

    fn has_new_bits(virgin_bits: Arc<Mutex<Vec<u8>>>, trace_bits: &Vec<u8>) -> FuzzerResult<u8> {
        let mut ret: u8 = 0;
        let v = virgin_bits.clone();
        let mut virgin_bits = v.lock().unwrap();
        for i in 0..AFLContext::MAP_SIZE {
            if trace_bits[i] != 0 && ((trace_bits[i] & virgin_bits[i]) != 0) {
                if ret < 2 {
                    ret = if trace_bits[i] != 0 && virgin_bits[i] == 0xff { 2 } else { 1 };
                }
                virgin_bits[i] &= !trace_bits[i];
            }
        }
        Ok(ret)
    }

    pub fn u8vec_to_u32(v: &Vec<u8>, pos: usize) -> u32 {
        // Little-endian.
        let mut k = v[pos + 3] as u32;
        k <<= 8;
        k += v[pos + 2] as u32;
        k <<= 8;
        k += v[pos + 1] as u32;
        k <<= 8;
        k += v[pos] as u32;
        k
    }

    pub fn rol32(x: u32, r: u32) -> u32 {
        (x << r) | (x >> (32 - r))
    }

    pub fn hash32(key: &Vec<u8>, seed: u32) -> u32 {
        let mut h1 = seed ^ (key.len() as u32);
        let mut i = 0;
        while i < key.len() - 3 {
            let mut k1 = Self::u8vec_to_u32(&key, i);
            i = i.wrapping_add(4);
            k1 = k1.wrapping_mul(0xcc9e2d51);
            k1 = Self::rol32(k1, 15);
            k1 = k1.wrapping_mul(0x1b873593);

            h1 ^= k1;
            h1 = Self::rol32(h1, 13);
            h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
        }
        h1 ^= h1 >> 16;
        h1 = h1.wrapping_mul(0x85ebca6b);
        h1 ^= h1 >> 13;
        h1 = h1.wrapping_mul(0xc2b2ae35);
        h1 ^= h1 >> 16;
        h1
    }

    pub fn calibrate_case(&mut self, fuzz: &mut <Self as Supervisor>::Fuzz, handicap: u32, ctx: &mut <Self as Supervisor>::FuzzerContext) -> FuzzerResult<()> {
        trace!("calibrate_case");
        const CAL_CYCLES: u32 = 8;
        const CAL_CYCLES_LONG: u32 = 40;
        let mut i = 0;
        let mut stage_max = CAL_CYCLES;
        let start_time = Instant::now();
        let mut first_cksum: u32 = 0;
        let mut new_bits = 0;
        let mut var_bytes: Vec<u8> = vec![0; AFLContext::MAP_SIZE];
        let mut first_trace: Vec<u8> = vec![0; AFLContext::MAP_SIZE];
        while i < stage_max {
            self.fuzz_process(fuzz.get_fuzz())?;
            let trace_bits = self.proc.get_trace_bits();

            let cksum = Self::hash32(trace_bits, Self::HASH_CONST);
            if first_cksum != cksum {
                let hnb = Self::has_new_bits(self.virgin_bits.clone(), trace_bits)?;
                new_bits = if hnb > new_bits { hnb } else { new_bits };
                if first_cksum != 0 {
                    for i in 0..AFLContext::MAP_SIZE {
                        if var_bytes[i] == 0 && first_trace[i] != trace_bits[i] {
                            var_bytes[i] = 1;
                            stage_max = CAL_CYCLES_LONG;
                            trace!("calibrate_case cycles changed: {}", CAL_CYCLES_LONG);
                        }
                    }
                } else {
                    // First time.
                    first_cksum = cksum;
                    first_trace = trace_bits.clone();
                }
            }
            i += 1;
        }
        let depth = {
            match fuzz.get_instrument() {
                Some(inst) => inst.depth,
                None => 0,
            }
        };
        let elapsed_time = start_time.elapsed();
        let avg_exec_us = elapsed_time.as_micros() / stage_max as u128;
        let bitmap_size = AFLInstrument::count_bitmap_size(self.proc.get_trace_bits());
        {
            let mut s = ctx.stats.lock().unwrap();
            s.total_bitmap_size += bitmap_size;
            s.total_bitmap_entries += 1;
            s.total_cal_us += elapsed_time.as_micros();
            s.total_cal_cycles += stage_max;
            let has_new_cov = if new_bits == 2 {
                s.queued_with_cov += 1;
                true
            } else { false };
            fuzz.trace_bits = self.proc.get_trace_bits().clone();
            fuzz.set_instrument(AFLInstrument {
                exec_us: avg_exec_us,
                has_new_bits: true,
                has_new_cov,
                handicap,
                depth,
                cksum: first_cksum,
                bitmap_size,
                ctx: ctx.clone(),
            });
        }
        Ok(())
    }

    fn next_p2(val: usize) -> usize {
        let mut ret: usize = 1;
        while val > ret { ret <<= 1; }
        ret
    }

    pub fn fuzz_with_gap(fuzz: &Vec<u8>, skip_at: usize, skip_len: usize) -> Vec<u8> {
        let mut ret: Vec<u8> = vec![];
        ret.extend(&fuzz[..skip_at]);
        ret.extend(&fuzz[skip_at + skip_len..]);
        ret
    }

    pub fn trim_case(&mut self, fuzz: &mut <Self as Supervisor>::Fuzz) -> FuzzerResult<()> {
        const TRIM_START_STEPS: usize = 16;
        const TRIM_MIN_BYTES: usize = 4;
        const TRIM_END_STEPS: usize = 1024;
        trace!("trim_case");
        let first_cksum = fuzz.get_instrument().unwrap().cksum;
        let f = fuzz.get_mut_fuzz();
        if f.len() < 5 { return Ok(()); }
        let mut needs_write = false;
        let mut clean_trace: Vec<u8> = vec![0; AFLContext::MAP_SIZE];
        let mut len_p2 = Self::next_p2(f.len());
        let mut remove_len = std::cmp::max(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);
        while remove_len >= std::cmp::max(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES) {
            let mut remove_pos = remove_len;
            while remove_pos < f.len() {
                let trim_avail: usize = std::cmp::min(remove_len, f.len() - remove_pos);
                let trimmed_fuzz = Self::fuzz_with_gap(f, remove_pos, trim_avail);
                self.fuzz_process(&trimmed_fuzz)?;
                let trace_bits = self.proc.get_trace_bits();

                let cksum = Self::hash32(trace_bits, Self::HASH_CONST);
                if first_cksum == cksum {
                    *f = trimmed_fuzz;
                    len_p2 = Self::next_p2(f.len());
                    if !needs_write {
                        needs_write = true;
                        clean_trace = trace_bits.clone();
                    }
                } else { remove_pos += remove_len; }
            }
            remove_len >>= 1;
        }

        if needs_write {
            match fuzz.store() {
                Ok(_) => {}
                Err(x) => { error!("Failed to fuzz.save: {}", x.to_string()); }
            }
            let trace_bits = self.proc.get_mut_trace_bits();
            for i in 0..AFLContext::MAP_SIZE { trace_bits[i] = clean_trace[i]; }
        }
        Ok(())
    }

    pub fn fuzz_process(&mut self, fuzz: &Vec<u8>) -> FuzzerResult<ProcessStatus> {
        let fuzz_filepath = &mut self.fuzz_filepath;
        let process_status = self.proc.watch(move |target| {
            target.run()?;
            match util::write_file(&fuzz_filepath, fuzz) {
                Ok(_) => {}
                Err(x) => {
                    error!("could not write {}: {}", fuzz_filepath, x.to_string());
                }
            }
            target.communicate()
        })?;
        self.process_status = process_status;
        Ok(process_status)
    }

    /// Removes hit counts.
    fn simplify_trace(mem: &mut Vec<u8>) {
        const SIMPLIFY_LOOKUP: [u8; 256] = [128; 256];
        mem[0] = 0x01;
        for e in mem.iter_mut().skip(1) {
            *e = if *e != 0 { SIMPLIFY_LOOKUP[*e as usize] } else { 0x01 };
        }
    }

    pub fn is_unique_crash(&mut self, ctx: &mut <Self as Supervisor>::FuzzerContext) -> FuzzerResult<bool> {
        let mut s = ctx.stats.lock().unwrap();
        s.total_crashes += 1;
        Self::simplify_trace(self.proc.get_mut_trace_bits());
        if Self::has_new_bits(self.virgin_crash.clone(), &self.proc.get_trace_bits())? == 0 {
            return Ok(false);
        }
        s.unique_crashes += 1;
        s.last_crash_time = Instant::now();
        Ok(true)
    }

    pub fn is_unique_timeout(&mut self, _fuzz: &mut <Self as Supervisor>::Fuzz, ctx: &mut <Self as Supervisor>::FuzzerContext) -> FuzzerResult<bool> {
        let mut s = ctx.stats.lock().unwrap();
        s.total_tmouts += 1;
        Self::simplify_trace(self.proc.get_mut_trace_bits());
        if Self::has_new_bits(self.virgin_tmout.clone(), self.proc.get_trace_bits())? == 0 {
            return Ok(false);
        }
        s.unique_tmouts += 1;
        s.last_tmout_time = Instant::now();
        Ok(true)
    }

    fn run(&mut self, fuzz: &mut <Self as Supervisor>::Fuzz, ctx: &mut <Self as Supervisor>::FuzzerContext) -> FuzzerResult<()> {
        ctx.stats.lock().unwrap().total_execs += 1;
        let status = self.fuzz_process(fuzz.get_fuzz())?;
        fuzz.set_status(status);
        Ok(())
    }

    fn get_target_status(&self) -> FuzzerResult<ProcessStatus> {
        Ok(self.process_status)
    }

    fn instrument_fuzz(fuzz: &mut <Self as Supervisor>::Fuzz, trace_bits: Vec<u8>, has_new_bits: bool, ctx: AFLContext) {
        match fuzz.get_mut_instrument() {
            Some(inst) => { inst.has_new_bits = has_new_bits; }
            None => {
                fuzz.trace_bits = trace_bits;
                fuzz.set_instrument(AFLInstrument {
                    exec_us: 0,
                    has_new_bits,
                    has_new_cov: false,
                    handicap: 1,
                    depth: 0,
                    cksum: 0,
                    bitmap_size: 0,
                    ctx,
                });
            }
        }
    }
}

impl Supervisor for AFLSupervisor {
    type Fuzz = AFLFuzz;
    type FuzzerContext = AFLContext;
    fn fuzz_one(&mut self, fuzz: &mut Self::Fuzz, ctx: &mut Self::FuzzerContext) -> FuzzerResult<ProcessStatus> {
        self.run(fuzz, ctx)?;
        let status = self.get_target_status().unwrap();
        match status {
            ProcessStatus::Crash => {
                let hnb = self.is_unique_crash(ctx)?;
                Self::has_new_bits(self.virgin_bits.clone(), self.proc.get_trace_bits()).unwrap();
                Self::instrument_fuzz(fuzz, self.proc.get_trace_bits().clone(), hnb, ctx.clone());
                return Ok(status);
            }
            ProcessStatus::TimeOut => {
                let hnb = self.is_unique_timeout(fuzz, ctx)?;
                Self::has_new_bits(self.virgin_bits.clone(), self.proc.get_trace_bits()).unwrap();
                Self::instrument_fuzz(fuzz, self.proc.get_trace_bits().clone(), hnb, ctx.clone());
                return Ok(status);
            }
            _ => {}
        }
        let hnb = Self::has_new_bits(self.virgin_bits.clone(), self.proc.get_trace_bits()).unwrap();
        if hnb > 0 {
            let mut handicap = ctx.stats.lock().unwrap().queue_cycle;
            if handicap > 0 { handicap -= 1; }
            let is_instrumented = fuzz.is_instrumented();
            self.calibrate_case(fuzz, handicap, ctx)?;
            if is_instrumented { self.trim_case(fuzz)?; }
        } else {
            Self::instrument_fuzz(fuzz, self.proc.get_trace_bits().clone(), false, ctx.clone());
        }
        Ok(status)
    }
}
