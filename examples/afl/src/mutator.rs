use crate::scheduler::AFLFuzzT;
use magne_flame::prelude::*;
use std::time::Instant;
use std::rc::Rc;
use std::cell::RefCell;
use crate::supervisor::AFLSupervisor;

#[derive(Debug)]
/// Mutation Phase.
enum Phase {
    BitFlip1(usize),
    BitFlip2(usize),
    BitFlip4(usize),
    BitFlip8(usize),
    BitFlip16(usize),
    BitFlip32(usize),
    Arith8(usize, i32),
    Arith16(usize, i32),
    Arith32(usize, i32),
    Interest8(usize, usize),
    Interest16(usize, usize),
    Interest32(usize, usize),
    Havoc(usize),
    Splice(usize, usize),
    Printable(usize, usize),
}

enum SpliceResult {
    RetrySplicing,
    DoNothing,
}

pub struct AFLMutationStrategy {
    phase: Phase,
    pub queue_cycle: usize,
    pub skip_deterministic: bool,
    pub is_skipped_deterministic: bool,
    run_over10m: bool,
    start_time: Instant,
    stage_max: usize,
    pub queue: Vec<Rc<RefCell<<AFLSupervisor as Supervisor>::Fuzz>>>,
    splice_buf: Option<<AFLSupervisor as Supervisor>::Fuzz>,
}

impl AFLMutationStrategy {
    const ARITH_MAX: i32 = 35;
    const INTERESTING_8: [i8; 9] = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
    const INTERESTING_16: [i16; 10] = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767];
    const INTERESTING_32: [i32; 8] = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647];
    const HAVOC_BLK_SMALL: usize = 32;
    const HAVOC_BLK_MEDIUM: usize = 128;
    const HAVOC_BLK_LARGE: usize = 1500;
    const HAVOC_BLK_XL: usize = 32768;
    const HAVOC_STACK_POW2: usize = 7;
    const MAX_FILE: usize = 1 * 1024 * 1024;
    pub fn new() -> Self {
        Self {
            phase: Phase::BitFlip1(0),
            queue: Vec::new(),
            queue_cycle: 1,
            skip_deterministic: false,
            is_skipped_deterministic: false,
            run_over10m: false,
            stage_max: 0,
            start_time: Instant::now(),
            splice_buf: None,
        }
    }

    fn splice_random_fuzz(&mut self, fuzz: &mut <AFLSupervisor as Supervisor>::Fuzz) -> Result<Vec<u8>, SpliceResult> {
        if fuzz.get_fuzz().len() <= 1 { return Err(SpliceResult::DoNothing); }
        if self.queue.len() <= 1 { return Err(SpliceResult::DoNothing); }
        let mut tid = util::gen_random(0, self.queue.len());
        loop {
            match self.queue.get(tid) {
                Some(x) => {
                    let mut x = x.borrow_mut();

                    if (fuzz as *mut <AFLSupervisor as Supervisor>::Fuzz) != (&mut *x as *mut <AFLSupervisor as Supervisor>::Fuzz) && x.get_fuzz().len() >= 2 { break; }
                    tid += 1;
                }
                None => { return Err(SpliceResult::RetrySplicing); }
            }
        }
        let target = &mut *self.queue.get(tid).unwrap().borrow_mut();

        match Self::satisfy(fuzz, target) {
            Ok(diff) => {
                let (f_diff, l_diff) = diff;
                let mut target = target.get_fuzz().clone();
                let split_at = util::gen_random(f_diff, l_diff);
                target.splice(0..split_at, fuzz.get_fuzz().iter().cloned());
                Ok(target)
            }
            Err(x) => { Err(x) }
        }
    }

    fn satisfy(orig: &mut <AFLSupervisor as Supervisor>::Fuzz, target: &mut <AFLSupervisor as Supervisor>::Fuzz) -> Result<(usize, usize), SpliceResult> {
        if (orig as *mut <AFLSupervisor as Supervisor>::Fuzz) == (target as *mut <AFLSupervisor as Supervisor>::Fuzz) { return Err(SpliceResult::RetrySplicing); }
        let target = target.get_fuzz();
        if target.len() < 2 { return Err(SpliceResult::RetrySplicing); }
        if orig.get_fuzz().len() <= 1 { return Err(SpliceResult::DoNothing); }
        let (f_diff, l_diff) = Self::locate_diffs(orig.get_fuzz(), target);
        if f_diff.is_none() { return Err(SpliceResult::RetrySplicing); }
        let (f_diff, l_diff) = (f_diff.unwrap(), l_diff.unwrap());
        if l_diff < 2 || f_diff == l_diff { return Err(SpliceResult::RetrySplicing); }
        Ok((f_diff, l_diff))
    }

    fn locate_diffs(v1: &Vec<u8>, v2: &Vec<u8>) -> (Option<usize>, Option<usize>) {
        let len = std::cmp::min(v1.len(), v2.len());
        let mut f_loc = None;
        let mut l_loc = None;
        for pos in 0..len {
            if v1[pos] != v2[pos] {
                if f_loc.is_none() { f_loc = Some(pos); }
                l_loc = Some(pos);
            }
        }
        (f_loc, l_loc)
    }

    fn get_havoc_div(&self, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> usize {
        let s = ctx.stats.lock().unwrap();
        let avg_us = if s.total_cal_cycles != 0 { s.total_cal_us / s.total_cal_cycles as u128 } else { 0 };
        let havoc_div = if avg_us > 50000 { 10 } else if avg_us > 20000 { 5 } else if avg_us > 10000 { 2 } else { 1 };
        havoc_div
    }

    pub fn splice(&mut self, seed: &mut <AFLSupervisor as Supervisor>::Fuzz, splice_cycle: &mut usize, havoc_cycle: &mut usize) -> Result<(), u32> {
        const SPLICE_CYCLES: usize = 15;
        if *havoc_cycle == 0 {
            while *splice_cycle < SPLICE_CYCLES {
                *splice_cycle += 1;
                match self.exec_splice(seed) {
                    Ok(_) => { break; }
                    Err(SpliceResult::DoNothing) => {
                        *splice_cycle = SPLICE_CYCLES;
                        return Err(2);
                    }
                    Err(SpliceResult::RetrySplicing) => {}
                }
            }
        }
        if *splice_cycle >= SPLICE_CYCLES { return Err(2); }
        match &self.splice_buf {
            Some(x) => { *seed = x.clone(); }
            None => {}
        }

        match self.havoc(seed, *havoc_cycle) {
            Ok(_) => { Ok(()) }
            Err(_) => { Err(1) }
        }
    }

    pub fn get_havoc_stage_max(&self, seed: &mut <AFLSupervisor as Supervisor>::Fuzz, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> usize {
        const HAVOC_MIN: usize = 16;
        const HAVOC_CYCLES_INIT: usize = 1024;
        const HAVOC_CYCLES: usize = 256;
        let mut stage_max: usize = if seed.was_fuzzed() { HAVOC_CYCLES_INIT } else { HAVOC_CYCLES } * seed.calculate_score(ctx) as usize / self.get_havoc_div(ctx) / 100;

        if stage_max < HAVOC_MIN { stage_max = HAVOC_MIN; }
        stage_max
    }

    pub fn get_splice_stage_max(&self, seed: &mut <AFLSupervisor as Supervisor>::Fuzz, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> usize {
        const HAVOC_MIN: usize = 16;
        const SPLICE_HAVOC: usize = 32;
        let mut stage_max: usize = SPLICE_HAVOC * seed.calculate_score(ctx) as usize / self.get_havoc_div(ctx) / 100;
        if stage_max < HAVOC_MIN { stage_max = HAVOC_MIN; }
        stage_max
    }

    pub fn havoc(&mut self, seed: &mut <AFLSupervisor as Supervisor>::Fuzz, now: usize) -> Result<(), u32> {
        if now == self.stage_max { return Err(1); } // Done?
        let use_stacking = 1 << (1 + util::gen_random(0, Self::HAVOC_STACK_POW2));
        for _ in 0..use_stacking {
            let o = util::gen_random(0, 15);
            self.exec_havoc(seed.get_mut_fuzz(), o);
        }
        Ok(())
    }

    pub fn exec_havoc(&mut self, seed: &mut Vec<u8>, o: usize) {
        match o {
            0 => { BitFlip::mutate(seed, util::gen_random(0, seed.len() * 8)).unwrap(); }
            1 => {
                let pos = util::gen_random(0, seed.len());
                let cpos: usize = util::gen_random(0, Self::INTERESTING_8.len());
                ReplaceByte::mutate(seed, pos, Self::INTERESTING_8[cpos] as u8).unwrap();
            }
            2 => {
                if seed.len() < 2 { return; }
                let pos = util::gen_random(0, seed.len() - 1);
                let cpos: usize = util::gen_random(0, Self::INTERESTING_16.len());
                if util::gen_bool(0.5) {
                    ReplaceByte::mutate(seed, pos, Self::INTERESTING_16[cpos] as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 1, (Self::INTERESTING_16[cpos] >> 8) as u8).unwrap();
                } else {
                    ReplaceByte::mutate(seed, pos, (Self::INTERESTING_16[cpos] >> 8) as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 1, Self::INTERESTING_16[cpos] as u8).unwrap();
                }
            }
            3 => {
                if seed.len() < 4 { return; }
                let pos = util::gen_random(0, seed.len() - 3);
                let cpos: usize = util::gen_random(0, Self::INTERESTING_32.len());
                if util::gen_bool(0.5) {
                    ReplaceByte::mutate(seed, pos, Self::INTERESTING_32[cpos] as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 1, (Self::INTERESTING_32[cpos] >> 8) as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 2, (Self::INTERESTING_32[cpos] >> 16) as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 3, (Self::INTERESTING_32[cpos] >> 24) as u8).unwrap();
                } else {
                    ReplaceByte::mutate(seed, pos, (Self::INTERESTING_32[cpos] >> 16) as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 1, (Self::INTERESTING_32[cpos] >> 24) as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 2, Self::INTERESTING_32[cpos] as u8).unwrap();
                    ReplaceByte::mutate(seed, pos + 3, (Self::INTERESTING_32[cpos] >> 8) as u8).unwrap();
                }
            }
            4 => {
                let pos = util::gen_random(0, seed.len());
                ArithmeticSub::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u8).unwrap();
            }
            5 => {
                let pos = util::gen_random(0, seed.len());
                ArithmeticAdd::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u8).unwrap();
            }
            6 => {
                if seed.len() < 2 { return; }
                let pos = util::gen_random(0, seed.len() - 1);
                if util::gen_bool(0.5) {
                    ArithmeticSub::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u16).unwrap();
                } else {
                    SwapByte::mutate(seed, pos, pos + 1).unwrap();
                    ArithmeticSub::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u16).unwrap();
                    SwapByte::mutate(seed, pos, pos + 1).unwrap();
                }
            }
            7 => {
                if seed.len() < 2 { return; }
                let pos = util::gen_random(0, seed.len() - 1);
                if util::gen_bool(0.5) {
                    ArithmeticAdd::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u16).unwrap();
                } else {
                    SwapByte::mutate(seed, pos, pos + 1).unwrap();
                    ArithmeticAdd::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u16).unwrap();
                    SwapByte::mutate(seed, pos, pos + 1).unwrap();
                }
            }
            8 => {
                if seed.len() < 4 { return; }
                let pos = util::gen_random(0, seed.len() - 3);
                if util::gen_bool(0.5) {
                    ArithmeticSub::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u32).unwrap();
                } else {
                    SwapByte::mutate(seed, pos, pos + 3).unwrap();
                    SwapByte::mutate(seed, pos + 1, pos + 2).unwrap();
                    ArithmeticSub::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u32).unwrap();
                    SwapByte::mutate(seed, pos, pos + 3).unwrap();
                    SwapByte::mutate(seed, pos + 1, pos + 2).unwrap();
                }
            }
            9 => {
                if seed.len() < 4 { return; }
                let pos = util::gen_random(0, seed.len() - 3);
                if util::gen_bool(0.5) {
                    ArithmeticAdd::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u32).unwrap();
                } else {
                    SwapByte::mutate(seed, pos, pos + 3).unwrap();
                    SwapByte::mutate(seed, pos + 1, pos + 2).unwrap();
                    ArithmeticAdd::mutate(seed, pos, 1 + util::gen_random(0, Self::ARITH_MAX as usize) as u32).unwrap();
                    SwapByte::mutate(seed, pos, pos + 3).unwrap();
                    SwapByte::mutate(seed, pos + 1, pos + 2).unwrap();
                }
            }
            10 => {
                let pos = util::gen_random(0, seed.len());
                ReplaceByte::mutate(seed, pos, seed[pos] ^ ((util::gen_random(0, 256) as u8).wrapping_add(1))).unwrap();
            }
            11 | 12 => {
                if seed.len() < 2 { return; }
                // 11 and 12 is the same operation.
                let del_len = self.choose_block_len(seed.len() - 1);
                let del_from = util::gen_random(0, seed.len() - del_len + 1);
                seed.drain(del_from..del_from + del_len);
            }
            13 => {
                if seed.len() + Self::HAVOC_BLK_XL >= Self::MAX_FILE { return; }
                let actually_clone = util::gen_bool(0.75);
                let (clone_len, clone_from) = if actually_clone {
                    let cl = self.choose_block_len(seed.len());
                    (cl, util::gen_random(0, seed.len() - cl + 1))
                } else {
                    (self.choose_block_len(Self::HAVOC_BLK_XL), 0)
                };
                let clone_to = util::gen_random(0, seed.len());
                if actually_clone {
                    // Copy
                    let slice = Vec::from(&seed[clone_from..clone_from + clone_len]);
                    seed.splice(clone_to..clone_to, slice.iter().cloned());
                } else {
                    // Replace
                    let c = if util::gen_bool(0.5) { util::gen_random(0, 256) as u8 } else { seed[util::gen_random(0, seed.len())] };
                    let slice = vec![c; clone_len];
                    seed.splice(clone_to..clone_to, slice.iter().cloned());
                }
            }
            14 => {
                if seed.len() < 2 { return; }
                let copy_len = self.choose_block_len(seed.len() - 1);
                let copy_from = util::gen_random(0, seed.len() - copy_len + 1);
                let copy_to = util::gen_random(0, seed.len() - copy_len + 1);
                if util::gen_bool(0.75) {
                    util::mem_move(seed, copy_to, copy_from, copy_len).unwrap();
                } else {
                    let c = if util::gen_bool(0.5) { util::gen_random(0, 256) as u8 } else { seed[util::gen_random(0, seed.len())] };
                    for i in copy_to..copy_to + copy_len { seed[i] = c; }
                }
            }
            _ => { error!("Unknown Havoc command"); }
        }
    }

    fn exec_splice(&mut self, seed: &mut <AFLSupervisor as Supervisor>::Fuzz) -> Result<(), SpliceResult> {
        match self.splice_random_fuzz(seed) {
            Ok(x) => {
                *seed.get_mut_fuzz() = x;
                self.splice_buf = Some(seed.clone());
            }
            Err(x) => { return Err(x); }
        }
        Ok(())
    }

    fn choose_block_len(&mut self, limit: usize) -> usize {
        let mut rlim = std::cmp::min(self.queue_cycle, 3);
        if self.run_over10m { rlim = 1; } else if self.start_time.elapsed().as_secs() >= 10 * 60 { self.run_over10m = true; }
        let (mut min_value, max_value) = match rlim {
            0 => {
                (1, Self::HAVOC_BLK_SMALL)
            }
            1 => {
                (Self::HAVOC_BLK_SMALL, Self::HAVOC_BLK_MEDIUM)
            }
            _ => {
                if util::gen_bool(0.9) {
                    (Self::HAVOC_BLK_MEDIUM, Self::HAVOC_BLK_LARGE)
                } else {
                    (Self::HAVOC_BLK_LARGE, Self::HAVOC_BLK_XL)
                }
            }
        };
        if min_value >= limit { min_value = 1 }

        min_value + util::gen_random(0, std::cmp::min(max_value, limit) - min_value + 1)
    }
}

impl MutationStrategy<AFLSupervisor> for AFLMutationStrategy {
    fn mutate(&mut self, seed: &mut <AFLSupervisor as Supervisor>::Fuzz, ctx: &mut <AFLSupervisor as Supervisor>::FuzzerContext) -> FuzzerResult<()> {
        let mut is_mutated = false;
        trace!("{:?}", self.phase);
        if self.skip_deterministic & &self.is_skipped_deterministic {
            self.phase = Phase::Havoc(0);
            self.is_skipped_deterministic = false;
        }
        while !is_mutated {
            self.phase = match self.phase {
                Phase::BitFlip1(pos) => {
                    if pos == 0 {
                        ctx.stats.lock().unwrap().now_trying = "bit flip 1\\1".to_string();
                    }
                    if pos == 0 && seed.was_fuzzed() {
                        // Skip deterministic
                        ctx.stats.lock().unwrap().now_trying = "havoc".to_string();
                        Phase::Havoc(0)
                    } else if pos < seed.get_fuzz().len() * 8 {
                        is_mutated = true;
                        BitFlip::mutate(seed.get_mut_fuzz(), pos).unwrap();
                        Phase::BitFlip1(pos + 1)
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "bit flip 2\\1".to_string();
                        Phase::BitFlip2(0)
                    }
                }
                Phase::BitFlip2(pos) => {
                    if pos + 1 < seed.get_fuzz().len() * 8 {
                        is_mutated = true;
                        BitFlip::mutate(seed.get_mut_fuzz(), pos).unwrap();
                        BitFlip::mutate(seed.get_mut_fuzz(), pos + 1).unwrap();
                        Phase::BitFlip2(pos + 1)
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "bit flip 4\\1".to_string();
                        Phase::BitFlip4(0)
                    }
                }
                Phase::BitFlip4(pos) => {
                    if pos + 3 < seed.get_fuzz().len() * 8 {
                        is_mutated = true;
                        BitFlip::mutate(seed.get_mut_fuzz(), pos).unwrap();
                        BitFlip::mutate(seed.get_mut_fuzz(), pos + 1).unwrap();
                        BitFlip::mutate(seed.get_mut_fuzz(), pos + 2).unwrap();
                        BitFlip::mutate(seed.get_mut_fuzz(), pos + 3).unwrap();
                        Phase::BitFlip4(pos + 1)
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "bit flip 8\\8".to_string();
                        Phase::BitFlip8(0)
                    }
                }
                Phase::BitFlip8(pos) => {
                    if pos < seed.get_fuzz().len() {
                        is_mutated = true;
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos).unwrap();
                        Phase::BitFlip8(pos + 1)
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "bit flip 16\\8".to_string();
                        Phase::BitFlip16(0)
                    }
                }
                Phase::BitFlip16(pos) => {
                    if pos + 1 < seed.get_fuzz().len() {
                        is_mutated = true;
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos).unwrap();
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos + 1).unwrap();
                        Phase::BitFlip16(pos + 1)
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "bit flip 32\\8".to_string();
                        Phase::BitFlip32(0)
                    }
                }
                Phase::BitFlip32(pos) => {
                    if pos + 3 < seed.get_fuzz().len() {
                        is_mutated = true;
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos).unwrap();
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos + 1).unwrap();
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos + 2).unwrap();
                        ByteFlip::mutate(seed.get_mut_fuzz(), pos + 3).unwrap();
                        Phase::BitFlip32(pos + 1)
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "arith 8\\8".to_string();
                        Phase::Arith8(0, -Self::ARITH_MAX)
                    }
                }
                Phase::Arith8(pos, val) => {
                    if pos < seed.get_fuzz().len() {
                        is_mutated = true;
                        if val >= 0 {
                            ArithmeticAdd::mutate(seed.get_mut_fuzz(), pos, val as u8).unwrap();
                        } else {
                            ArithmeticSub::mutate(seed.get_mut_fuzz(), pos, -val as u8).unwrap();
                        }
                        if val < Self::ARITH_MAX { // -35 to 35
                            Phase::Arith8(pos, val + 1)
                        } else {
                            Phase::Arith8(pos + 1, -Self::ARITH_MAX)
                        }
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "arith 16\\8".to_string();
                        Phase::Arith16(0, -Self::ARITH_MAX)
                    }
                }
                Phase::Arith16(pos, val) => {
                    if pos + 1 < seed.get_fuzz().len() {
                        is_mutated = true;
                        if val >= 0 {
                            ArithmeticAdd::mutate(seed.get_mut_fuzz(), pos, val as u16).unwrap();
                        } else {
                            ArithmeticSub::mutate(seed.get_mut_fuzz(), pos, -val as u16).unwrap();
                        }
                        if val < Self::ARITH_MAX {
                            Phase::Arith16(pos, val + 1)
                        } else {
                            Phase::Arith16(pos + 1, -Self::ARITH_MAX)
                        }
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "arith 32\\8".to_string();
                        Phase::Arith32(0, -Self::ARITH_MAX)
                    }
                }
                Phase::Arith32(pos, val) => {
                    if pos + 3 < seed.get_fuzz().len() {
                        is_mutated = true;
                        if val >= 0 {
                            ArithmeticAdd::mutate(seed.get_mut_fuzz(), pos, val as u32).unwrap();
                        } else {
                            ArithmeticSub::mutate(seed.get_mut_fuzz(), pos, -val as u32).unwrap();
                        }
                        if val < Self::ARITH_MAX {
                            Phase::Arith32(pos, val + 1)
                        } else {
                            Phase::Arith32(pos + 1, -Self::ARITH_MAX)
                        }
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "interest 8\\8".to_string();
                        Phase::Interest8(0, 0)
                    }
                }
                Phase::Interest8(pos, cpos) => {
                    if pos < seed.get_fuzz().len() {
                        is_mutated = true;
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos, Self::INTERESTING_8[cpos] as u8).unwrap();
                        if cpos + 1 == Self::INTERESTING_8.len() {
                            Phase::Interest8(pos + 1, 0)
                        } else {
                            Phase::Interest8(pos, cpos + 1)
                        }
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "interest 16\\8".to_string();
                        Phase::Interest16(0, 0)
                    }
                }
                Phase::Interest16(pos, cpos) => {
                    if pos + 1 < seed.get_fuzz().len() {
                        is_mutated = true;
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos, Self::INTERESTING_16[cpos] as u8).unwrap();
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos + 1, (Self::INTERESTING_16[cpos] >> 8) as u8).unwrap();
                        if cpos + 1 == Self::INTERESTING_16.len() {
                            Phase::Interest16(pos + 1, 0)
                        } else {
                            Phase::Interest16(pos, cpos + 1)
                        }
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "interest 32\\8".to_string();
                        Phase::Interest32(0, 0)
                    }
                }
                Phase::Interest32(pos, cpos) => {
                    if pos + 3 < seed.get_fuzz().len() {
                        is_mutated = true;
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos, Self::INTERESTING_32[cpos] as u8).unwrap();
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos + 1, (Self::INTERESTING_32[cpos] >> 8) as u8).unwrap();
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos + 2, (Self::INTERESTING_32[cpos] >> 16) as u8).unwrap();
                        ReplaceByte::mutate(seed.get_mut_fuzz(), pos + 3, (Self::INTERESTING_32[cpos] >> 24) as u8).unwrap();
                        if cpos + 1 == Self::INTERESTING_32.len() {
                            Phase::Interest32(pos + 1, 0)
                        } else {
                            Phase::Interest32(pos, cpos + 1)
                        }
                    } else {
                        ctx.stats.lock().unwrap().now_trying = "printable".to_string();
                        Phase::Printable(0, 0)
                    }
                }
                Phase::Printable(pos, cpos) => {
                    if pos >= seed.get_fuzz().len() {
                        self.stage_max = self.get_havoc_stage_max(seed, ctx);
                        ctx.stats.lock().unwrap().now_trying = "havoc".to_string();
                        Phase::Havoc(0)
                    } else if cpos >= Printable::v_len() {
                        Phase::Printable(pos + 1, 0)
                    } else {
                        is_mutated = true;
                        Printable::mutate(seed.get_mut_fuzz(), pos, cpos).unwrap();
                        Phase::Printable(pos, cpos + 1)
                    }
                }
                Phase::Havoc(now) => {
                    match self.havoc(seed, now) {
                        Ok(()) => {
                            is_mutated = true;
                            Phase::Havoc(now + 1)
                        }
                        _ => {
                            self.stage_max = self.get_splice_stage_max(seed, ctx);
                            ctx.stats.lock().unwrap().now_trying = "splice".to_string();
                            Phase::Splice(0, 0)
                        }
                    }
                }
                Phase::Splice(mut splice_cycle, mut havoc_cycle) => {
                    match self.splice(seed, &mut splice_cycle, &mut havoc_cycle) {
                        Ok(()) => {
                            is_mutated = true;
                            Phase::Splice(splice_cycle, havoc_cycle + 1)
                        }
                        Err(1) => Phase::Splice(splice_cycle + 1, 0),
                        _ => {
                            ctx.stats.lock().unwrap().now_trying = "bit flip 1\\1".to_string();
                            self.phase = Phase::BitFlip1(0);
                            return Err(FuzzerError("next".to_string()));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
