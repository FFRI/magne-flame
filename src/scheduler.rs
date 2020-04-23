use crate::prelude::*;
use std::marker::PhantomData;
use std::sync::Mutex;
use once_cell::sync::Lazy;

/// Decides where to load a seed and stores the seed.
pub trait Seed: 'static + Unpin + Send + Clone + Default {
    /// Gets fuzz data from anywhere.
    fn get(&self) -> FuzzerResult<Vec<u8>>;
    /// Stores fuzz data to anywhere.
    fn store(&self, seed: &Vec<u8>) -> FuzzerResult<()>;
    /// Disposes fuzz data.
    fn dispose(&mut self) -> FuzzerResult<()>;
    /// Sets seed ID. Seed ID is used to get, store, dispose a fuzz input.
    fn set_id(&mut self, id: String);
    /// Gets seed ID. Seed ID is used to get, store, dispose a fuzz input.
    fn get_id(&self) -> &String;
}

/// Implements a scheduling strategy that decides which fuzz input to retrieve from the data structure.
pub trait Scheduler<T>: 'static + Unpin
    where
        T: Supervisor,
{
    /// Evaluates a fuzz input to add.
    fn evaluate_fuzz(&mut self, fuzz: T::Fuzz, ctx: &mut T::FuzzerContext);
    /// Gets a mutated fuzz input.
    fn get_fuzz(&mut self, ctx: &mut T::FuzzerContext) -> FuzzerResult<T::Fuzz>;
}

/// Stores a fuzz byte sequence.
pub trait Fuzz: Unpin + Send + Clone + From<Vec<u8>> {
    /// Gets a &mut fuzz byte sequence.
    fn get_mut_fuzz(&mut self) -> &mut Vec<u8>;
    /// Gets a &fuzz byte sequence.
    fn get_fuzz(&self) -> &Vec<u8>;
    /// Stores the fuzz input.
    fn store(&self) -> FuzzerResult<()>;
    /// Returns an id.
    fn get_id(&self) -> &String;
    /// Sets an id.
    fn set_id(&mut self, id: String);
    /// Gets ProcessStatus when fuzzing with this fuzz input.
    fn get_status(&self) -> ProcessStatus;
    /// Sets ProcessStatus when fuzzing with this fuzz input.
    fn set_status(&mut self, status: ProcessStatus);
}

/// Fuzz input that stores an instrumentation.
pub trait InstrumentedFuzz: Fuzz {
    /// Instrument type.
    type Instrument: Instrument;
    /// Is the fuzz data valuable?
    fn is_valuable(&self) -> bool;
    /// Sets a instrument.
    fn set_instrument(&mut self, instrument: Self::Instrument);
    /// Gets the &instrument.
    fn get_instrument(&self) -> Option<&Self::Instrument>;
    /// Gets the &mut instrument.
    fn get_mut_instrument(&mut self) -> Option<&mut Self::Instrument>;
    /// Is the fuzz data instrumented?
    fn is_instrumented(&self) -> bool { true }
}

/// Instrument
pub trait Instrument: Send + Sync + Clone {}

static OUT_DIR: Lazy<Mutex<String>> = Lazy::new(|| { Mutex::new(String::new()) });

/// Reads a fuzz input from a file.
#[derive(Clone, Default)]
pub struct FileSeed {
    pub filepath: String
}

impl FileSeed {
    /// Sets and creates a directory for FileSeed.
    ///
    /// FileSeed will load or store the corpus in the directory.
    pub fn set_out_dir(mut path: String) {
        if path.len() != 0 && !path.ends_with("/") && !path.ends_with("\\") {
            path.push(std::path::MAIN_SEPARATOR);
        }
        util::create_directory(&path).expect("Failed to create out_dir");
        *OUT_DIR.lock().unwrap() = path;
    }
}

impl Seed for FileSeed {
    /// Gets a corpus from a file.
    fn get(&self) -> FuzzerResult<Vec<u8>> {
        let k = util::read_file(&self.filepath)?;
        Ok(k)
    }

    /// Stores the corpus to a file.
    fn store(&self, seed: &Vec<u8>) -> FuzzerResult<()> {
        util::write_file(&self.filepath, &seed)?;
        Ok(())
    }

    /// Removes a corpus file.
    fn dispose(&mut self) -> FuzzerResult<()> {
        util::remove_file(&self.filepath)?;
        Ok(())
    }

    /// Sets an ID ( ID of FileSeed is the corpus file path).
    fn set_id(&mut self, id: String) {
        self.filepath = format!("{}{}", *OUT_DIR.lock().unwrap(), id);
    }

    /// Gets an ID ( ID of FileSeed is the corpus file path).
    fn get_id(&self) -> &String { &self.filepath }
}

/// For testing and debugging.
#[derive(Clone, Default)]
pub struct MockSeed { pub id: String, pub v: Vec<u8> }

impl Seed for MockSeed {
    fn get(&self) -> FuzzerResult<Vec<u8>> {
        Ok(self.v.clone())
    }

    /// Does nothing.
    fn store(&self, _seed: &Vec<u8>) -> FuzzerResult<()> {
        Ok(())
    }

    /// Does nothing.
    fn dispose(&mut self) -> FuzzerResult<()> {
        Ok(())
    }

    fn set_id(&mut self, id: String) { self.id = id; }
    fn get_id(&self) -> &String { &self.id }
}

/// Gets a fuzz input from the queue in order.
///
/// If the index reaches the end of the queue, it returns the start of the queue.
/// The enqueued fuzz inputs will not be removed.
pub struct SimpleScheduler<F, T, M>
    where F: FuzzerContext + StoreFuzz<T>,
          T: Supervisor,
          M: MutationStrategy<T>
{
    queue: Vec<T::Fuzz>,
    idx: usize,
    mutation_strategy: M,
    is_saved: bool,
    phantom: PhantomData<F>,
}

impl<F, T, M> SimpleScheduler<F, T, M>
    where F: FuzzerContext + StoreFuzz<T>,
          T: Supervisor,
          M: MutationStrategy<T>
{
    pub fn new(mutation_strategy: M, is_saved: bool) -> Self {
        SimpleScheduler {
            queue: Vec::new(),
            idx: 0,
            mutation_strategy,
            is_saved,
            phantom: PhantomData,
        }
    }

    /// Enqueues seeds without evaluation.
    /// Wrap `Vec<u8>` with `T::Fuzz` and enqueue.
    pub fn add_raw_fuzzes(&mut self, seeds: &Vec<Vec<u8>>) {
        for seed in seeds.iter() {
            self.add_raw_fuzz(seed.clone());
        }
    }

    /// Enqueues a fuzz input.
    pub fn enqueue_fuzz(&mut self, mut fuzz: T::Fuzz) {
        let file_path = format!("id_{:>05}.txt", self.queue.len());
        fuzz.set_id(file_path);
        fuzz.store().unwrap();
        self.queue.push(fuzz);
    }

    /// Wraps `Vec<u8>` with `T::Fuzz` and enqueue.
    pub fn add_raw_fuzz(&mut self, fuzz: Vec<u8>) {
        let c = T::Fuzz::from(fuzz);
        self.enqueue_fuzz(c);
    }
}

impl<F, T, M> Scheduler<T> for SimpleScheduler<F, T, M>
    where F: FuzzerContext + StoreFuzz<T>,
          T: Supervisor<FuzzerContext=F>,
          M: MutationStrategy<T>
{
    /// Enqueues a fuzz data unconditionally if self.is_saved is true.
    fn evaluate_fuzz(&mut self, fuzz: T::Fuzz, ctx: &mut T::FuzzerContext) {
        match fuzz.get_status() {
            ProcessStatus::Crash => ctx.store_crash(&fuzz),
            ProcessStatus::TimeOut => ctx.store_hang(&fuzz),
            _ => {}
        }
        if self.is_saved { self.enqueue_fuzz(fuzz); }
    }

    /// Gets a fuzz input from queue and mutates it.
    fn get_fuzz(&mut self, ctx: &mut T::FuzzerContext) -> FuzzerResult<T::Fuzz> {
        if self.queue.len() <= self.idx { self.idx = 0; }
        let x = self.queue.get(self.idx);
        self.idx += 1;
        let mut x = x.unwrap().clone();
        self.mutation_strategy.mutate(&mut x, ctx).unwrap();
        Ok(x)
    }
}

/// Black-box fuzz input.
pub struct SimpleFuzz<T: Seed> {
    seed: T,
    /// Raw fuzz byte sequence.
    fuzz: Vec<u8>,
    /// ProcessStatus when fuzzing with the fuzz input.
    status: ProcessStatus,
}

impl<T: Seed> SimpleFuzz<T> {
    pub fn new() -> Self {
        Self { seed: T::default(), fuzz: vec![], status: ProcessStatus::Suspend }
    }
}

impl<T: Seed> Clone for SimpleFuzz<T> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
            fuzz: self.fuzz.clone(),
            status: ProcessStatus::Suspend,
        }
    }
}

impl<T: Seed> From<Vec<u8>> for SimpleFuzz<T> {
    fn from(fuzz: Vec<u8>) -> Self {
        Self { seed: T::default(), fuzz, status: ProcessStatus::Suspend }
    }
}

impl<T: Seed> Fuzz for SimpleFuzz<T> {
    /// Gets a &mut fuzz.
    fn get_mut_fuzz(&mut self) -> &mut Vec<u8> { &mut self.fuzz }

    /// Gets a &fuzz.
    fn get_fuzz(&self) -> &Vec<u8> { &self.fuzz }

    /// Stores a fuzz input.
    fn store(&self) -> FuzzerResult<()> {
        self.seed.store(&self.fuzz)
    }

    /// Gets a seed ID.
    fn get_id(&self) -> &String { self.seed.get_id() }

    /// Sets a seed ID.
    fn set_id(&mut self, id: String) { self.seed.set_id(id); }

    /// Gets a status when fuzzing with this fuzz input.
    fn get_status(&self) -> ProcessStatus { self.status }

    /// Sets a status when fuzzing with this fuzz input.
    fn set_status(&mut self, status: ProcessStatus) { self.status = status; }
}

#[derive(Clone)]
/// Dummy instrument for testing and debugging.
pub struct NoInstrument;

impl Instrument for NoInstrument {}
