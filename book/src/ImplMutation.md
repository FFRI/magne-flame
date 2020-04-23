# Implement Mutation

Mutator mutates a fuzz byte sequence `&mut Vec<u8>`.

undo function is the reverse operation of mutate function.

```rust
pub trait Mutator: Unpin + 'static {
    fn mutate(&mut self, fuzz: &mut Vec<u8>) -> FuzzerResult<()>;
    fn undo(&mut self, _fuzz: &mut Vec<u8>) -> FuzzerResult<()> {
        unimplemented!("undo is not implemented.");
    }
}
```

The following is the implementation of ByteFlip Mutator.

```rust
use magne_flame::prelude::*;

#[derive(Default)]
pub struct ByteFlip {
    pub pos: usize,
}

impl ByteFlip {
    pub fn mutate(seed: &mut Vec<u8>, pos: usize) -> FuzzerResult<()> {
        if pos < seed.len() {
            seed[pos] ^= 0xFF as u8; // Flip a byte.
            Ok(())
        } else { Err(0) }
    }
}

impl Mutator for ByteFlip {
    fn mutate(&mut self, seed: &mut Vec<u8>) -> FuzzerResult<()> {
        Self::mutate(seed, self.pos)
    }

    fn undo(&mut self, seed: &mut Vec<u8>) -> FuzzerResult<()> {
        self.mutate(seed)
    }
}
```

# MutationStrategy

MutationStrategy implements a mutation strategy.

```rust
pub trait MutationStrategy<T: Supervisor>: Unpin + 'static {
    fn mutate(&mut self, seed: &mut T::Fuzz, ctx: &mut T::FuzzerContext) -> FuzzerResult<()>;
    fn undo(&mut self, _seed: &mut T::Fuzz, _ctx: &mut T::FuzzerContext) -> FuzzerResult<()> {
        unimplemented!("undo is not implemented.");
    }
}
```

A strategy that adds or subtracts two little-endian bytes with a 50-50 chance can be implemented in this way.

```rust
use magne_flame::prelude::*;

struct PrintableMutationStrategy;

impl<T: Supervisor> MutationStrategy<T> for PrintableMutationStrategy {
    fn mutate(&mut self, seed: &mut T::Fuzz, _ctx: &mut T::FuzzerContext) -> FuzzerResult<()> {
        let len = seed.get_fuzz().len();
        if util::gen_bool(0.5) {
            ArithmeticAdd::mutate(seed.get_mut_fuzz(), util::gen_random(0, len - 1), util::gen_random(1, 0xFFFF) as u16)
        } else {
            ArithmeticSub::mutate(seed.get_mut_fuzz(), util::gen_random(0, len - 1), util::gen_random(1, 0xFFFF) as u16)
        }
    }
}
```

