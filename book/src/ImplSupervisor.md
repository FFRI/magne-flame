# Implement Supervisor

Supervisor executes and monitors a target.

```rust
pub trait Supervisor: Unpin + 'static {
    type Fuzz: Fuzz;
    type FuzzerContext: FuzzerContext;

    fn run_target(&mut self, fuzz: &mut Self::Fuzz, ctx: &mut Self::FuzzerContext) -> FuzzerResult<ProcessStatus>;
}
```

run_target function executes and fuzzes the target once.
This function called by SupervisorController.
