# Implement Scheduler

Scheduler implements scheduling strategy that decides which fuzz input to retrieve from the data structure.

```rust
pub trait Scheduler<T>: 'static + Unpin
    where T: Supervisor,
{
    fn evaluate_fuzz(&mut self, fuzz: T::Fuzz, ctx: &mut T::FuzzerContext);
    fn get_fuzz(&mut self, ctx: &mut T::FuzzerContext) -> FuzzerResult<T::Fuzz>;
}
```

evaluate_fuzz function evaluates the fuzz input after fuzzing, and insert it to the data structure if it is interested.

get_fuzz function fetches a fuzz input from the scheduler.
