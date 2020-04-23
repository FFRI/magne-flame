# FuzzerContext

FuzzerContext is shared by the whole fuzzer.

FuzzerContext implementation have to be thread-safe, because it may be shared across threads.

FuzzerContext trait implements functions that will be called before and after Supervisor::run_target function.

```rust
pub trait FuzzerContext: 'static + Unpin + Send + Sync {
    fn pre_run_target(&mut self) {}
    fn post_run_target(&mut self) {}
}
```

TargetStatus implements check_target_status function where the context watches the status of the target.
For example, you can use it to count the crashes or hangs of the target process.

```rust
pub trait TargetStatus: FuzzerContext {
    fn check_target_status(&mut self, status: &ProcessStatus);
}
```

```rust
pub trait SaveFuzz<T: Supervisor>: FuzzerContext {
    fn save_crash(&mut self, fuzz: &T::Fuzz);
    fn save_hang(&mut self, fuzz: &T::Fuzz);
}
```

SaveFuzz is used to save the fuzz input that made the target crash or hang.
