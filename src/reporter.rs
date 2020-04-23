/// Report statistics.
use std::thread;
use std::time::Duration;

pub trait Reporter: 'static + Unpin {
    /// Prints a report.
    fn print_report<F>(&self, func: &F) where F: Fn(&Self) + Send + 'static;
    /// Starts a reporter.
    fn start<F>(reporter: Self, func: F) where F: Fn(&Self) + Send + 'static;
}

#[derive(Clone)]
/// Writes a report periodically.
pub struct SimpleReporter {
    /// Time span to report.
    pub span: Duration,
}

impl SimpleReporter {
    pub fn new() -> Self {
        SimpleReporter { span: Duration::from_secs(1) }
    }
}

impl Reporter for SimpleReporter {
    /// Prints a report and a line feed.
    fn print_report<F>(&self, func: &F)
        where F: Fn(&Self) + Send + 'static
    {
        func(self);
        println!();
    }

    /// Starts a reporter.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use magne_flame::prelude::*;
    ///
    /// let reporter=SimpleReporter::new();
    /// Reporter::start(reporter,move||{
    ///     println!("test");
    /// });
    /// ```
    fn start<F>(reporter: Self, func: F)
        where F: Fn(&Self) + Send + 'static
    {
        thread::spawn({
            move || {
                loop {
                    std::thread::sleep(reporter.span);
                    reporter.print_report(&func);
                }
            }
        });
    }
}
