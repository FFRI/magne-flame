#[cfg(test)]
mod tests {
    use magne_flame::prelude::*;

    #[test]
    fn mock_seed_test() {
        let m = MockSeed { id: "".to_string(), v: vec!['t' as u8, 'e' as u8, 's' as u8, 't' as u8, '1' as u8] };
        println!("{:?}", m.v);
        println!("{:x?}", m.v);
    }

    #[test]
    fn dumb_scheduler_test() {
        let expected_seed: Vec<Vec<u8>> = vec![vec![78, 117, 108, 97, 97], vec![72, 69, 76, 76, 79], vec![88, 88, 88, 88, 88]];
        let mut ctx = MockFuzzerContext::default();
        let mut scheduler: SimpleScheduler<_, ArgvSupervisor<MockFuzzerContext, MockSeed>, _> = SimpleScheduler::new(SimpleMutationStrategy::new(TransparentMutator), false);
        scheduler.add_raw_fuzzes(&expected_seed);

        for i in 0..expected_seed.len() * 10 {
            assert_eq!(expected_seed[i % expected_seed.len()], scheduler.get_fuzz(&mut ctx).unwrap().get_mut_fuzz().clone());
        }
    }
}
