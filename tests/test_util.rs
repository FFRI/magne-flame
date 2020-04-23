#[cfg(test)]
mod test_util {
    use magne_flame::prelude::util;

    #[test]
    fn gen_fuzzer_id_test() {
        for _ in 0..100 {
            let id = util::gen_fuzzer_id();
            let l = id.len();
            assert!(1 <= l && l <= 16);
        }
    }

    #[test]
    fn mem_copy_test() {
        fn assert_check(v1: &mut Vec<u8>, v2: &mut Vec<u8>, offset: usize, expected: &mut Vec<u8>) {
            let _ = util::mem_copy(v1, v2, offset);
            assert_eq!(v1, expected);
        }

        assert_check(&mut vec![1, 2, 3], &mut vec![4, 5, 6], 0, &mut vec![4, 5, 6]);
        assert_check(&mut vec![1, 2, 3], &mut vec![4, 5, 6], 1, &mut vec![1, 4, 5]);
        assert_check(&mut vec![1, 2, 3], &mut vec![4, 5, 6], 2, &mut vec![1, 2, 4]);
        assert_check(&mut vec![1, 2, 3], &mut vec![4, 5, 6], 3, &mut vec![1, 2, 3]);
        assert_check(&mut vec![1, 2, 3], &mut vec![4, 5, 6], 4, &mut vec![1, 2, 3]);
    }

    #[test]
    fn mem_move_test() {
        fn assert_check(v1: &mut Vec<u8>, offset_to: usize, offset_from: usize, len: usize, expected: &mut Vec<u8>) {
            let _ = util::mem_move(v1, offset_to, offset_from, len);
            assert_eq!(v1, expected);
        }
        assert_check(&mut vec![1, 2, 3, 4], 0, 1, 2, &mut vec![2, 3, 3, 4]);
        assert_check(&mut vec![1, 2, 3, 4], 0, 2, 2, &mut vec![3, 4, 3, 4]);
        assert_check(&mut vec![1, 2, 3, 4], 1, 0, 2, &mut vec![1, 1, 2, 4]);
        assert_check(&mut vec![1, 2, 3, 4], 1, 1, 2, &mut vec![1, 2, 3, 4]);
        assert_check(&mut vec![1, 2, 3, 4], 2, 0, 2, &mut vec![1, 2, 1, 2]);
        assert_check(&mut vec![1, 2, 3, 4], 3, 1, 2, &mut vec![1, 2, 3, 2]);
        assert_check(&mut vec![1, 2, 3, 4], 1, 3, 2, &mut vec![1, 4, 3, 4]);
    }
}
