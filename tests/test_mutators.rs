#[cfg(test)]
mod test_mutators {
    use magne_flame::prelude::*;

    fn assert_mutate<T: Mutator>(mutator: &mut T, seed: &Vec<u8>, expected: &Vec<u8>) {
        let mut s = seed.clone();
        let _ = mutator.mutate(&mut s);
        assert_eq!(s, *expected);
    }

    fn assert_undo<T: Mutator>(mutator: &mut T, seed: &Vec<u8>, expected: &Vec<u8>) {
        let mut s = seed.clone();
        let _ = mutator.undo(&mut s);
        assert_eq!(s, *expected);
    }

    #[test]
    fn bit_flip_test() {
        let seed: Vec<Vec<u8>> = vec![vec![0x00], vec![0xFF]];
        let mut mutator = BitFlip::default();
        assert_mutate(&mut mutator, &seed[0], &vec![0x80]);
        mutator.pos = 1;
        assert_mutate(&mut mutator, &seed[0], &vec![0x40]);
        mutator.pos = 2;
        assert_mutate(&mut mutator, &seed[0], &vec![0x20]);
        mutator.pos = 3;
        assert_mutate(&mut mutator, &seed[0], &vec![0x10]);
        mutator.pos = 4;
        assert_mutate(&mut mutator, &seed[0], &vec![0x08]);
        mutator.pos = 5;
        assert_mutate(&mut mutator, &seed[0], &vec![0x04]);
        mutator.pos = 6;
        assert_mutate(&mut mutator, &seed[0], &vec![0x02]);
        mutator.pos = 7;
        assert_mutate(&mut mutator, &seed[0], &vec![0x01]);

        mutator.pos = 0;
        assert_mutate(&mut mutator, &seed[1], &vec![0x7F]);
        mutator.pos = 1;
        assert_mutate(&mut mutator, &seed[1], &vec![0xBF]);
        mutator.pos = 2;
        assert_mutate(&mut mutator, &seed[1], &vec![0xDF]);
        mutator.pos = 3;
        assert_mutate(&mut mutator, &seed[1], &vec![0xEF]);
        mutator.pos = 4;
        assert_mutate(&mut mutator, &seed[1], &vec![0xF7]);
        assert_undo(&mut mutator, &seed[1], &vec![0xF7]);
        mutator.pos = 5;
        assert_mutate(&mut mutator, &seed[1], &vec![0xFB]);
        assert_undo(&mut mutator, &seed[1], &vec![0xFB]);
        mutator.pos = 6;
        assert_mutate(&mut mutator, &seed[1], &vec![0xFD]);
        assert_undo(&mut mutator, &seed[1], &vec![0xFD]);
        mutator.pos = 7;
        assert_mutate(&mut mutator, &seed[1], &vec![0xFE]);
        assert_undo(&mut mutator, &seed[1], &vec![0xFE]);
    }

    #[test]
    fn byte_flip_test() {
        let seed: Vec<Vec<u8>> = vec![vec![0x00], vec![0xFF], vec![0x41, 0x42, 0x7F, 0x30]];
        let mut mutator = ByteFlip::default();
        assert_mutate(&mut mutator, &seed[0], &vec![0xFF]);
        assert_mutate(&mut mutator, &seed[1], &vec![0x00]);
        assert_mutate(&mut mutator, &seed[2], &vec![0xBE, 0x42, 0x7F, 0x30]);
        mutator.pos = 1;
        assert_mutate(&mut mutator, &seed[2], &vec![0x41, 0xBD, 0x7F, 0x30]);
        assert_undo(&mut mutator, &seed[2], &vec![0x41, 0xBD, 0x7F, 0x30]);
        mutator.pos = 2;
        assert_mutate(&mut mutator, &seed[2], &vec![0x41, 0x42, 0x80, 0x30]);
        assert_undo(&mut mutator, &seed[2], &vec![0x41, 0x42, 0x80, 0x30]);
        mutator.pos = 3;
        assert_mutate(&mut mutator, &seed[2], &vec![0x41, 0x42, 0x7F, 0xCF]);
        assert_undo(&mut mutator, &seed[2], &vec![0x41, 0x42, 0x7F, 0xCF]);
    }

    #[test]
    #[allow(non_snake_case)]
    fn ArithmeticAdd_test() {
        fn assert_arith8(seed: Vec<u8>, pos: usize, val: u8, expected: Vec<u8>) {
            let mut s = seed.clone();
            let e = expected.clone();
            ArithmeticAdd::mutate(&mut s, pos, val).unwrap();
            assert_eq!(s, e);
        }

        fn assert_arith16(seed: Vec<u8>, pos: usize, val: u16, expected: Vec<u8>) {
            let mut s = seed.clone();
            let e = expected.clone();
            ArithmeticAdd::mutate(&mut s, pos, val).unwrap();
            assert_eq!(s, e);
        }

        fn assert_arith32(seed: Vec<u8>, pos: usize, val: u32, expected: Vec<u8>) {
            let mut s = seed.clone();
            let e = expected.clone();
            ArithmeticAdd::mutate(&mut s, pos, val).unwrap();
            assert_eq!(s, e);
        }

        assert_arith8(vec![1, 2, 3, 4], 0, 1, vec![2, 2, 3, 4]);
        assert_arith8(vec![254, 2, 3, 4], 0, 1, vec![255, 2, 3, 4]);
        assert_arith8(vec![254, 2, 3, 4], 0, 2, vec![0, 2, 3, 4]);
        assert_arith8(vec![254, 146, 3, 4], 1, 185, vec![254, 75, 3, 4]);

        assert_arith16(vec![1, 2, 3, 4], 0, 1, vec![2, 2, 3, 4]);
        assert_arith16(vec![254, 2, 3, 4], 0, 1, vec![255, 2, 3, 4]);
        assert_arith16(vec![254, 2, 3, 4], 0, 2, vec![0, 3, 3, 4]);
        assert_arith16(vec![254, 146, 3, 4], 1, 185, vec![254, 75, 4, 4]);

        assert_arith32(vec![1, 2, 3, 4, 5], 0, 1, vec![2, 2, 3, 4, 5]);
        assert_arith32(vec![0xFE, 2, 3, 4, 5], 0, 1, vec![255, 2, 3, 4, 5]);
        assert_arith32(vec![0xFE, 2, 3, 4, 5], 0, 2, vec![0, 3, 3, 4, 5]);
        assert_arith32(vec![0xFE, 146, 3, 4, 5], 1, 185, vec![254, 75, 4, 4, 5]);
        assert_arith32(vec![0xFE, 146, 3, 4, 5], 1, 4989596, vec![254, 0x2E, 0x26, 0x50, 5]);
        assert_arith32(vec![0xFE, 0, 0, 0, 0, 0], 1, 0xFFFFFFFF, vec![254, 0xFF, 0xFF, 0xFF, 0xFF, 0]);
        assert_arith32(vec![0xFE, 1, 0, 0, 0, 0], 1, 0xFFFFFFFF, vec![254, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn swap_byte_test() {
        fn assert_swap(seed: Vec<u8>, pos1: usize, pos2: usize, expected: Vec<u8>) {
            let mut s = seed.clone();
            let e = expected.clone();
            SwapByte::mutate(&mut s, pos1, pos2).unwrap();
            assert_eq!(s, e);
        }

        assert_swap(vec![1, 2, 3, 4, 5], 1, 2, vec![1, 3, 2, 4, 5]);
        assert_swap(vec![1, 3, 2, 4, 5], 1, 2, vec![1, 2, 3, 4, 5]);
        assert_swap(vec![1, 2, 3, 4, 5], 2, 2, vec![1, 2, 3, 4, 5]);
    }
}
