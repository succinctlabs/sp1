#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::Rng;
use sp1_zkvm::syscalls::call_memcpy;

fn memcpy(dest: &mut [u8], src: &mut [u8], n: usize) {
    // println!("cycle-tracker-start: memcpy");
    println!("dest: {:?}", dest.as_mut_ptr());
    println!("src: {:?}", src.as_mut_ptr());
    call_memcpy(dest.as_mut_ptr(), src.as_mut_ptr(), n);
    // // println!("cycle-tracker-end: memcpy");
    for i in 0..n {
        assert_eq!(dest[i], src[i]);
    }
}

#[sp1_derive::cycle_tracker]
fn main() {
    let mut rng = rand::thread_rng();
    // for src_offset in 0..4 {
    //     for dest_offset in 0..4 {
    for nbytes in 4..5 {
        let mut src = rng.gen::<[u8; 32]>().to_vec();
        let mut dest = rng.gen::<[u8; 32]>().to_vec();

        memcpy(&mut dest, &mut src, nbytes);
    }
    //     }
    // }

    println!("All tests passed successfully!");
}
