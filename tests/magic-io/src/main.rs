#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let a = sp1_zkvm::io::read::<Vec<u8>>();
    println!("a[0..20] = {:?}", &a[0..20]);
    let b = sp1_zkvm::io::read_magic_vec();
    println!("b[0..20] = {:?}", &b[0..20]);

    assert_eq!(a, b);
    println!("success");
}
