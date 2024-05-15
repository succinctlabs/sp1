use sp1_recursion_gnark_ffi::{babybearextinv, Test2, Test3};

fn main() {
    unsafe {
        Test2();
        let res = Test3(2);
        println!("res: {}", res);
        let res2 = babybearextinv(2, 2, 2, 2, 2);
        println!("res2: {}", res2);
    }
}
