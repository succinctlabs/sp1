#![no_main]
sp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_fri_fold(input_mem_ptr: *const u32, output_mem_ptr: *const *mut u32);
}

pub fn main() {
    let x = 31;
    let alpha_base_slice = [534846791, 266430563, 1876720999, 461694771];
    let z_base_slice = [1454407147, 568676784, 1977102820, 1323872866];
    let p_at_z_base_slice = [1257978304, 1179973496, 1444690212, 456956341];
    let p_at_x = 777132171;

    let ro_base_slice = [1847687120, 1423454610, 1144640053, 1381242286];
    let alpha_pow_base_slice = [540044308, 1018290973, 627874647, 969069565];

    let mut input_vec = Vec::new();
    input_vec.push(x);
    input_vec.extend_from_slice(&alpha_base_slice);
    input_vec.extend_from_slice(&z_base_slice);
    input_vec.extend_from_slice(&p_at_z_base_slice);
    input_vec.push(p_at_x);

    let mut ro_alpha_pow_ptrs = [ro_base_slice.as_ptr(), alpha_pow_base_slice.as_ptr()];

    unsafe {
        syscall_fri_fold(
            input_vec.as_slice().as_ptr() as *const u32,
            ro_alpha_pow_ptrs.as_mut_ptr() as *const *mut u32,
        );
    }

    let expected_ro_base_slice = [1306862788, 594458733, 1798096294, 1881139490];
    let expected_alpha_pow_base_slice = [1726063080, 1854443909, 1099989448, 144245555];

    for i in 0..4 {
        assert_eq!(ro_base_slice[i], expected_ro_base_slice[i]);
        assert_eq!(alpha_pow_base_slice[i], expected_alpha_pow_base_slice[i]);
    }

    println!("done");
}
