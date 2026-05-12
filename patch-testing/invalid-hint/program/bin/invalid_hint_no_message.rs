//! Same as `invalid_hint_macro`, but uses the no-message form of the macro
//! (which delegates to `halt_invalid_hint`).

#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let trigger = sp1_lib::io::read::<u8>();
    if trigger != 0 {
        sp1_lib::invalid_hint!();
    }
    sp1_lib::io::commit::<u8>(&trigger);
}
