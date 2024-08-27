// make the function available to Rust

extern void add_one(unsigned int *x) {
    *x += 1;
}