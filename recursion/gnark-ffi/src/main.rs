fn main() {
    println!("hi world!");
    let args: Vec<String> = std::env::args().collect();
    println!("args: {:#?}", args);
}
