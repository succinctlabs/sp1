use compiler::builder::{Builder, Function};

fn main() {
    pub struct Fibonacci;

    impl<B: Builder> Function<B> for Fibonacci {
        fn ident(&self) -> String {
            "fibonacci".to_string()
        }

        fn define(self, builder: &mut B) {}
    }
}
