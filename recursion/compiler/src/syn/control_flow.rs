use super::BaseBuilder;

pub trait IfBuilder<B: BaseBuilder> {
    fn then(self, f: impl FnOnce(&mut B));
    fn then_or_else(self, then_f: impl FnOnce(&mut B), else_f: impl FnOnce(&mut B));
}
