use super::BaseBuilder;

pub trait Condition<B: BaseBuilder> {}

pub trait IfBuilder {
    fn then(self, f: impl FnOnce(&mut Self));
    fn then_or_else(self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self));
}

// A constant boolean condition which can be evaluated in compile time.
pub struct ConstantCondition<'a, B> {
    condition: bool,
    builder: &'a mut B,
}

impl<'a, B: BaseBuilder> BaseBuilder for ConstantCondition<'a, B> {}

impl<'a, B: BaseBuilder> IfBuilder for ConstantCondition<'a, B> {
    fn then(mut self, f: impl FnOnce(&mut Self)) {
        if self.condition {
            f(&mut self);
        }
    }

    fn then_or_else(mut self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self)) {
        if self.condition {
            then_f(&mut self);
        } else {
            else_f(&mut self);
        }
    }
}
