use super::BaseBuilder;

pub trait Condition<B: BaseBuilder> {
    type IfBuilder<'a>
    where
        B: 'a;
    fn if_condition(self, builder: &mut B) -> Self::IfBuilder<'_>;
}

pub trait IfBuilder {
    fn then(self, f: impl FnOnce(&mut Self));
    fn then_or_else(self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self));
}

// A constant boolean condition which can be evaluated in compile time.
pub struct ConstantConditionBuilder<'a, B> {
    condition: bool,
    pub(crate) builder: &'a mut B,
}

impl<'a, B: BaseBuilder> BaseBuilder for ConstantConditionBuilder<'a, B> {}

impl<'a, B: BaseBuilder> IfBuilder for ConstantConditionBuilder<'a, B> {
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
