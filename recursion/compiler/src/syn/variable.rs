use super::BaseBuilder;

pub trait Variable<B: BaseBuilder>: Copy {
    fn uninit(builder: &mut B) -> Self;
}

pub trait FromConstant<B: BaseBuilder>: Variable<B> {
    type Constant: Sized;

    fn from_constant(constant: Self::Constant, builder: &mut B) -> Self;
}

pub trait Expression<B: BaseBuilder> {
    type Value: Variable<B>;

    fn assign(&self, dst: Self::Value, builder: &mut B);
}
