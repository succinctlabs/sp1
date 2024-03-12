mod control_flow;
mod iter;
mod ops;
mod variable;

pub use control_flow::*;
pub use iter::*;
pub use ops::*;
pub use variable::*;

pub trait BaseBuilder: Sized {}

pub trait Builder: BaseBuilder {
    fn assign<E: Expression<Self>>(&mut self, dst: E::Value, expr: E) {
        expr.assign(dst, self);
    }

    fn constant<T: FromConstant<Self>>(&mut self, value: T::Constant) -> T {
        let var = T::uninit(self);
        var.imm(value, self);
        var
    }

    fn eval<E: Expression<Self>>(&mut self, expr: E) -> E::Value {
        let dst = E::Value::uninit(self);
        expr.assign(dst, self);
        dst
    }

    fn iter<I: IntoIterator<Self>>(&mut self, iter: I) -> I::IterBuilder<'_> {
        iter.into_iter(self)
    }
}

impl<T: BaseBuilder> Builder for T {}

pub trait FieldBuilder: Builder {
    type Felt: AlgebraicVariable<Self>;
}
