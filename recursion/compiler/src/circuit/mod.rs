mod backend;

pub trait CircuitBuilder {
    type F;
    type Var;
}
