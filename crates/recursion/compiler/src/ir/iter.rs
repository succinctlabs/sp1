use std::mem;

use super::{Builder, Config, DslIr, DslIrBlock};

pub trait IrIter<C: Config, Item>: Sized {
    fn ir_par_map_collect<B, F, S>(self, builder: &mut Builder<C>, map_op: F) -> B
    where
        F: FnMut(&mut Builder<C>, Item) -> S,
        B: Default + Extend<S>;
}

impl<C, I, Item> IrIter<C, Item> for I
where
    C: Config,
    I: Iterator<Item = Item>,
{
    fn ir_par_map_collect<B, F, S>(self, builder: &mut Builder<C>, mut map_op: F) -> B
    where
        F: FnMut(&mut Builder<C>, I::Item) -> S,
        B: Default + Extend<S>,
    {
        let prev_ops = mem::take(builder.get_mut_operations());
        let (blocks, coll): (Vec<_>, B) = self
            .map(|r| {
                let next_addr = builder.variable_count();
                let s = map_op(builder, r);
                let block = DslIrBlock {
                    ops: mem::take(builder.get_mut_operations()),
                    addrs_written: next_addr..builder.variable_count(),
                };
                (block, s)
            })
            .unzip();
        *builder.get_mut_operations() = prev_ops;
        builder.push_op(DslIr::Parallel(blocks));
        coll
    }
}
