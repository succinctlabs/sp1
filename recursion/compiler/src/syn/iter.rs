use super::BaseBuilder;
use core::ops::Range;

pub trait IntoIterator<B: BaseBuilder> {
    type Item;

    fn into_iter(self, builder: &mut B) -> impl IterBuilder<B, Item = Self::Item>;
}

pub trait IterBuilder<B: BaseBuilder> {
    type Item;

    fn for_each(self, f: impl FnMut(Self::Item, &mut B));
}

// An iterator for constant size loops.

impl<B: BaseBuilder> IntoIterator<B> for Range<usize> {
    type Item = usize;

    fn into_iter(self, builder: &mut B) -> impl IterBuilder<B, Item = Self::Item> {
        ConstantSizeLoopIterBuilder {
            range: self,
            builder,
        }
    }
}

pub struct ConstantSizeLoopIterBuilder<'a, B> {
    range: Range<usize>,
    builder: &'a mut B,
}

impl<'a, B: BaseBuilder> BaseBuilder for ConstantSizeLoopIterBuilder<'a, B> {}

impl<'a, B: BaseBuilder> IterBuilder<B> for ConstantSizeLoopIterBuilder<'a, B> {
    type Item = usize;

    fn for_each(self, mut f: impl FnMut(usize, &mut B)) {
        for i in self.range {
            f(i, self.builder);
        }
    }
}
