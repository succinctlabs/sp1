use std::{collections::HashMap, fmt::Display, hash::Hash, iter::once};

use thiserror::Error;

use super::sorted_table_lines;

#[derive(Debug, Clone)]
pub struct SpanBuilder<S, T> {
    pub parents: Vec<Span<S, T>>,
    pub current_span: Span<S, T>,
}

impl<S, T> SpanBuilder<S, T>
where
    S: Display,
    T: Ord + Display + Hash,
{
    pub fn new(name: S) -> Self {
        Self {
            parents: Default::default(),
            current_span: Span::new(name),
        }
    }

    pub fn item(&mut self, item_name: impl Into<T>) -> &mut Self
    where
        T: Hash + Eq,
    {
        self.current_span
            .cts
            .entry(item_name.into())
            .and_modify(|x| *x += 1)
            .or_insert(1);
        self
    }

    pub fn enter(&mut self, span_name: S) -> &mut Self {
        let span = Span::new(span_name);
        self.parents
            .push(core::mem::replace(&mut self.current_span, span));
        self
    }

    pub fn exit(&mut self) -> Result<&mut Self, SpanBuilderExitError>
    where
        T: Clone + Hash + Eq,
    {
        let mut parent_span = self
            .parents
            .pop()
            .ok_or(SpanBuilderExitError::RootSpanExit)?;
        // Add spanned instructions to parent.
        for (instr_name, &ct) in self.current_span.cts.iter() {
            // Always clones. Could be avoided with `raw_entry`, but it's not a big deal.
            parent_span
                .cts
                .entry(instr_name.clone())
                .and_modify(|x| *x += ct)
                .or_insert(ct);
        }
        // Move to the parent span.
        let child_span = core::mem::replace(&mut self.current_span, parent_span);
        self.current_span.children.push(child_span);
        Ok(self)
    }

    pub fn finish(self) -> Result<Span<S, T>, SpanBuilderFinishError> {
        if self.parents.is_empty() {
            Ok(self.current_span)
        } else {
            Err(SpanBuilderFinishError::OpenSpan(
                self.current_span.name.to_string(),
            ))
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum SpanBuilderError {
    #[error(transparent)]
    Exit(#[from] SpanBuilderExitError),
    #[error(transparent)]
    Finish(#[from] SpanBuilderFinishError),
}

#[derive(Error, Debug, Clone)]
pub enum SpanBuilderExitError {
    #[error("cannot exit root span")]
    RootSpanExit,
}

#[derive(Error, Debug, Clone)]
pub enum SpanBuilderFinishError {
    #[error("open span: {0}")]
    OpenSpan(String),
}

#[derive(Debug, Clone, Default)]
pub struct Span<S, T> {
    pub name: S,
    pub cts: HashMap<T, usize>,
    pub children: Vec<Span<S, T>>,
}

impl<S, T> Span<S, T>
where
    S: Display,
    T: Ord + Display + Hash,
{
    pub fn new(name: S) -> Self {
        Self {
            name,
            cts: Default::default(),
            children: Default::default(),
        }
    }

    pub fn total(&self) -> usize {
        self.cts
            .values()
            .cloned()
            .chain(self.children.iter().map(|x| x.total()))
            .sum()
    }

    pub fn to_lines(&self) -> Vec<String> {
        let Self {
            name,
            cts: instr_cts,
            children,
        } = self;

        once(format!("{}", name))
            .chain(
                children
                    .iter()
                    .flat_map(|c| c.to_lines())
                    .chain(sorted_table_lines(instr_cts))
                    .map(|line| format!("│  {line}")),
            )
            .chain(once(format!("└╴ {} total", self.total())))
            .collect()
    }
}
