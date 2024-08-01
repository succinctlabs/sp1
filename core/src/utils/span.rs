use std::{borrow::Cow, collections::HashMap, iter::once, mem::take};

use thiserror::Error;

use super::sorted_table_lines;

#[derive(Debug, Clone, Default)]
pub struct SpanBuilder<'a> {
    pub parents: Vec<Span<'a>>,
    pub current_span: Span<'a>,
}

impl<'a> SpanBuilder<'a> {
    pub fn new(name: String) -> Self {
        Self {
            current_span: Span {
                name,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn item(&mut self, item_name: impl Into<Cow<'a, str>>) -> &mut Self {
        self.current_span
            .cts
            .entry(item_name.into())
            .and_modify(|x| *x += 1)
            .or_insert(1);
        self
    }

    pub fn enter(&mut self, span_name: String) -> &mut Self {
        let span = Span::new(span_name);
        self.parents
            .push(core::mem::replace(&mut self.current_span, span));
        self
    }

    pub fn exit(&mut self) -> Result<&mut Self, SpanBuilderExitError> {
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

    pub fn finish(&mut self) -> Result<Span<'a>, SpanBuilderFinishError> {
        self.parents
            .is_empty()
            .then(|| take(&mut self.current_span))
            .ok_or_else(|| SpanBuilderFinishError::OpenSpan(self.current_span.name.clone()))
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
pub struct Span<'a> {
    pub name: String,
    pub cts: HashMap<Cow<'a, str>, usize>,
    pub children: Vec<Span<'a>>,
}

impl<'a> Span<'a> {
    pub fn new(name: String) -> Self {
        Self {
            name,
            ..Default::default()
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

        once(name.to_string())
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
