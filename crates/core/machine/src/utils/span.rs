use std::{collections::HashMap, fmt::Display, hash::Hash, iter::once};

use sp1_core_executor::events::{format_table_line, sorted_table_lines};
use thiserror::Error;

/// A builder to create a [`Span`].
/// `S` is the type of span names and `T` is the type of item names.
#[derive(Debug, Clone)]
pub struct SpanBuilder<S, T = S> {
    pub parents: Vec<Span<S, T>>,
    pub current_span: Span<S, T>,
}

impl<S, T> SpanBuilder<S, T>
where
    S: Display,
    T: Ord + Display + Hash,
{
    /// Create an empty builder with the given name for the root span.
    pub fn new(name: S) -> Self {
        Self { parents: Default::default(), current_span: Span::new(name) }
    }

    /// Add an item to this span.
    pub fn item(&mut self, item_name: impl Into<T>) -> &mut Self
    where
        T: Hash + Eq,
    {
        self.current_span.cts.entry(item_name.into()).and_modify(|x| *x += 1).or_insert(1);
        self
    }

    /// Enter a new child span with the given name.
    pub fn enter(&mut self, span_name: S) -> &mut Self {
        let span = Span::new(span_name);
        self.parents.push(core::mem::replace(&mut self.current_span, span));
        self
    }

    /// Exit the current span, moving back to its parent.
    ///
    /// Yields an error if the current span is the root span, which may not be exited.
    pub fn exit(&mut self) -> Result<&mut Self, SpanBuilderExitError>
    where
        T: Clone + Hash + Eq,
    {
        let mut parent_span = self.parents.pop().ok_or(SpanBuilderExitError::RootSpanExit)?;
        // Add spanned instructions to parent.
        for (instr_name, &ct) in self.current_span.cts.iter() {
            // Always clones. Could be avoided with `raw_entry`, but it's not a big deal.
            parent_span.cts.entry(instr_name.clone()).and_modify(|x| *x += ct).or_insert(ct);
        }
        // Move to the parent span.
        let child_span = core::mem::replace(&mut self.current_span, parent_span);
        self.current_span.children.push(child_span);
        Ok(self)
    }

    /// Get the root span, consuming the builder.
    ///
    /// Yields an error if the current span is not the root span.
    pub fn finish(self) -> Result<Span<S, T>, SpanBuilderFinishError> {
        if self.parents.is_empty() {
            Ok(self.current_span)
        } else {
            Err(SpanBuilderFinishError::OpenSpan(self.current_span.name.to_string()))
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

/// A span for counting items in a recursive structure. Create and populate using [`SpanBuilder`].
/// `S` is the type of span names and `T` is the type of item names.
#[derive(Debug, Clone, Default)]
pub struct Span<S, T = S> {
    pub name: S,
    pub cts: HashMap<T, usize>,
    pub children: Vec<Span<S, T>>,
}

impl<S, T> Span<S, T>
where
    S: Display,
    T: Ord + Display + Hash,
{
    /// Create a new span with the given name.
    pub fn new(name: S) -> Self {
        Self { name, cts: Default::default(), children: Default::default() }
    }

    /// Calculate the total number of items counted by this span and its children.
    pub fn total(&self) -> usize {
        // Counts are already added from children.
        self.cts.values().cloned().sum()
    }

    /// Format and yield lines describing this span. Appropriate for logging.
    pub fn lines(&self) -> Vec<String> {
        let Self { name, cts: instr_cts, children } = self;
        let (width, lines) = sorted_table_lines(instr_cts);
        let lines = lines.map(|(label, count)| format_table_line(&width, &label, count));

        once(format!("{}", name))
            .chain(
                children
                    .iter()
                    .flat_map(|c| c.lines())
                    .chain(lines)
                    .map(|line| format!("│  {line}")),
            )
            .chain(once(format!("└╴ {} total", self.total())))
            .collect()
    }
}
