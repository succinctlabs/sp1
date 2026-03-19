//! Debug utilities for constraint checking.
//!
//! This module is only compiled when `sp1_debug_constraints` is enabled.
//! It provides infrastructure for naming constraints and reporting failures.

use crate::zk::dot_product::dot_product;
use slop_algebra::AbstractField;

use super::{ProofTranscript, TranscriptLinConstraint};

/// Tracks debug information for linear constraints.
///
/// Only available when compiled with `sp1_debug_constraints`.
#[derive(Debug, Clone, Default)]
pub struct ConstraintDebugger {
    names: Vec<Option<String>>,
}

impl ConstraintDebugger {
    /// Creates a new empty debugger.
    pub fn new() -> Self {
        Self { names: vec![] }
    }

    /// Called when a single constraint is added.
    pub fn on_constraint_added(&mut self) {
        self.names.push(None);
    }

    /// Called when multiple constraints are added.
    pub fn on_constraints_added(&mut self, count: usize) {
        self.names.extend(std::iter::repeat_n(None, count));
    }

    /// Names the most recently added constraint.
    ///
    /// If the constraint already has a name (e.g. an auto-captured source location),
    /// the new name is appended as `"existing_name — new_name"`.
    pub fn name_last(&mut self, name: impl Into<String>) {
        if let Some(last) = self.names.last_mut() {
            let name = name.into();
            match last {
                Some(existing) => {
                    existing.push_str(" — ");
                    existing.push_str(&name);
                }
                None => *last = Some(name),
            }
        }
    }

    /// Checks all constraints and reports any failures.
    ///
    /// For each constraint, verifies that `dot(constraint_vec, transcript) == dot(constraint_vec, masks)`.
    /// Reports failing constraints with their names (if provided) or indices.
    pub fn check_and_report<K: AbstractField + Copy + PartialEq>(
        &self,
        transcript: &ProofTranscript<K>,
        masks: &[K],
        constraints: &[TranscriptLinConstraint<K>],
    ) {
        let mut failing_constraints: Vec<String> = Vec::new();

        for (i, constraint) in constraints.iter().enumerate() {
            let constraint_vec = transcript.single_constraint_to_dot_vector(constraint);
            let transcript_dot = dot_product(&constraint_vec, &transcript.values);
            let mask_dot = dot_product(&constraint_vec, masks);

            if transcript_dot != mask_dot {
                let name = self
                    .names
                    .get(i)
                    .and_then(|n| n.as_ref())
                    .map(|s| format!("\"{}\" (index {})", s, i))
                    .unwrap_or_else(|| format!("index {}", i));
                failing_constraints.push(name);
            }
        }

        if !failing_constraints.is_empty() {
            eprintln!(
                "======== ZK-BUILDER LINEAR CONSTRAINTS FAILED ========\n\
                 Total constraints: {}\n\
                 Failing constraints:\n  {}\n\
                 ======================================================",
                constraints.len(),
                failing_constraints.join("\n  ")
            );
        }
    }
}
