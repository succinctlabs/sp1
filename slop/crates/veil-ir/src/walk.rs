//! Shared DAG walker for expression arenas.
//!
//! Every backend needs to lower an [`ExprId`] to some target type `T` while
//! respecting the arena's structural sharing (don't re-emit a shared
//! sub-expression). This helper captures that pattern once.

use std::collections::HashMap;
use std::hash::Hash;

use crate::{ExprArena, ExprId, ExprKind};

/// Walk the DAG rooted at `root`, invoking `visit` once per node
/// post-order, and return the result for `root`.
///
/// `cache` is populated as the walk proceeds; pass the same map across
/// multiple roots to share work across calls (e.g. when walking every
/// expression referenced by a program's statements).
///
/// `visit` receives the node and a view of already-computed children by
/// [`ExprId`]; it is responsible for looking up its operand ids in `cache`.
pub fn walk_expr_dag<E, T, Err>(
    arena: &ExprArena<E>,
    root: ExprId,
    cache: &mut HashMap<ExprId, T>,
    mut visit: impl FnMut(&ExprKind<E>, &HashMap<ExprId, T>) -> Result<T, Err>,
) -> Result<T, Err>
where
    E: Clone + Hash + Eq,
    T: Clone,
{
    // Iterative post-order traversal. `stack` holds (id, expanded) pairs:
    // `expanded = false` means "descend into children"; `expanded = true`
    // means "all children computed, visit me now".
    let mut stack: Vec<(ExprId, bool)> = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if cache.contains_key(&id) {
            continue;
        }
        if expanded {
            let kind = &arena.get(id).kind;
            let value = visit(kind, cache)?;
            cache.insert(id, value);
            continue;
        }
        stack.push((id, true));
        match &arena.get(id).kind {
            ExprKind::ConstExt(_) | ExprKind::Var(_) | ExprKind::Challenge(_) => {
                // leaves: no children to descend
            }
            ExprKind::Add(a, b) | ExprKind::Sub(a, b) | ExprKind::Mul(a, b) => {
                stack.push((*b, false));
                stack.push((*a, false));
            }
            ExprKind::Neg(a) => {
                stack.push((*a, false));
            }
        }
    }

    Ok(cache.get(&root).expect("root was visited").clone())
}
