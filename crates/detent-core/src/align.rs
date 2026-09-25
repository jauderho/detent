//! Sequence alignment: a bounded greedy [Myers] diff over any `PartialEq` items.
//!
//! Two callers share it. `detent-ops` aligns the lines of two texts to build a
//! unified-diff preview, and [`Document::edit_entries`](crate::doc::Document::edit_entries)
//! aligns the entries parsed from a file with the entries of a model, so that
//! `apply` keeps every unchanged line where it is.
//!
//! # The edit-distance cap
//!
//! The search is bounded: when the edit distance exceeds [`MAX_EDIT_DISTANCE`],
//! [`align`] gives up and returns `None`. Greedy Myers costs `O(D)` passes for
//! an edit distance of `D`, so a small change in a large input is cheap and only
//! a wholesale rewrite reaches the cap. The fallback both callers use is
//! [`replace_all`]: delete every old item, then insert every new one. For a
//! diff that is a whole-file replacement hunk; for `apply` it degrades to
//! pairing entries by position. Either is correct, only coarser. That keeps
//! memory and time bounded on adversarial input, in the spirit of PLAN §2.3
//! invariant 6.
//!
//! [Myers]: http://www.xmailserver.org/diff2.pdf

/// Largest edit distance the Myers search explores before [`align`] gives up.
///
/// The search allocates `O(MAX_EDIT_DISTANCE²)` machine words in the worst
/// case, so this is what bounds its memory. Real configuration edits have an
/// edit distance of a handful of items.
pub const MAX_EDIT_DISTANCE: usize = 512;

/// One step of an edit script, as indices into the two sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Old item `.0` equals new item `.1`.
    Equal(usize, usize),
    /// Old item `.0` is gone.
    Delete(usize),
    /// New item `.0` is added.
    Insert(usize),
}

/// Read one cell of the Myers frontier. Out-of-range never happens for the
/// indices this module generates; `0` is the same value an unvisited diagonal
/// carries, so a hypothetical out-of-range read stays consistent rather than
/// panicking.
fn cell(front: &[usize], index: usize) -> usize {
    front.get(index).copied().unwrap_or(0)
}

/// Write one cell of the Myers frontier, ignoring an out-of-range index for
/// the same reason as [`cell`].
fn set_cell(front: &mut [usize], index: usize, value: usize) {
    if let Some(slot) = front.get_mut(index) {
        *slot = value;
    }
}

/// Whether the Myers step at diagonal `kidx` came from a downward (insert)
/// move rather than a rightward (delete) one.
fn came_from_down(front: &[usize], kidx: usize, lo: usize, hi: usize) -> bool {
    kidx == lo
        || (kidx != hi && cell(front, kidx.saturating_sub(1)) < cell(front, kidx.saturating_add(1)))
}

/// Aligns `old` with `new`: the shortest edit script that turns one into the
/// other, in forward order. Every old index appears exactly once, as `Equal`
/// or `Delete`, and every new index exactly once, as `Equal` or `Insert`.
///
/// Returns `None` when the edit distance exceeds [`MAX_EDIT_DISTANCE`]; the
/// caller then falls back to [`replace_all`].
///
/// `front[kidx]` is the furthest old index reached on diagonal `kidx - offset`;
/// `trace` keeps one snapshot of `front` per edit distance so [`backtrack`]
/// can reconstruct the script without a second search.
#[must_use]
pub fn align<T: PartialEq>(old: &[T], new: &[T]) -> Option<Vec<Step>> {
    let old_len = old.len();
    let new_len = new.len();
    let max_dist = old_len.saturating_add(new_len).min(MAX_EDIT_DISTANCE);
    let offset = max_dist;
    let width = max_dist.saturating_mul(2).saturating_add(1);
    let mut front = vec![0_usize; width];
    let mut trace: Vec<Vec<usize>> = Vec::new();

    for dist in 0..=max_dist {
        trace.push(front.clone());
        let lo = offset.saturating_sub(dist);
        let hi = offset.saturating_add(dist);
        let mut kidx = lo;
        while kidx <= hi {
            let mut oldi = if came_from_down(&front, kidx, lo, hi) {
                cell(&front, kidx.saturating_add(1))
            } else {
                cell(&front, kidx.saturating_sub(1)).saturating_add(1)
            };
            let mut newi = oldi.saturating_add(offset).saturating_sub(kidx);
            while oldi < old_len && newi < new_len && old.get(oldi) == new.get(newi) {
                oldi = oldi.saturating_add(1);
                newi = newi.saturating_add(1);
            }
            set_cell(&mut front, kidx, oldi);
            if oldi >= old_len && newi >= new_len {
                return Some(backtrack(&trace, offset, dist, old_len, new_len));
            }
            kidx = kidx.saturating_add(2);
        }
    }
    None
}

/// Walk the recorded snapshots back from the end of both sequences to the
/// start, emitting the edit script in forward order.
fn backtrack(
    trace: &[Vec<usize>],
    offset: usize,
    last_dist: usize,
    old_len: usize,
    new_len: usize,
) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut oldi = old_len;
    let mut newi = new_len;
    for dist in (0..=last_dist).rev() {
        let Some(front) = trace.get(dist) else { break };
        let kidx = offset.saturating_add(oldi).saturating_sub(newi);
        let lo = offset.saturating_sub(dist);
        let hi = offset.saturating_add(dist);
        let down = came_from_down(front, kidx, lo, hi);
        let prev_kidx = if down {
            kidx.saturating_add(1)
        } else {
            kidx.saturating_sub(1)
        };
        let prev_old = cell(front, prev_kidx);
        let prev_new = prev_old.saturating_add(offset).saturating_sub(prev_kidx);
        while oldi > prev_old && newi > prev_new {
            oldi = oldi.saturating_sub(1);
            newi = newi.saturating_sub(1);
            steps.push(Step::Equal(oldi, newi));
        }
        if dist > 0 {
            if down {
                newi = newi.saturating_sub(1);
                steps.push(Step::Insert(newi));
            } else {
                oldi = oldi.saturating_sub(1);
                steps.push(Step::Delete(oldi));
            }
        }
    }
    steps.reverse();
    steps
}

/// The fallback script for when [`align`] gives up: delete all `old_len` old
/// items, then insert all `new_len` new ones.
#[must_use]
pub fn replace_all(old_len: usize, new_len: usize) -> Vec<Step> {
    let mut steps = Vec::with_capacity(old_len.saturating_add(new_len));
    steps.extend((0..old_len).map(Step::Delete));
    steps.extend((0..new_len).map(Step::Insert));
    steps
}

#[cfg(test)]
mod tests {
    use super::{MAX_EDIT_DISTANCE, Step, align, replace_all};

    /// Rebuilds `new` from `old` and a script, checking that the script is
    /// well formed on the way: each old item consumed once, in order.
    fn replay<T: Clone + PartialEq>(old: &[T], new: &[T], steps: &[Step]) -> Option<Vec<T>> {
        let mut out = Vec::new();
        let mut next_old = 0_usize;
        for step in steps {
            match *step {
                Step::Equal(o, n) => {
                    if o != next_old || old.get(o) != new.get(n) {
                        return None;
                    }
                    next_old = next_old.saturating_add(1);
                    out.push(old.get(o)?.clone());
                }
                Step::Delete(o) => {
                    if o != next_old {
                        return None;
                    }
                    next_old = next_old.saturating_add(1);
                }
                Step::Insert(n) => out.push(new.get(n)?.clone()),
            }
        }
        (next_old == old.len()).then_some(out)
    }

    #[test]
    fn empty_inputs_align_to_an_empty_script() {
        assert_eq!(align::<u8>(&[], &[]), Some(Vec::new()));
    }

    #[test]
    fn a_pure_insert_keeps_every_old_item() {
        let old = [1, 2, 3];
        let new = [1, 9, 2, 3];
        assert_eq!(
            align(&old, &new),
            Some(vec![
                Step::Equal(0, 0),
                Step::Insert(1),
                Step::Equal(1, 2),
                Step::Equal(2, 3),
            ])
        );
        assert_eq!(align(&[], &[7]), Some(vec![Step::Insert(0)]));
    }

    #[test]
    fn a_pure_delete_keeps_every_remaining_item() {
        let old = ["a", "b", "c"];
        let new = ["b", "c"];
        assert_eq!(
            align(&old, &new),
            Some(vec![Step::Delete(0), Step::Equal(1, 0), Step::Equal(2, 1)])
        );
        assert_eq!(align(&[7], &[]), Some(vec![Step::Delete(0)]));
    }

    #[test]
    fn a_mixed_edit_is_minimal_and_replays() {
        let old = ["a", "b", "c", "d", "e"];
        let new = ["a", "x", "c", "e", "f"];
        let steps = align(&old, &new).unwrap_or_default();
        assert_eq!(replay(&old, &new, &steps), Some(new.to_vec()));
        let equal = steps
            .iter()
            .filter(|step| matches!(**step, Step::Equal(..)))
            .count();
        assert_eq!(equal, 3, "a, c and e are kept: {steps:?}");
        assert_eq!(steps.len(), 7, "3 kept + 2 deleted + 2 inserted");
    }

    #[test]
    fn an_edit_distance_over_the_cap_returns_none() {
        let old: Vec<usize> = (0..MAX_EDIT_DISTANCE).collect();
        let new: Vec<usize> = (MAX_EDIT_DISTANCE..MAX_EDIT_DISTANCE.saturating_mul(2)).collect();
        assert_eq!(align(&old, &new), None);
        // Exactly at the cap still succeeds.
        let half_cap = MAX_EDIT_DISTANCE.saturating_div(2);
        let half: Vec<usize> = (0..half_cap).collect();
        let other: Vec<usize> =
            (MAX_EDIT_DISTANCE..MAX_EDIT_DISTANCE.saturating_add(half_cap)).collect();
        let steps = align(&half, &other).unwrap_or_default();
        assert_eq!(steps.len(), MAX_EDIT_DISTANCE);
        assert_eq!(replay(&half, &other, &steps), Some(other.clone()));
    }

    #[test]
    fn replace_all_deletes_then_inserts() {
        assert_eq!(
            replace_all(2, 1),
            vec![Step::Delete(0), Step::Delete(1), Step::Insert(0)]
        );
        assert!(replace_all(0, 0).is_empty());
        let old = [1, 2];
        let new = [3];
        assert_eq!(replay(&old, &new, &replace_all(2, 1)), Some(vec![3]));
    }

    #[test]
    fn replay_rejects_a_malformed_script() {
        assert_eq!(
            replay(&[1], &[1], &[Step::Equal(0, 0), Step::Equal(0, 0)]),
            None
        );
        assert_eq!(replay(&[1], &[], &[Step::Delete(1)]), None);
        assert_eq!(replay::<u8>(&[1], &[], &[]), None);
        assert_eq!(replay::<u8>(&[], &[], &[Step::Insert(0)]), None);
        assert_eq!(replay::<u8>(&[1], &[1], &[Step::Equal(1, 0)]), None);
    }
}
