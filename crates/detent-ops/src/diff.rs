//! A small in-tree line diff producing unified-diff hunks.
//!
//! PLAN §4.1's size budget rules out pulling in a diff crate for what a plan
//! preview needs, so this is the greedy [Myers] diff of
//! [`detent_core::align`] run over *lines that keep their own terminator*.
//! Keeping the `\n` (and therefore any preceding `\r`) inside the line has two
//! consequences that matter:
//!
//! * CRLF files diff and render byte-for-byte, with no normalisation step that
//!   could silently rewrite a file's line endings; and
//! * reassembling a hunk's lines is plain concatenation, which is what makes
//!   "apply the hunks to the original and get the new text back" an exact
//!   identity rather than an approximation. The property test at the bottom of
//!   this file asserts precisely that.
//!
//! The search is bounded: an edit distance above [`MAX_EDIT_DISTANCE`] falls
//! back to one whole-file replacement hunk. Greedy Myers costs `O(D)` passes
//! for an edit distance of `D`, so a one-line change in a large file is cheap
//! and only a wholesale rewrite reaches the cap — where a coarse preview is
//! the honest one anyway. That keeps memory and time bounded on adversarial
//! input, in the spirit of PLAN §2.3 invariant 6.
//!
//! [Myers]: http://www.xmailserver.org/diff2.pdf

use detent_core::align::{Step, align, replace_all};
use serde::Serialize;

/// Unchanged lines kept on each side of a change by default (PLAN §2.6: the
/// plan preview is a normal unified diff).
pub const DEFAULT_CONTEXT: usize = 3;

/// Largest edit distance the Myers search explores before giving up and
/// reporting a whole-file replacement instead; see
/// [`detent_core::align::MAX_EDIT_DISTANCE`].
pub use detent_core::align::MAX_EDIT_DISTANCE;

/// One line of a [`Hunk`], including its own line terminator when the source
/// line had one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "op", content = "text", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum DiffLine {
    /// Present in both texts.
    Context(String),
    /// Present only in the original.
    Delete(String),
    /// Present only in the candidate.
    Insert(String),
}

impl DiffLine {
    /// The line's text, terminator included.
    #[must_use]
    pub fn text(&self) -> &str {
        match *self {
            Self::Context(ref text) | Self::Delete(ref text) | Self::Insert(ref text) => text,
        }
    }

    /// The unified-diff prefix character for this line.
    #[must_use]
    pub const fn marker(&self) -> char {
        match *self {
            Self::Context(_) => ' ',
            Self::Delete(_) => '-',
            Self::Insert(_) => '+',
        }
    }
}

/// One contiguous run of changes plus its surrounding context, addressed the
/// way a unified diff addresses it: 1-based line numbers, and a start of `0`
/// when the side contributes no lines at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Hunk {
    /// First original line covered, 1-based; `0` when `old_lines` is `0`.
    pub old_start: usize,
    /// How many original lines this hunk covers.
    pub old_lines: usize,
    /// First candidate line covered, 1-based; `0` when `new_lines` is `0`.
    pub new_start: usize,
    /// How many candidate lines this hunk covers.
    pub new_lines: usize,
    /// The hunk body, in order.
    pub lines: Vec<DiffLine>,
}

impl Hunk {
    /// The `@@ -a,b +c,d @@` header for this hunk.
    #[must_use]
    pub fn header(&self) -> String {
        format!(
            "@@ -{},{} +{},{} @@",
            self.old_start, self.old_lines, self.new_start, self.new_lines
        )
    }
}

/// Split `text` into lines that each keep their own `\n`.
///
/// A file not ending in a newline yields a final line without one, which is
/// what [`render_unified`] turns into the `\ No newline at end of file`
/// marker.
fn split_lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// Running counts of original and candidate lines consumed before each step,
/// with one extra entry for "after the last step".
fn positions(steps: &[Step]) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(steps.len().saturating_add(1));
    let mut old = 0_usize;
    let mut new = 0_usize;
    out.push((old, new));
    for step in steps {
        match *step {
            Step::Equal(..) => {
                old = old.saturating_add(1);
                new = new.saturating_add(1);
            }
            Step::Delete(_) => old = old.saturating_add(1),
            Step::Insert(_) => new = new.saturating_add(1),
        }
        out.push((old, new));
    }
    out
}

/// Step-index ranges that a hunk must cover: every changed step, widened by
/// `context` on each side, with overlapping or touching ranges merged.
fn groups(steps: &[Step], context: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        if matches!(*step, Step::Equal(..)) {
            continue;
        }
        let start = index.saturating_sub(context);
        let end = index
            .saturating_add(context)
            .saturating_add(1)
            .min(steps.len());
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// A unified-diff start line.
///
/// When the side contributes lines this is the 1-based number of the first of
/// them. When it contributes none — a pure insertion has no original lines, a
/// pure deletion no candidate ones — the convention is the number of lines
/// that precede the change, so `0` only for a change at the very start of an
/// empty side. Getting this wrong makes the hunk unappliable, which is what
/// the property test at the bottom of this file exists to catch.
fn start_of(begin: usize, count: usize) -> usize {
    if count == 0 {
        begin
    } else {
        begin.saturating_add(1)
    }
}

/// Diff `old` against `new`, keeping `context` unchanged lines around each
/// change.
///
/// The result is empty exactly when the two texts are identical.
#[must_use]
pub fn diff(old: &str, new: &str, context: usize) -> Vec<Hunk> {
    let old_lines = split_lines(old);
    let new_lines = split_lines(new);
    if old_lines == new_lines {
        return Vec::new();
    }
    let steps = align(&old_lines, &new_lines)
        .unwrap_or_else(|| replace_all(old_lines.len(), new_lines.len()));
    let at = positions(&steps);
    let mut hunks = Vec::new();
    for (start, end) in groups(&steps, context) {
        let (old_begin, new_begin) = at.get(start).copied().unwrap_or((0, 0));
        let (old_end, new_end) = at.get(end).copied().unwrap_or((0, 0));
        let old_count = old_end.saturating_sub(old_begin);
        let new_count = new_end.saturating_sub(new_begin);
        let mut lines = Vec::with_capacity(end.saturating_sub(start));
        for step in steps.get(start..end).unwrap_or_default() {
            let line = match *step {
                Step::Equal(index, _) => DiffLine::Context(text_at(&old_lines, index)),
                Step::Delete(index) => DiffLine::Delete(text_at(&old_lines, index)),
                Step::Insert(index) => DiffLine::Insert(text_at(&new_lines, index)),
            };
            lines.push(line);
        }
        hunks.push(Hunk {
            old_start: start_of(old_begin, old_count),
            old_lines: old_count,
            new_start: start_of(new_begin, new_count),
            new_lines: new_count,
            lines,
        });
    }
    hunks
}

/// Owned copy of one line, or the empty string for an index the edit script
/// can never produce.
fn text_at(lines: &[&str], index: usize) -> String {
    lines.get(index).copied().unwrap_or_default().to_owned()
}

/// Render `hunks` as a unified diff, with the usual `---`/`+++` header.
///
/// Returns the empty string when there are no hunks, so a caller can treat
/// "no diff" and "nothing to show" identically.
#[must_use]
pub fn render_unified(old_label: &str, new_label: &str, hunks: &[Hunk]) -> String {
    if hunks.is_empty() {
        return String::new();
    }
    let mut out = format!("--- {old_label}\n+++ {new_label}\n");
    for hunk in hunks {
        out.push_str(&hunk.header());
        out.push('\n');
        for line in &hunk.lines {
            out.push(line.marker());
            let text = line.text();
            out.push_str(text);
            if !text.ends_with('\n') {
                out.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_CONTEXT, DiffLine, Hunk, MAX_EDIT_DISTANCE, diff, render_unified, split_lines,
    };
    use proptest::prelude::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// Rebuild the candidate text from the original and a hunk list. This is
    /// the inverse the property test pins down; production code never needs
    /// it, so it lives here rather than in the public API.
    fn apply_hunks(old: &str, hunks: &[Hunk]) -> String {
        let lines = split_lines(old);
        let mut out = String::with_capacity(old.len());
        let mut cursor = 0_usize;
        for hunk in hunks {
            let begin = if hunk.old_lines == 0 {
                hunk.old_start
            } else {
                hunk.old_start.saturating_sub(1)
            };
            for line in lines.get(cursor..begin).unwrap_or_default() {
                out.push_str(line);
            }
            cursor = begin;
            for line in &hunk.lines {
                match *line {
                    DiffLine::Context(ref text) => {
                        out.push_str(text);
                        cursor = cursor.saturating_add(1);
                    }
                    DiffLine::Delete(_) => cursor = cursor.saturating_add(1),
                    DiffLine::Insert(ref text) => out.push_str(text),
                }
            }
        }
        for line in lines.get(cursor..).unwrap_or_default() {
            out.push_str(line);
        }
        out
    }

    fn roundtrip(old: &str, new: &str) -> String {
        apply_hunks(old, &diff(old, new, DEFAULT_CONTEXT))
    }

    #[test]
    fn splitting_keeps_terminators_and_handles_a_missing_final_newline() {
        assert!(split_lines("").is_empty());
        assert_eq!(split_lines("a\n"), vec!["a\n"]);
        assert_eq!(split_lines("a\nb"), vec!["a\n", "b"]);
        assert_eq!(split_lines("a\r\nb\r\n"), vec!["a\r\n", "b\r\n"]);
    }

    #[test]
    fn identical_inputs_produce_no_hunks() {
        assert!(diff("", "", DEFAULT_CONTEXT).is_empty());
        assert!(diff("a\nb\n", "a\nb\n", DEFAULT_CONTEXT).is_empty());
        assert_eq!(render_unified("a", "b", &[]), "");
    }

    #[test]
    fn empty_to_nonempty_is_all_insertions() {
        let hunks = diff("", "a\nb\n", DEFAULT_CONTEXT);
        assert_eq!(hunks.len(), 1);
        assert_eq!(
            hunks.first().map(Hunk::header),
            Some("@@ -0,0 +1,2 @@".to_owned())
        );
        assert_eq!(hunks.first().map(|h| h.old_start), Some(0));
        assert_eq!(hunks.first().map(|h| h.old_lines), Some(0));
        assert_eq!(hunks.first().map(|h| h.new_start), Some(1));
        assert_eq!(hunks.first().map(|h| h.new_lines), Some(2));
        assert!(
            hunks
                .iter()
                .flat_map(|hunk| &hunk.lines)
                .all(|line| matches!(*line, DiffLine::Insert(_)))
        );
        assert_eq!(roundtrip("", "a\nb\n"), "a\nb\n");
    }

    #[test]
    fn nonempty_to_empty_is_all_deletions() {
        let hunks = diff("a\nb\n", "", DEFAULT_CONTEXT);
        assert_eq!(hunks.len(), 1);
        assert_eq!(
            hunks.first().map(Hunk::header),
            Some("@@ -1,2 +0,0 @@".to_owned())
        );
        assert!(
            hunks
                .iter()
                .flat_map(|hunk| &hunk.lines)
                .all(|line| matches!(*line, DiffLine::Delete(_)))
        );
        assert_eq!(roundtrip("a\nb\n", ""), "");
    }

    #[test]
    fn pure_insertion_keeps_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n";
        let new = "1\n2\n3\n4\nX\n5\n6\n7\n8\n";
        let hunks = diff(old, new, DEFAULT_CONTEXT);
        assert_eq!(hunks.len(), 1);
        assert_eq!(
            hunks.first().map(Hunk::header),
            Some("@@ -2,6 +2,7 @@".to_owned())
        );
        assert_eq!(
            hunks
                .iter()
                .flat_map(|hunk| &hunk.lines)
                .filter(|line| matches!(**line, DiffLine::Insert(_)))
                .count(),
            1
        );
        assert_eq!(roundtrip(old, new), new);
    }

    #[test]
    fn pure_deletion_keeps_context() {
        let old = "1\n2\n3\n4\nX\n5\n6\n7\n8\n";
        let new = "1\n2\n3\n4\n5\n6\n7\n8\n";
        assert_eq!(roundtrip(old, new), new);
        let hunks = diff(old, new, DEFAULT_CONTEXT);
        assert_eq!(hunks.len(), 1);
        let rendered = render_unified("old", "new", &hunks);
        assert!(rendered.starts_with("--- old\n+++ new\n@@ "));
        assert!(rendered.contains("-X\n"));
    }

    #[test]
    fn two_distant_changes_become_two_hunks() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n";
        let new = "A\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nL\n";
        let hunks = diff(old, new, DEFAULT_CONTEXT);
        assert_eq!(hunks.len(), 2);
        assert_eq!(roundtrip(old, new), new);
    }

    #[test]
    fn nearby_changes_merge_into_one_hunk() {
        let old = "a\nb\nc\nd\ne\n";
        let new = "A\nb\nc\nd\nE\n";
        assert_eq!(diff(old, new, DEFAULT_CONTEXT).len(), 1);
        assert_eq!(roundtrip(old, new), new);
    }

    #[test]
    fn zero_context_emits_only_changed_lines() {
        let old = "a\nb\nc\n";
        let new = "a\nX\nc\n";
        let hunks = diff(old, new, 0);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks.first().map(|hunk| hunk.lines.len()), Some(2));
        assert_eq!(roundtrip(old, new), new);
    }

    #[test]
    fn crlf_content_survives_unchanged() {
        let old = "a\r\nb\r\n";
        let new = "a\r\nX\r\nb\r\n";
        assert_eq!(roundtrip(old, new), new);
        let rendered = render_unified("old", "new", &diff(old, new, DEFAULT_CONTEXT));
        assert!(rendered.contains("+X\r\n"));
        // Mixed endings must not be normalised either.
        assert_eq!(roundtrip("a\r\n", "a\n"), "a\n");
    }

    #[test]
    fn a_missing_final_newline_is_marked() {
        let rendered = render_unified("old", "new", &diff("a\n", "a\nb", DEFAULT_CONTEXT));
        assert!(rendered.contains("\\ No newline at end of file\n"));
        assert_eq!(roundtrip("a\n", "a\nb"), "a\nb");
        assert_eq!(roundtrip("a", "a\n"), "a\n");
    }

    #[test]
    fn diff_line_accessors_cover_every_variant() {
        let lines = [
            DiffLine::Context("c".to_owned()),
            DiffLine::Delete("d".to_owned()),
            DiffLine::Insert("i".to_owned()),
        ];
        let markers: String = lines.iter().map(DiffLine::marker).collect();
        assert_eq!(markers, " -+");
        assert_eq!(lines.iter().map(DiffLine::text).collect::<String>(), "cdi");
        assert_eq!(lines.first(), lines.first());
        assert!(format!("{lines:?}").contains("Context"));
    }

    #[test]
    fn hunks_serialize_for_the_api() -> R {
        let hunks = diff("a\n", "b\n", DEFAULT_CONTEXT);
        let json = serde_json::to_value(&hunks)?;
        assert_eq!(
            json.pointer("/0/lines/0/op").and_then(|v| v.as_str()),
            Some("delete")
        );
        assert_eq!(
            json.pointer("/0/lines/0/text").and_then(|v| v.as_str()),
            Some("a\n")
        );
        assert_eq!(hunks.first().cloned(), hunks.first().cloned());
        Ok(())
    }

    #[test]
    fn an_edit_distance_over_the_cap_falls_back_to_a_whole_file_replacement() {
        // Every line differs, so the edit distance is 2 * lines, comfortably
        // past `MAX_EDIT_DISTANCE` and therefore onto the fallback path.
        let lines = MAX_EDIT_DISTANCE;
        let old: String = (0..lines)
            .map(|index| index.to_string())
            .map(|index| ["old-", &index, "\n"].concat())
            .collect();
        let new: String = (0..lines)
            .map(|index| index.to_string())
            .map(|index| ["new-", &index, "\n"].concat())
            .collect();
        let hunks = diff(&old, &new, DEFAULT_CONTEXT);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks.first().map(|hunk| hunk.old_lines), Some(lines));
        assert_eq!(hunks.first().map(|hunk| hunk.new_lines), Some(lines));
        assert_eq!(apply_hunks(&old, &hunks), new);
    }

    /// Line alphabet small enough that the diff finds real common
    /// subsequences rather than replacing everything, and including CRLF and
    /// unterminated lines.
    fn line() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("alpha\n".to_owned()),
            Just("beta\n".to_owned()),
            Just("gamma\r\n".to_owned()),
            Just("\n".to_owned()),
            Just("  indented\n".to_owned()),
        ]
    }

    fn text() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec(line(), 0..12),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(mut lines, tail, empty)| {
                if empty {
                    return String::new();
                }
                if tail {
                    lines.push("no-newline".to_owned());
                }
                lines.concat()
            })
    }

    proptest! {
        /// The invariant that makes the hunks trustworthy: applying them to
        /// the original reproduces the candidate exactly, for every context
        /// width.
        #[test]
        fn applying_the_hunks_reproduces_the_new_text(
            old in text(),
            new in text(),
            context in 0_usize..5,
        ) {
            let hunks = diff(&old, &new, context);
            proptest::prop_assert_eq!(apply_hunks(&old, &hunks), new.clone());
            proptest::prop_assert_eq!(hunks.is_empty(), old == new);
        }

        /// Rendering never loses a line: every hunk line appears in the
        /// unified text with its marker.
        #[test]
        fn rendering_covers_every_hunk_line(old in text(), new in text()) {
            let hunks = diff(&old, &new, DEFAULT_CONTEXT);
            let rendered = render_unified("a", "b", &hunks);
            let body_lines: usize = hunks.iter().map(|hunk| hunk.lines.len()).sum();
            proptest::prop_assert_eq!(rendered.is_empty(), hunks.is_empty());
            if !hunks.is_empty() {
                proptest::prop_assert!(rendered.lines().count() >= body_lines);
            }
        }
    }
}
