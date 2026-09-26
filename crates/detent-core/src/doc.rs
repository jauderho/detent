//! Lossless, line-oriented concrete syntax tree.
//!
//! Line-based config formats (`/etc/hosts`, `resolv.conf`, `fstab`, `exports`,
//! `chrony.conf`, …) all share the same shape: a sequence of lines, each of which is
//! blank, a comment, a directive, or something the module does not recognise. This
//! module models exactly that and nothing more, preserving the original bytes so that
//! [`Document::render`] reproduces its input byte for byte.
//!
//! Formats with a richer grammar (INI, YAML, JSON) get their own concrete syntax tree
//! in the module that needs it, but reuse [`Span`] and
//! [`Diagnostic`](crate::diag::Diagnostic).
//!
//! # Losslessness
//!
//! `render(parse(s, c)) == s` holds for **every** `&str`: empty input, input without a
//! trailing newline, mixed `\n`/`\r\n` endings, lone `\r`, and embedded NUL. A lone
//! `\r` is *not* a line terminator; it stays inside [`Line::raw`].

use crate::align::{Step, align, replace_all};
use crate::module::{EditError, EditReport, LosslessDoc};

/// A byte range within the text a [`Document`] was parsed from.
///
/// `start` is inclusive, `end` is exclusive. Both are byte offsets, not character
/// offsets, and always fall on UTF-8 boundaries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Span {
    /// Creates a span covering `start..end`.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// The terminator that followed a line in the original text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum LineEnding {
    /// Unix line ending, `\n`.
    Lf,
    /// DOS line ending, `\r\n`.
    CrLf,
    /// No terminator: this is the last line of a file that does not end in a newline.
    None,
}

impl LineEnding {
    /// The bytes this ending renders to.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::CrLf => "\r\n",
            Self::None => "",
        }
    }
}

/// What a module's classifier made of a line.
///
/// The classifier is supplied per module because "comment" and "directive" are
/// format-specific; the core only needs the four buckets to drive generic editing and
/// diffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum LineKind {
    /// Empty or whitespace-only.
    Blank,
    /// A comment line.
    Comment,
    /// A directive the module understands.
    Directive,
    /// Anything else: preserved verbatim, never rewritten.
    Unknown,
}

/// One line of a [`Document`], including the exact bytes it was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    kind: LineKind,
    raw: String,
    ending: LineEnding,
    span: Span,
}

impl Line {
    /// Creates a line for `Document::rebuild` callers and tests.
    #[must_use]
    pub fn new(raw: String, kind: LineKind, ending: LineEnding) -> Self {
        Self {
            raw,
            kind,
            ending,
            span: Span::new(0, 0),
        }
    }

    /// The classification assigned by the module's classifier.
    #[must_use]
    pub const fn kind(&self) -> LineKind {
        self.kind
    }

    /// The exact bytes of the line, excluding its terminator.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The terminator that follows this line.
    #[must_use]
    pub const fn ending(&self) -> LineEnding {
        self.ending
    }

    /// The byte range of [`Line::raw`] within the document text.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// A read-only plan of entry edits, built by [`Document::plan_entries`] and
/// carried out by [`Document::apply_plan`].
///
/// Line numbers refer to the document the plan was built from. Plans built from
/// one document for disjoint sets of lines — one per flavor of a multi-format
/// module — can be combined with [`EntryPlan::extend`] and applied in one pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct EntryPlan {
    /// `(line, raw)`: rewrite line `line` in place, keeping its terminator.
    replace: Vec<(usize, String)>,
    /// Lines to remove.
    remove: Vec<usize>,
    /// `(at, raw)`: insert a new line before original line `at`; `at == len()`
    /// appends. Inserts at the same `at` keep the order they were added in.
    insert: Vec<(usize, String)>,
}

impl EntryPlan {
    /// Adds the edits of `other`, a plan for other lines of the same document.
    /// Its inserts go after this plan's inserts at the same position.
    pub fn extend(&mut self, other: Self) {
        self.replace.extend(other.replace);
        self.remove.extend(other.remove);
        self.insert.extend(other.insert);
    }

    /// Adds: rewrite line `line` as `raw`, keeping its terminator. A plan
    /// takes at most one rewrite or removal per line.
    ///
    /// # Errors
    ///
    /// [`EditError::LineBreakInValue`] if `raw` contains `\n`, `\r` or NUL.
    pub fn replace(&mut self, line: usize, raw: String) -> Result<(), EditError> {
        check_raw(&raw)?;
        self.replace.push((line, raw));
        Ok(())
    }

    /// Adds: remove line `line`. A plan takes at most one rewrite or removal
    /// per line.
    pub fn remove(&mut self, line: usize) {
        self.remove.push(line);
    }

    /// Adds: insert `raw` as a new line before original line `at`; `at` at or
    /// past the end appends. Inserts at the same `at` keep the order they were
    /// added in.
    ///
    /// # Errors
    ///
    /// [`EditError::LineBreakInValue`] if `raw` contains `\n`, `\r` or NUL.
    pub fn insert(&mut self, at: usize, raw: String) -> Result<(), EditError> {
        check_raw(&raw)?;
        self.insert.push((at, raw));
        Ok(())
    }
}

/// Where one wanted entry of [`Document::plan_entries`] ends up.
enum Slot {
    /// On this existing line, kept or rewritten in place.
    Line(usize),
    /// On a new line with this text.
    New(String),
}

/// Settles one run of changes between two kept entries: the run's deleted
/// lines are paired, in order, with its new entries and rewritten in place;
/// deleted lines left over are removed, and new entries left over become new
/// lines. Renders every new entry, which is the only fallible step.
fn settle_run<T>(
    deleted: &mut Vec<usize>,
    inserted: &mut Vec<&T>,
    render: &impl Fn(&T) -> Result<String, EditError>,
    plan: &mut EntryPlan,
    slots: &mut Vec<Slot>,
) -> Result<(), EditError> {
    let mut gone = deleted.drain(..);
    for entry in inserted.drain(..) {
        let raw = render(entry)?;
        check_raw(&raw)?;
        if let Some(row) = gone.next() {
            plan.replace.push((row, raw));
            slots.push(Slot::Line(row));
        } else {
            slots.push(Slot::New(raw));
        }
    }
    plan.remove.extend(gone);
    Ok(())
}

/// A parsed line-oriented config file.
///
/// The line vector is private so that the ending policy and the spans cannot be
/// desynchronised from the text; use [`Document::insert_line`],
/// [`Document::replace_raw`] and [`Document::remove_line`] to edit.
#[derive(Debug, Clone)]
pub struct Document {
    lines: Vec<Line>,
    classify: fn(&str) -> LineKind,
}

/// Two documents are equal when their lines are equal. The classifier function
/// pointer is metadata, not content, and is deliberately not compared.
impl PartialEq for Document {
    fn eq(&self, other: &Self) -> bool {
        self.lines == other.lines
    }
}

impl Eq for Document {}

impl LosslessDoc for Document {
    fn render(&self) -> String {
        Self::render(self)
    }
}

impl Document {
    /// Splits `src` into lines, classifying each with `classify`.
    ///
    /// Total: succeeds on any `&str` and never panics.
    #[must_use]
    pub fn parse(src: &str, classify: fn(&str) -> LineKind) -> Self {
        let mut lines = Vec::new();
        let mut offset = 0usize;
        for segment in src.split_inclusive('\n') {
            let (raw, ending) = match segment.strip_suffix('\n') {
                Some(body) => match body.strip_suffix('\r') {
                    Some(body) => (body, LineEnding::CrLf),
                    None => (body, LineEnding::Lf),
                },
                None => (segment, LineEnding::None),
            };
            lines.push(Line {
                kind: classify(raw),
                raw: raw.to_owned(),
                ending,
                span: Span::new(offset, offset.saturating_add(raw.len())),
            });
            offset = offset.saturating_add(segment.len());
        }
        Self { lines, classify }
    }

    /// Reconstructs the document text. Runs in O(total bytes).
    #[must_use]
    pub fn render(&self) -> String {
        let capacity = self.lines.iter().fold(0usize, |acc, line| {
            acc.saturating_add(line.raw.len()).saturating_add(2)
        });
        let mut out = String::with_capacity(capacity);
        for line in &self.lines {
            out.push_str(&line.raw);
            out.push_str(line.ending.as_str());
        }
        out
    }

    /// All lines, in document order.
    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// Number of lines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether the document has no lines (true only for empty input).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Iterates over the lines the classifier assigned `kind`.
    pub fn lines_of_kind(&self, kind: LineKind) -> impl Iterator<Item = &Line> {
        self.lines.iter().filter(move |line| line.kind == kind)
    }

    /// The ending new lines inherit: `CrLf` when the document uses more `\r\n` than
    /// `\n`, otherwise `Lf` (which is also the answer for an empty document).
    #[must_use]
    pub fn dominant_ending(&self) -> LineEnding {
        let mut crlf = 0usize;
        let mut lf = 0usize;
        for line in &self.lines {
            match line.ending {
                LineEnding::CrLf => crlf = crlf.saturating_add(1),
                LineEnding::Lf => lf = lf.saturating_add(1),
                LineEnding::None => {}
            }
        }
        if crlf > lf {
            LineEnding::CrLf
        } else {
            LineEnding::Lf
        }
    }

    /// Returns the classifier function this document was parsed with.
    #[must_use]
    pub fn classifier(&self) -> fn(&str) -> LineKind {
        self.classify
    }

    /// Batch-mutates the document in one pass, normalising only once.
    ///
    /// M20's shared helper funnels every `apply` through here so a 200k-line file
    /// does not pay O(n) `normalize` per edited line.
    pub fn rebuild<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Vec<Line>),
    {
        f(&mut self.lines);
        self.normalize();
    }

    /// Inserts a new line before position `idx`; `idx == len()` appends.
    ///
    /// The new line inherits [`Document::dominant_ending`]. Appending to a document
    /// whose last line has no terminator moves that terminator-less state onto the new
    /// last line, so a file that did not end in a newline still does not.
    ///
    /// # Errors
    ///
    /// [`EditError::LineBreakInValue`] if `raw` contains `\n`, `\r` or NUL (invariant
    /// 5: a value can never smuggle in an extra directive), and
    /// [`EditError::IndexOutOfRange`] if `idx > len()`.
    pub fn insert_line(&mut self, idx: usize, raw: &str) -> Result<(), EditError> {
        check_raw(raw)?;
        if idx > self.lines.len() {
            return Err(EditError::IndexOutOfRange {
                index: idx,
                len: self.lines.len(),
            });
        }
        let dominant = self.dominant_ending();
        let mut ending = dominant;
        if idx == self.lines.len()
            && let Some(last) = self.lines.last_mut()
            && last.ending == LineEnding::None
        {
            last.ending = dominant;
            ending = LineEnding::None;
        }
        self.lines.insert(
            idx,
            Line {
                kind: (self.classify)(raw),
                raw: raw.to_owned(),
                ending,
                span: Span::new(0, 0),
            },
        );
        self.normalize();
        Ok(())
    }

    /// Replaces the text of line `idx`, keeping its terminator.
    ///
    /// # Errors
    ///
    /// [`EditError::LineBreakInValue`] if `raw` contains `\n`, `\r` or NUL, and
    /// [`EditError::IndexOutOfRange`] if `idx >= len()`.
    pub fn replace_raw(&mut self, idx: usize, raw: &str) -> Result<(), EditError> {
        check_raw(raw)?;
        let kind = (self.classify)(raw);
        let len = self.lines.len();
        let Some(line) = self.lines.get_mut(idx) else {
            return Err(EditError::IndexOutOfRange { index: idx, len });
        };
        line.kind = kind;
        raw.clone_into(&mut line.raw);
        self.normalize();
        Ok(())
    }

    /// Removes line `idx`.
    ///
    /// If the removed line was the terminator-less last line, the new last line loses
    /// its terminator too, so the file's trailing-newline state is preserved.
    ///
    /// # Errors
    ///
    /// [`EditError::IndexOutOfRange`] if `idx >= len()`.
    pub fn remove_line(&mut self, idx: usize) -> Result<(), EditError> {
        if idx >= self.lines.len() {
            return Err(EditError::IndexOutOfRange {
                index: idx,
                len: self.lines.len(),
            });
        }
        let removed = self.lines.remove(idx);
        if removed.ending == LineEnding::None
            && let Some(last) = self.lines.last_mut()
        {
            last.ending = LineEnding::None;
        }
        self.normalize();
        Ok(())
    }

    /// Plans the edits that make this document's entries equal `wanted`,
    /// without touching the document.
    ///
    /// The entries are the [`LineKind::Directive`] lines that `parse` accepts.
    /// They are aligned with `wanted` by [`align`], so:
    ///
    /// * an entry that is unchanged keeps its line byte for byte, in place —
    ///   hand-aligned columns survive and later lines are never rewritten;
    /// * a changed entry is rewritten in place (a deleted entry paired with a
    ///   new one between the same two unchanged entries);
    /// * a deleted entry loses its line;
    /// * a new entry goes directly after the line of the entry before it in
    ///   `wanted`, which is in the same section. A new entry that itself opens
    ///   a section (`opens_section` of its rendered text) instead goes at the
    ///   end of the previous entry's section, before any blank and comment
    ///   lines that lead into the next one. A new entry with no entry before it
    ///   goes before the next kept entry, or at the end of the file when there
    ///   is none.
    ///
    /// `opens_section` is the module's notion of a section header, applied to
    /// raw line text; a module without sections passes `|_| false`, so its file
    /// is one section. Past [`MAX_EDIT_DISTANCE`](crate::align::MAX_EDIT_DISTANCE)
    /// the alignment falls back to [`replace_all`], which pairs entries by
    /// position: still correct, only coarser.
    ///
    /// Every new or changed entry is rendered here, before any edit, so a
    /// rejected value leaves the document untouched.
    ///
    /// # Errors
    ///
    /// Whatever `render` returns, and [`EditError::LineBreakInValue`] if a
    /// rendered line contains `\n`, `\r` or NUL.
    pub fn plan_entries<T: PartialEq>(
        &self,
        wanted: &[T],
        parse: impl Fn(&str) -> Option<T>,
        render: impl Fn(&T) -> Result<String, EditError>,
        opens_section: impl Fn(&str) -> bool,
    ) -> Result<EntryPlan, EditError> {
        let mut rows = Vec::new();
        let mut have = Vec::new();
        for (row, line) in self.lines.iter().enumerate() {
            if line.kind == LineKind::Directive
                && let Some(entry) = parse(&line.raw)
            {
                rows.push(row);
                have.push(entry);
            }
        }
        let steps = align(&have, wanted).unwrap_or_else(|| replace_all(have.len(), wanted.len()));

        let mut plan = EntryPlan::default();
        let mut slots = Vec::with_capacity(wanted.len());
        let mut deleted = Vec::new();
        let mut inserted = Vec::new();
        for step in steps {
            match step {
                Step::Delete(old) => deleted.extend(rows.get(old).copied()),
                Step::Insert(new) => inserted.extend(wanted.get(new)),
                Step::Equal(old, _) => {
                    settle_run(&mut deleted, &mut inserted, &render, &mut plan, &mut slots)?;
                    slots.extend(rows.get(old).copied().map(Slot::Line));
                }
            }
        }
        settle_run(&mut deleted, &mut inserted, &render, &mut plan, &mut slots)?;

        // The line of the next entry that has one, for each slot.
        let mut next_rows = Vec::with_capacity(slots.len());
        let mut next_row = None;
        for slot in slots.iter().rev() {
            next_rows.push(next_row);
            if let Slot::Line(row) = *slot {
                next_row = Some(row);
            }
        }
        next_rows.reverse();

        let mut at: Option<usize> = None;
        for (slot, next_row) in slots.into_iter().zip(next_rows) {
            match slot {
                Slot::Line(row) => at = Some(row.saturating_add(1)),
                Slot::New(raw) => {
                    let limit = next_row.unwrap_or(self.lines.len());
                    let here = match at {
                        Some(from) if opens_section(&raw) => {
                            self.section_end(from, limit, &opens_section)
                        }
                        Some(from) => from,
                        None => limit,
                    };
                    plan.insert.push((here, raw));
                    at = Some(here);
                }
            }
        }
        Ok(plan)
    }

    /// Where the section containing line `from - 1` ends: the next line in
    /// `from..limit` that opens a section, or `limit`, moved back over the blank
    /// and comment lines just before it but never before `from`.
    ///
    /// [`Document::plan_entries`] puts a new section header here; a module that
    /// builds its own [`EntryPlan`] does the same with it.
    #[must_use]
    pub fn section_end(
        &self,
        from: usize,
        limit: usize,
        opens_section: &impl Fn(&str) -> bool,
    ) -> usize {
        let mut end = self
            .lines
            .iter()
            .enumerate()
            .take(limit)
            .skip(from)
            .find(|(_, line)| opens_section(&line.raw))
            .map_or(limit, |(row, _)| row);
        while end > from
            && self
                .lines
                .get(end.saturating_sub(1))
                .is_some_and(|line| matches!(line.kind, LineKind::Blank | LineKind::Comment))
        {
            end = end.saturating_sub(1);
        }
        end
    }

    /// Carries out a plan from [`Document::plan_entries`] in one pass,
    /// normalising once.
    ///
    /// New lines are classified with [`Document::classifier`] and inherit
    /// [`Document::dominant_ending`]; a rewritten line keeps its terminator. A
    /// file that did not end in a newline still does not.
    pub fn apply_plan(&mut self, plan: EntryPlan) -> EditReport {
        let EntryPlan {
            mut replace,
            mut remove,
            mut insert,
        } = plan;
        let report = EditReport {
            changed_lines: replace.len(),
            added: insert.len(),
            removed: remove.len(),
        };
        replace.sort_by_key(|&(row, _)| row);
        remove.sort_unstable();
        insert.sort_by_key(|&(at, _)| at);
        let classify = self.classifier();
        let dominant = self.dominant_ending();
        let new_line = |raw: String| {
            let kind = classify(&raw);
            Line::new(raw, kind, dominant)
        };
        self.rebuild(|lines| {
            let old = std::mem::take(lines);
            let unterminated = old
                .last()
                .is_some_and(|line| line.ending == LineEnding::None);
            let mut replace = replace.into_iter().peekable();
            let mut remove = remove.into_iter().peekable();
            let mut insert = insert.into_iter().peekable();
            for (row, mut line) in old.into_iter().enumerate() {
                while let Some((_, raw)) = insert.next_if(|&(at, _)| at <= row) {
                    lines.push(new_line(raw));
                }
                if remove.next_if_eq(&row).is_some() {
                    continue;
                }
                if let Some((_, raw)) = replace.next_if(|&(at, _)| at == row) {
                    line.kind = classify(&raw);
                    line.raw = raw;
                }
                if line.ending == LineEnding::None {
                    line.ending = dominant;
                }
                lines.push(line);
            }
            lines.extend(insert.map(|(_, raw)| new_line(raw)));
            if unterminated && let Some(last) = lines.last_mut() {
                last.ending = LineEnding::None;
            }
        });
        report
    }

    /// Makes this document's entries equal `wanted`: [`Document::plan_entries`]
    /// followed by [`Document::apply_plan`]. On error the document is untouched.
    ///
    /// # Errors
    ///
    /// As [`Document::plan_entries`].
    pub fn edit_entries<T: PartialEq>(
        &mut self,
        wanted: &[T],
        parse: impl Fn(&str) -> Option<T>,
        render: impl Fn(&T) -> Result<String, EditError>,
        opens_section: impl Fn(&str) -> bool,
    ) -> Result<EditReport, EditError> {
        let plan = self.plan_entries(wanted, parse, render, opens_section)?;
        Ok(self.apply_plan(plan))
    }

    /// Restores the two properties an edit can break, then recomputes every span.
    ///
    /// A document is *canonical* when re-parsing its rendered text yields an equal
    /// document. Two edits can leave it non-canonical, and both are repaired here
    /// without changing a single rendered byte:
    ///
    /// * A line whose text ends in `\r` that has just been given an `Lf` terminator
    ///   renders as `\r\n`, which re-parses as `CrLf`. The `\r` is moved into the
    ///   terminator.
    /// * A trailing empty line with no terminator renders as nothing at all, so it
    ///   is dropped. Only the last line can lack a terminator, so one pass suffices.
    fn normalize(&mut self) {
        for line in &mut self.lines {
            if line.ending == LineEnding::Lf && line.raw.ends_with('\r') {
                line.raw.pop();
                line.ending = LineEnding::CrLf;
            }
        }
        if self
            .lines
            .last()
            .is_some_and(|l| l.ending == LineEnding::None && l.raw.is_empty())
        {
            self.lines.pop();
        }
        let mut offset = 0usize;
        for line in &mut self.lines {
            line.span = Span::new(offset, offset.saturating_add(line.raw.len()));
            offset = line.span.end.saturating_add(line.ending.as_str().len());
        }
    }
}

/// Rejects text that would break out of its line.
fn check_raw(raw: &str) -> Result<(), EditError> {
    if raw.contains(['\n', '\r', '\0']) {
        return Err(EditError::LineBreakInValue {
            value: raw.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Document, EditError, EditReport, Line, LineEnding, LineKind, LosslessDoc, Span};
    use crate::align::MAX_EDIT_DISTANCE;

    fn classify(raw: &str) -> LineKind {
        if raw.trim().is_empty() {
            LineKind::Blank
        } else if raw.starts_with('#') {
            LineKind::Comment
        } else if raw.contains('=') {
            LineKind::Directive
        } else {
            LineKind::Unknown
        }
    }

    fn parse(src: &str) -> Document {
        Document::parse(src, classify)
    }

    #[test]
    fn round_trips_every_shape() {
        for src in [
            "",
            "\n",
            "\r",
            "\r\n",
            "a",
            "a\n",
            "a\r\n",
            "a\nb",
            "a\r\nb\nc\r\n",
            "\0",
            "x\0y\n",
            "\n\n\r\n",
            "  \t  \n#c\nk=v\n",
            "a\r\rb\n",
            "é日\n",
        ] {
            let doc = parse(src);
            assert_eq!(doc.render(), src, "round trip failed for {src:?}");
            assert_eq!(LosslessDoc::render(&doc), src);
        }
    }

    #[test]
    fn large_input_round_trips() {
        let src = "key=value\r\n# comment\n\n".repeat(60_000);
        let doc = parse(&src);
        assert!(doc.len() > 100_000);
        assert_eq!(doc.render(), src);
    }

    #[test]
    fn classifies_and_spans() {
        let doc = parse("# c\r\n\nk=v\nplain");
        assert_eq!(doc.len(), 4);
        assert!(!doc.is_empty());
        assert!(parse("").is_empty());
        let kinds: Vec<LineKind> = doc.lines().iter().map(Line::kind).collect();
        assert_eq!(
            kinds,
            vec![
                LineKind::Comment,
                LineKind::Blank,
                LineKind::Directive,
                LineKind::Unknown
            ]
        );
        let endings: Vec<LineEnding> = doc.lines().iter().map(Line::ending).collect();
        assert_eq!(
            endings,
            vec![
                LineEnding::CrLf,
                LineEnding::Lf,
                LineEnding::Lf,
                LineEnding::None
            ]
        );
        assert_eq!(
            doc.lines().iter().map(Line::span).collect::<Vec<_>>(),
            vec![
                Span::new(0, 3),
                Span::new(5, 5),
                Span::new(6, 9),
                Span::new(10, 15)
            ]
        );
        assert_eq!(
            doc.lines().iter().map(Line::raw).collect::<Vec<_>>(),
            vec!["# c", "", "k=v", "plain"]
        );
        assert_eq!(doc.lines_of_kind(LineKind::Directive).count(), 1);
    }

    #[test]
    fn dominant_ending_follows_the_majority() {
        assert_eq!(parse("").dominant_ending(), LineEnding::Lf);
        assert_eq!(parse("a").dominant_ending(), LineEnding::Lf);
        assert_eq!(parse("a\nb\r\n").dominant_ending(), LineEnding::Lf);
        assert_eq!(parse("a\r\nb\r\nc\n").dominant_ending(), LineEnding::CrLf);
    }

    #[test]
    fn insert_respects_ending_policy() {
        let mut doc = parse("a\r\nb\r\n");
        assert_eq!(doc.insert_line(1, "mid"), Ok(()));
        assert_eq!(doc.render(), "a\r\nmid\r\nb\r\n");

        let mut doc = parse("a\nb");
        assert_eq!(doc.insert_line(2, "c"), Ok(()));
        assert_eq!(doc.render(), "a\nb\nc");

        let mut doc = parse("");
        assert_eq!(doc.insert_line(0, "only"), Ok(()));
        assert_eq!(doc.render(), "only\n");
        assert_eq!(doc.lines().first().map(Line::kind), Some(LineKind::Unknown));
    }

    #[test]
    fn replace_keeps_ending_and_reclassifies() {
        let mut doc = parse("a\r\nb");
        assert_eq!(doc.replace_raw(0, "# now a comment"), Ok(()));
        assert_eq!(doc.replace_raw(1, "k=v"), Ok(()));
        assert_eq!(doc.render(), "# now a comment\r\nk=v");
        assert_eq!(doc.lines().first().map(Line::kind), Some(LineKind::Comment));
        assert_eq!(doc.lines().get(1).map(Line::span), Some(Span::new(17, 20)));
    }

    #[test]
    fn edits_canonicalise_ambiguous_documents() {
        // A line ending in `\r` that gains an `Lf` terminator must become `CrLf`,
        // otherwise the rendered text re-parses into a different document.
        let mut doc = parse("a\r");
        assert_eq!(doc.insert_line(1, "b"), Ok(()));
        assert_eq!(doc.render(), "a\r\nb");
        assert_eq!(doc, parse("a\r\nb"));

        // A trailing empty line with no terminator renders as nothing and must go.
        let mut doc = parse("a");
        assert_eq!(doc.replace_raw(0, ""), Ok(()));
        assert_eq!(doc.render(), "");
        assert!(doc.is_empty());

        let mut doc = parse("\r\nx");
        assert_eq!(doc.remove_line(1), Ok(()));
        assert_eq!(doc.render(), "");
        assert_eq!(doc, parse(""));
    }

    #[test]
    fn remove_preserves_trailing_newline_state() {
        let mut doc = parse("a\nb\nc");
        assert_eq!(doc.remove_line(2), Ok(()));
        assert_eq!(doc.render(), "a\nb");

        let mut doc = parse("a\nb\nc\n");
        assert_eq!(doc.remove_line(0), Ok(()));
        assert_eq!(doc.render(), "b\nc\n");
    }

    #[test]
    fn edits_reject_out_of_range_indices() {
        let mut doc = parse("a\n");
        assert_eq!(
            doc.insert_line(2, "x"),
            Err(EditError::IndexOutOfRange { index: 2, len: 1 })
        );
        assert_eq!(
            doc.replace_raw(1, "x"),
            Err(EditError::IndexOutOfRange { index: 1, len: 1 })
        );
        assert_eq!(
            doc.remove_line(1),
            Err(EditError::IndexOutOfRange { index: 1, len: 1 })
        );
    }

    #[test]
    fn edits_reject_embedded_line_breaks() {
        let mut doc = parse("a\n");
        for bad in ["x\ny", "x\ry", "x\0y"] {
            assert_eq!(
                doc.insert_line(0, bad),
                Err(EditError::LineBreakInValue {
                    value: bad.to_owned()
                })
            );
            assert_eq!(
                doc.replace_raw(0, bad),
                Err(EditError::LineBreakInValue {
                    value: bad.to_owned()
                })
            );
        }
        assert_eq!(doc.render(), "a\n");
    }

    #[test]
    fn documents_compare_by_lines_only() {
        let a = parse("k=v\n");
        let b = Document::parse("k=v\n", |_| LineKind::Unknown);
        assert_ne!(a, b);
        assert_eq!(a, a.clone());
        assert!(format!("{a:?}").contains("k=v"));
    }

    // ------------------------------------------------------------ entry edits

    /// An INI-like format: `[name]` headers and `k=v` settings are entries.
    fn ini(raw: &str) -> LineKind {
        if raw.starts_with('[') {
            LineKind::Directive
        } else {
            classify(raw)
        }
    }

    fn header(raw: &str) -> bool {
        raw.starts_with('[')
    }

    fn flat(_: &str) -> bool {
        false
    }

    /// An entry is its line, trimmed.
    const PARSE_INI: fn(&str) -> Option<String> = |raw| Some(raw.trim().to_owned());

    /// An entry renders as itself.
    const RENDER_INI: fn(&String) -> Result<String, EditError> = |entry| Ok(entry.clone());

    fn wanted(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    /// Applies `entries` to `src` and returns the report and the new text.
    fn edit(src: &str, entries: &[&str], sections: fn(&str) -> bool) -> (EditReport, String) {
        let mut doc = Document::parse(src, ini);
        let report = doc
            .edit_entries(&wanted(entries), PARSE_INI, RENDER_INI, sections)
            .unwrap_or_default();
        (report, doc.render())
    }

    fn report(changed_lines: usize, added: usize, removed: usize) -> EditReport {
        EditReport {
            changed_lines,
            added,
            removed,
        }
    }

    #[test]
    fn edit_entries_keeps_unchanged_lines_in_place() {
        let src = "# c\n  a=1\nb=2\n";
        assert_eq!(
            edit(src, &["a=1", "b=2"], flat),
            (EditReport::default(), src.to_owned())
        );
    }

    #[test]
    fn edit_entries_deletes_without_touching_later_lines() {
        assert_eq!(
            edit("a=1\n  b=2\n# c\n  c=3\n", &["b=2", "c=3"], flat),
            (report(0, 0, 1), "  b=2\n# c\n  c=3\n".to_owned())
        );
    }

    #[test]
    fn edit_entries_replaces_a_changed_entry_in_place() {
        assert_eq!(
            edit("a=1\r\n  b=2\r\nc=3\r\n", &["a=1", "b=9", "c=3"], flat),
            (report(1, 0, 0), "a=1\r\nb=9\r\nc=3\r\n".to_owned())
        );
    }

    #[test]
    fn edit_entries_inserts_after_the_previous_kept_line_in_its_section() {
        let src = "[a]\nx=1\n; tail of a\n[b]\ny=1\n";
        assert_eq!(
            edit(src, &["[a]", "x=1", "x=2", "[b]", "y=1", "y=2"], header),
            (
                report(0, 2, 0),
                "[a]\nx=1\nx=2\n; tail of a\n[b]\ny=1\ny=2\n".to_owned()
            )
        );
    }

    #[test]
    fn edit_entries_inserts_into_an_empty_section() {
        assert_eq!(
            edit(
                "[a]\n# only a comment\n[b]\n",
                &["[a]", "x=1", "[b]"],
                header
            ),
            (
                report(0, 1, 0),
                "[a]\nx=1\n# only a comment\n[b]\n".to_owned()
            )
        );
    }

    #[test]
    fn edit_entries_puts_a_new_section_after_the_previous_one() {
        // The new header goes after the unknown line that belongs to `[a]` but
        // before the blank and comment that lead into `[b]`.
        let src = "[a]\nx=1\nunknown\n\n# about b\n[b]\n";
        assert_eq!(
            edit(src, &["[a]", "x=1", "[n]", "z=1", "[b]"], header),
            (
                report(0, 2, 0),
                "[a]\nx=1\nunknown\n[n]\nz=1\n\n# about b\n[b]\n".to_owned()
            )
        );
        // A new header whose section takes over a kept entry goes before it.
        assert_eq!(
            edit(
                "[a]\nx=1\nunknown\ny=1\n",
                &["[a]", "x=1", "[n]", "y=1"],
                header
            ),
            (report(0, 1, 0), "[a]\nx=1\nunknown\n[n]\ny=1\n".to_owned())
        );
        // With nothing after it, a new header goes at the end of the file.
        assert_eq!(
            edit("[a]\nx=1\n\n", &["[a]", "x=1", "[n]"], header),
            (report(0, 1, 0), "[a]\nx=1\n[n]\n\n".to_owned())
        );
    }

    #[test]
    fn edit_entries_places_entries_without_a_predecessor() {
        // Before the next kept entry ...
        assert_eq!(
            edit("# top\nb=2\n", &["[s]", "a=1", "b=2"], header),
            (report(0, 2, 0), "# top\n[s]\na=1\nb=2\n".to_owned())
        );
        // ... or at the end of a file that has no entries.
        assert_eq!(
            edit("# top\nunknown", &["a=1", "b=2"], flat),
            (report(0, 2, 0), "# top\nunknown\na=1\nb=2".to_owned())
        );
        assert_eq!(
            edit("", &["a=1"], flat),
            (report(0, 1, 0), "a=1\n".to_owned())
        );
    }

    #[test]
    fn edit_entries_mixes_replace_insert_and_delete() {
        assert_eq!(
            edit("a=1\nb=1\nc=1\n", &["a=2", "a=3", "c=1"], flat),
            (report(2, 0, 0), "a=2\na=3\nc=1\n".to_owned())
        );
        assert_eq!(
            edit("a=1\nb=1\nc=1\n", &["x=1", "c=1", "d=1"], flat),
            (report(1, 1, 1), "x=1\nc=1\nd=1\n".to_owned())
        );
        assert_eq!(
            edit("a=1\nb=1", &[], flat),
            (report(0, 0, 2), String::new())
        );
    }

    #[test]
    fn edit_entries_keeps_a_missing_final_newline() {
        assert_eq!(
            edit("a=1\nb=1", &["a=1"], flat),
            (report(0, 0, 1), "a=1".to_owned())
        );
        assert_eq!(
            edit("a=1", &["a=1", "b=1"], flat),
            (report(0, 1, 0), "a=1\nb=1".to_owned())
        );
        // A rewritten line keeps its terminator, even a missing one.
        assert_eq!(
            edit("a=1\nb=1", &["a=1", "b=2"], flat),
            (report(1, 0, 0), "a=1\nb=2".to_owned())
        );
    }

    #[test]
    fn edit_entries_reparses_to_an_equal_document() {
        let mut doc = Document::parse("[a]\r\nx=1\r\n# c\r\n", ini);
        let result = doc.edit_entries(
            &wanted(&["[a]", "y=1", "[b]"]),
            PARSE_INI,
            RENDER_INI,
            header,
        );
        assert_eq!(result, Ok(report(1, 1, 0)));
        assert_eq!(doc.render(), "[a]\r\ny=1\r\n[b]\r\n# c\r\n");
        assert_eq!(doc, Document::parse(&doc.render(), ini));
        assert_eq!(doc.classifier()("[b]"), LineKind::Directive);
    }

    #[test]
    fn edit_entries_ignores_lines_the_parser_refuses() {
        let mut doc = Document::parse("a=1\nskip=1\n", ini);
        let only_a = |raw: &str| raw.starts_with('a').then(|| raw.to_owned());
        let result = doc.edit_entries(&wanted(&["a=2"]), only_a, RENDER_INI, flat);
        assert_eq!(result, Ok(report(1, 0, 0)));
        assert_eq!(doc.render(), "a=2\nskip=1\n");
    }

    #[test]
    fn edit_entries_refuses_before_touching_the_document() {
        let src = "a=1\nb=1\n";
        let mut doc = Document::parse(src, ini);
        assert_eq!(
            doc.edit_entries(
                &wanted(&["a=1", "c=1", "d\n=1"]),
                PARSE_INI,
                RENDER_INI,
                flat
            ),
            Err(EditError::LineBreakInValue {
                value: "d\n=1".to_owned()
            })
        );
        let refuse = |_: &String| -> Result<String, EditError> {
            Err(EditError::Unsupported {
                message: "no".to_owned(),
            })
        };
        assert!(matches!(
            doc.edit_entries(&wanted(&["x=1"]), PARSE_INI, refuse, flat),
            Err(EditError::Unsupported { .. })
        ));
        assert_eq!(doc.render(), src);
    }

    #[test]
    fn plans_for_disjoint_lines_combine_into_one_pass() -> Result<(), EditError> {
        let mut doc = Document::parse("a=1\nb=1\n", ini);
        let of = |prefix: char| move |raw: &str| raw.starts_with(prefix).then(|| raw.to_owned());
        let mut plan = doc.plan_entries(&wanted(&["a=2", "a=3"]), of('a'), RENDER_INI, flat)?;
        plan.extend(doc.plan_entries(&wanted(&[]), of('b'), RENDER_INI, flat)?);
        assert_eq!(doc.render(), "a=1\nb=1\n", "planning is read-only");
        assert_eq!(doc.apply_plan(plan), report(1, 1, 1));
        assert_eq!(doc.render(), "a=2\na=3\n");
        assert_eq!(
            doc.apply_plan(super::EntryPlan::default()),
            EditReport::default()
        );
        Ok(())
    }

    #[test]
    fn a_plan_built_by_hand_applies_in_one_pass() -> Result<(), EditError> {
        let mut doc = Document::parse("a=1\nb=1\nc=1", ini);
        let mut plan = super::EntryPlan::default();
        plan.replace(0, "a=2".to_owned())?;
        plan.remove(1);
        plan.insert(2, "x=1".to_owned())?;
        plan.insert(2, "y=1".to_owned())?;
        plan.insert(9, "z=1".to_owned())?;
        assert_eq!(doc.apply_plan(plan), report(1, 3, 1));
        assert_eq!(doc.render(), "a=2\nx=1\ny=1\nc=1\nz=1");
        let mut refused = super::EntryPlan::default();
        assert!(matches!(
            refused.replace(0, "a\nb".to_owned()),
            Err(EditError::LineBreakInValue { .. })
        ));
        assert!(matches!(
            refused.insert(0, "a\rb".to_owned()),
            Err(EditError::LineBreakInValue { .. })
        ));
        assert_eq!(refused, super::EntryPlan::default());
        Ok(())
    }

    #[test]
    fn edit_entries_falls_back_to_positional_pairing_past_the_cap() {
        let old: Vec<String> = (0..MAX_EDIT_DISTANCE).map(|i| format!("o{i}=1")).collect();
        let new: Vec<String> = (0..MAX_EDIT_DISTANCE).map(|i| format!("n{i}=1")).collect();
        let src: String = old.iter().map(|line| [line, "\n"].concat()).collect();
        let mut doc = Document::parse(&src, ini);
        let result = doc.edit_entries(&new, PARSE_INI, RENDER_INI, flat);
        assert_eq!(result, Ok(report(MAX_EDIT_DISTANCE, 0, 0)));
        let expected: String = new.iter().map(|line| [line, "\n"].concat()).collect();
        assert_eq!(doc.render(), expected);
    }

    #[test]
    fn line_new_builds_an_unplaced_line() {
        let line = Line::new("k=v".to_owned(), LineKind::Directive, LineEnding::CrLf);
        assert_eq!(line.raw(), "k=v");
        assert_eq!(line.kind(), LineKind::Directive);
        assert_eq!(line.ending(), LineEnding::CrLf);
        assert_eq!(line.span(), Span::new(0, 0));
    }

    #[test]
    fn span_serde_round_trips() {
        let json = serde_json::to_string(&Span::new(1, 4)).unwrap_or_default();
        assert_eq!(json, r#"{"start":1,"end":4}"#);
        assert_eq!(
            serde_json::from_str::<Span>(&json).ok(),
            Some(Span::new(1, 4))
        );
        let schema = schemars::schema_for!(Span);
        assert!(schema.to_value().to_string().contains("start"));
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_impls_build_values() {
        use arbitrary::{Arbitrary, Unstructured};
        let data = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let mut u = Unstructured::new(&data);
        assert!(Span::arbitrary(&mut u).is_ok());
        assert!(LineEnding::arbitrary(&mut u).is_ok());
        assert!(LineKind::arbitrary(&mut u).is_ok());
        assert!(<Span as Arbitrary>::size_hint(0).0 > 0);
        assert!(Span::arbitrary_take_rest(Unstructured::new(&data)).is_ok());
        assert!(LineEnding::arbitrary_take_rest(Unstructured::new(&data)).is_ok());
        assert!(LineKind::arbitrary_take_rest(Unstructured::new(&data)).is_ok());
        assert!(<LineEnding as Arbitrary>::size_hint(0).0 > 0);
        assert!(<LineKind as Arbitrary>::size_hint(0).0 > 0);
    }
}
