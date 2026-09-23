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

use crate::module::{EditError, LosslessDoc};

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
    use super::{Document, EditError, Line, LineEnding, LineKind, LosslessDoc, Span};

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
