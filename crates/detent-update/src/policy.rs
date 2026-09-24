//! Release selection policy (PLAN §2.9 step 2): semver-only movement, the
//! downgrade refusal, the age gate, and the security-metadata bypass.

use time::OffsetDateTime;

/// The release body metadata line that bypasses the age gate: a security
/// release ships to every device immediately, per PLAN §2.9 step 2.
pub const SECURITY_MARKER: &str = "detent-security: true";

/// Default for [`Policy::min_age_days`]: PLAN §2.10, `[update] min_age_days`.
pub const DEFAULT_MIN_AGE_DAYS: u64 = 2;

/// Why no release was selected.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Nothing non-draft, non-prerelease, newer than `current` was found.
    #[error("no newer release is available")]
    NoUpdate,
    /// The newest candidate is older than the running version and
    /// downgrades were not requested.
    #[error("refusing downgrade to {candidate} from {current}")]
    DowngradeRefused {
        /// The candidate tag.
        candidate: String,
        /// The running version.
        current: String,
    },
    /// The candidate is newer but younger than `min_age_days` and carries no
    /// [`SECURITY_MARKER`].
    #[error("release {tag} is younger than {min_age_days} day(s)")]
    TooYoung {
        /// The candidate tag.
        tag: String,
        /// The configured minimum age in days.
        min_age_days: u64,
    },
    /// The tag is not a semver version (with or without a leading `v`).
    #[error("release tag {0} is not a semver version")]
    BadTag(String),
}

/// The selection knobs, from `/etc/detent/detent.toml` `[update]` (§2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Refuse releases younger than this many days unless the release body
    /// carries [`SECURITY_MARKER`].
    pub min_age_days: u64,
    /// Permit installing a release whose version is lower than the running
    /// one. Never set by default; an explicit operator decision.
    pub allow_downgrade: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_age_days: DEFAULT_MIN_AGE_DAYS,
            allow_downgrade: false,
        }
    }
}

/// The one release a run of the update flow acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The release tag, e.g. `v0.0.2`.
    pub tag: String,
    /// When GitHub published the release (None while it is still a draft).
    pub published: Option<OffsetDateTime>,
    /// The release body, scanned for [`SECURITY_MARKER`].
    pub body: String,
}

/// Picks the release to update to, or explains why none qualifies.
///
/// Releases are sorted by semver and publication date before policy checks;
/// API order is not trusted because a backport can precede a newer release.
/// The newest release that satisfies the age gate wins.
///
/// # Errors
///
/// [`PolicyError`] per the refusal reason.
pub fn select(
    releases: &[Candidate],
    current: &semver::Version,
    now: OffsetDateTime,
    policy: &Policy,
) -> Result<Candidate, PolicyError> {
    let mut parsed = releases
        .iter()
        .filter_map(|release| version_of(&release.tag).map(|version| (release, version)))
        .collect::<Vec<_>>();
    parsed.sort_by(|(left, left_version), (right, right_version)| {
        right_version
            .cmp(left_version)
            .then_with(|| right.published.cmp(&left.published))
    });

    let mut too_young = None;
    for (release, version) in parsed {
        if version > *current {
            match gate_age(release, now, policy) {
                Ok(_) => return Ok(release.clone()),
                Err(error @ PolicyError::TooYoung { .. }) => {
                    too_young.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        } else if version == *current {
            if too_young.is_none() {
                return Err(PolicyError::NoUpdate);
            }
        } else if !policy.allow_downgrade {
            if too_young.is_none() {
                return Err(PolicyError::DowngradeRefused {
                    candidate: release.tag.clone(),
                    current: current.to_string(),
                });
            }
        } else {
            match gate_age(release, now, policy) {
                Ok(_) => return Ok(release.clone()),
                Err(error @ PolicyError::TooYoung { .. }) => {
                    too_young.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
    }
    Err(too_young.unwrap_or(PolicyError::NoUpdate))
}

/// The age gate applied to an already-chosen release.
fn gate_age(
    release: &Candidate,
    now: OffsetDateTime,
    policy: &Policy,
) -> Result<Candidate, PolicyError> {
    let security = release
        .body
        .lines()
        .any(|line| line.trim() == SECURITY_MARKER);
    if !security {
        if let Some(published) = release.published {
            #[allow(clippy::arithmetic_side_effects)] // time subtraction clamps to the era bounds
            let age = now - published;
            if age.whole_days() < i64::try_from(policy.min_age_days).unwrap_or(i64::MAX) {
                return Err(PolicyError::TooYoung {
                    tag: release.tag.clone(),
                    min_age_days: policy.min_age_days,
                });
            }
        } else {
            // A release GitHub has not published yet has no age to speak of:
            // refuse closed until it does.
            return Err(PolicyError::TooYoung {
                tag: release.tag.clone(),
                min_age_days: policy.min_age_days,
            });
        }
    }
    Ok(release.clone())
}

/// Parses a release tag as semver, tolerating a leading `v` (the release
/// workflow tags `v*`).
#[must_use]
pub fn version_of(tag: &str) -> Option<semver::Version> {
    semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag)).ok()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// 2026-09-18T00:00:00Z — comfortably after the 7-day-cooldown era of
    /// the fixture releases.
    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_786_780_800).expect("fixed test timestamp")
    }

    fn candidate(tag: &str, published_days_ago: i64) -> Candidate {
        Candidate {
            tag: tag.to_owned(),
            published: Some(now() - time::Duration::days(published_days_ago)),
            body: String::new(),
        }
    }

    fn current() -> semver::Version {
        semver::Version::new(0, 0, 1)
    }

    #[test]
    fn selects_newer_release_past_min_age() {
        let releases = [candidate("v0.0.2", 3)];
        let chosen = select(&releases, &current(), now(), &Policy::default())
            .expect("v0.0.2 is three days old");
        assert_eq!(chosen.tag, "v0.0.2");
    }

    #[test]
    fn backport_in_api_order_does_not_hide_newer_release() {
        let releases = [candidate("v0.1.0", 3), candidate("v0.0.2", 3)];
        let chosen = select(&releases, &current(), now(), &Policy::default())
            .expect("newest semver should be selected");
        assert_eq!(chosen.tag, "v0.1.0");
    }

    #[test]
    fn tags_without_leading_v_parse() {
        let releases = [candidate("0.0.2", 3)];
        let chosen = select(&releases, &current(), now(), &Policy::default())
            .expect("plain semver tags are accepted");
        assert_eq!(chosen.tag, "0.0.2");
    }

    /// Note: draft/prerelease filtering happens in `fetch` when it builds
    /// candidates (it owns GitHub's JSON semantics); policy only sees the
    /// parsed tags.
    #[test]
    fn skips_unparsable_tags() {
        let releases = [
            Candidate {
                tag: "latest".to_owned(),
                published: Some(now()),
                body: String::new(),
            },
            candidate("v0.0.2", 3),
        ];
        let chosen = select(&releases, &current(), now(), &Policy::default())
            .expect("only v0.0.2 qualifies");
        assert_eq!(chosen.tag, "v0.0.2");
    }

    #[test]
    fn refuses_younger_release() {
        let releases = [candidate("v0.0.2", 1)];
        assert!(matches!(
            select(&releases, &current(), now(), &Policy::default()),
            Err(PolicyError::TooYoung { tag, min_age_days: 2 }) if tag == "v0.0.2"
        ));
    }

    #[test]
    fn security_marker_bypasses_age_gate() {
        let mut young = candidate("v0.0.2", 0);
        young.body = "Bugfix for CVE-2026-9999.\n\ndetent-security: true\n".to_owned();
        let chosen = select(&[young], &current(), now(), &Policy::default())
            .expect("security releases skip the age gate");
        assert_eq!(chosen.tag, "v0.0.2");
    }

    #[test]
    fn marker_must_match_exactly() {
        let mut young = candidate("v0.0.2", 0);
        young.body = "detent-security: false".to_owned();
        assert!(matches!(
            select(&[young], &current(), now(), &Policy::default()),
            Err(PolicyError::TooYoung { .. })
        ));
    }

    #[test]
    fn marker_embedded_in_sentence_does_not_bypass() -> Result<(), Box<dyn std::error::Error>> {
        let mut young = candidate("v0.0.2", 0);
        young.body = "See detent-security: true for details".to_owned();
        assert!(matches!(
            select(&[young.clone()], &current(), now(), &Policy::default()),
            Err(PolicyError::TooYoung { .. })
        ));
        young.body = "  detent-security: true  ".to_owned();
        let chosen = select(&[young.clone()], &current(), now(), &Policy::default())?;
        assert_eq!(chosen.tag, "v0.0.2");
        Ok(())
    }

    #[test]
    fn unpublished_release_is_refused() {
        let release = Candidate {
            tag: "v0.0.2".to_owned(),
            published: None,
            body: String::new(),
        };
        assert!(matches!(
            select(&[release], &current(), now(), &Policy::default()),
            Err(PolicyError::TooYoung { .. })
        ));
    }

    #[test]
    fn refuses_downgrade_by_default() {
        let releases = [candidate("v0.0.0", 30)];
        assert!(matches!(
            select(&releases, &current(), now(), &Policy::default()),
            Err(PolicyError::DowngradeRefused { candidate, .. }) if candidate == "v0.0.0"
        ));
    }

    #[test]
    fn equal_version_is_no_update() {
        let releases = [candidate("v0.0.1", 30)];
        assert!(matches!(
            select(&releases, &current(), now(), &Policy::default()),
            Err(PolicyError::NoUpdate)
        ));
    }

    #[test]
    fn allow_downgrade_picks_explicit_older_release() {
        let releases = [candidate("v0.0.0", 30)];
        let policy = Policy {
            allow_downgrade: true,
            ..Policy::default()
        };
        let chosen = select(&releases, &current(), now(), &policy)
            .expect("downgrade was explicitly allowed");
        assert_eq!(chosen.tag, "v0.0.0");
    }

    #[test]
    fn empty_release_list_is_no_update() {
        assert!(matches!(
            select(&[], &current(), now(), &Policy::default()),
            Err(PolicyError::NoUpdate)
        ));
    }

    #[test]
    fn version_of_tolerates_v_prefix_and_refuses_garbage() {
        assert_eq!(version_of("v1.2.3"), Some(semver::Version::new(1, 2, 3)));
        assert_eq!(version_of("latest"), None);
    }
}
