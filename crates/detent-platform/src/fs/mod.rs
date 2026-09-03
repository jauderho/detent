//! Filesystem primitives: the atomic write protocol and its backup store.

pub mod atomic;

pub use atomic::{
    AtomicError, BackupEntry, DEFAULT_KEEP_BACKUPS, Sha256Digest, WriteOutcome, WriteRequest,
    list_backups, read_with_digest, restore_backup, write_atomic,
};
