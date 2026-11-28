pub mod apate;
pub mod polyglot;

use crate::detector::{ArchiveFormat, DetectOptions, DisguisedSplitInfo};
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Scan cost tier that governs when a [`StegoCodec`] runs in the detection pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProbeCost {
    /// O(1) header/tail signature or structural probe (e.g. Apate 4-byte tail indicator).
    /// Runs BEFORE name-only split/extension fallbacks so disguised split volumes are restored
    /// rather than misclassified as plain renamed splits, and BEFORE linear scans.
    FastHeaderOrTail,
    /// Tail-window or linear payload scan (e.g. appended ZIP EOCD, chunked 7z/RAR polyglot scan).
    /// Runs AFTER normal extension/split checks as a fallback.
    FallbackScan,
}

/// Read-only context passed to each [`StegoCodec::probe`].
pub struct ProbeContext<'a> {
    pub path: &'a Path,
    pub file: &'a mut File,
    pub file_len: u64,
    pub header: &'a [u8],
    pub ext: &'a str,
    pub opts: DetectOptions,
    pub is_nested: bool,
    pub is_split: bool,
    pub disguised_split: Option<&'a DisguisedSplitInfo>,
}

/// Error returned when restoring a steganography payload to a temporary file.
#[derive(Debug)]
pub enum StegoError {
    Cancelled,
    Message(String),
}

/// Self-contained handle produced by a successful [`StegoCodec::probe`].
/// Knows how to describe itself in the UI/logs, stream-restore the hidden archive to disk,
/// and optionally detect sibling split volumes disguised by the same tool.
pub trait StegoRestorer: Send + Sync {
    /// Stable tool identifier (e.g. `"apate"`, `"polyglot"`).
    fn tool_id(&self) -> &'static str;

    /// UI badge text (should include `"隐写"` so task cards render it with the warning tag).
    fn badge_text(&self, fmt: ArchiveFormat) -> String;

    /// Stage text shown while restoring the hidden archive.
    fn stage_label(&self, fmt: ArchiveFormat) -> String;

    /// Log line emitted once restoration succeeds.
    fn restored_log(&self, fmt: ArchiveFormat) -> String;

    /// Stream-restores the hidden archive from `src` to `dst` without modifying `src`.
    fn restore_to(
        &self,
        src: &Path,
        dst: &Path,
        cancel_flag: &AtomicBool,
        on_progress: &mut dyn FnMut(u8),
    ) -> Result<(), StegoError>;

    /// Optional: probes whether a sibling split volume (e.g. `.002.mp4`) was also disguised
    /// by this tool and returns a restorer for that sibling.
    fn probe_split_sibling(
        &self,
        _first_vol: &Path,
        _sibling: &Path,
    ) -> Option<Box<dyn StegoRestorer>> {
        None
    }
}

/// Result returned when a [`StegoCodec`] recognizes a disguised/stego archive.
pub struct StegoMatch {
    pub format: ArchiveFormat,
    pub is_split: bool,
    pub disguised_split: Option<DisguisedSplitInfo>,
    pub restorer: Arc<dyn StegoRestorer>,
}

/// Extension point for adding new steganography / disguise tools.
///
/// To add a new tool:
/// 1. Create `src/stego/<tool>.rs` implementing [`StegoCodec`] and [`StegoRestorer`]
///    (optionally implementing [`crate::detector::ByteSource`] to reuse all format validators).
/// 2. Register an instance in [`CODECS`] below.
pub trait StegoCodec: Send + Sync {
    #[allow(dead_code)]
    fn id(&self) -> &'static str;
    fn cost(&self) -> ProbeCost;
    fn probe(&self, ctx: &mut ProbeContext<'_>) -> Option<StegoMatch>;
}

/// Static registry of all built-in steganography codecs.
/// Ordered from cheapest/most-specific to broadest within each [`ProbeCost`] tier.
static CODECS: &[&dyn StegoCodec] = &[&apate::ApateCodec, &polyglot::PolyglotCodec];

/// Probes all registered codecs in the given [`ProbeCost`] tier, returning the first match.
pub fn probe_tier(tier: ProbeCost, ctx: &mut ProbeContext<'_>) -> Option<StegoMatch> {
    for codec in CODECS {
        if codec.cost() == tier {
            if let Some(matched) = codec.probe(ctx) {
                return Some(matched);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_registered_codecs_have_unique_ids() {
        let mut ids = HashSet::new();
        for codec in CODECS {
            assert!(!codec.id().is_empty());
            assert!(ids.insert(codec.id()), "duplicate codec id: {}", codec.id());
        }
    }
}
