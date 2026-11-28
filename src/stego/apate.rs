use super::{ProbeContext, ProbeCost, StegoCodec, StegoError, StegoMatch, StegoRestorer};
use crate::detector::{self, ArchiveFormat, ByteSource, format_bytes};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum number of stacked Apate disguise layers peeled during O(1) probing.
const MAX_APATE_LAYERS: usize = 16;

/// Codec for Apate (`github.com/rippod/apate`):
/// OneKey (`mask.mp4`), custom mask files, simple masks (`EXE` / `JPG` / `MP4` / `MOV`),
/// as well as stacked multi-layer Apate disguises (e.g. `secret.7z.mp4.jpg` or repeated OneKey).
pub struct ApateCodec;

/// Virtual byte-level view over one Apate disguise layer.
///
/// Apate disguises an original file of length `orig_len` with a mask of length `mask_len` (`i32 > 0`) as:
/// - `[0 .. mask_len]` = mask bytes
/// - `[mask_len .. orig_len]` = untouched original tail (only when `orig_len > mask_len`)
/// - `[file_len - 4 - rev_head_len .. file_len - 4]` = `reverse(orig[0 .. rev_head_len])`
///   where `rev_head_len = min(mask_len, orig_len)`
/// - `[file_len - 4 .. file_len]` = `mask_len` as 4-byte little-endian `i32`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApateView {
    pub file_len: u64,
    pub mask_len: u64,
    pub orig_len: u64,
    pub rev_head_len: u64,
}

impl ApateView {
    pub fn new(file_len: u64, mask_len: u64) -> Option<Self> {
        if mask_len == 0 || mask_len > i32::MAX as u64 {
            return None;
        }
        let orig_len = file_len.checked_sub(4)?.checked_sub(mask_len)?;
        if orig_len == 0 {
            return None;
        }
        let rev_head_len = mask_len.min(orig_len);
        Some(Self {
            file_len,
            mask_len,
            orig_len,
            rev_head_len,
        })
    }

    /// Reads the trailing 4-byte little-endian mask length indicator at the current virtual depth
    /// and constructs the next [`ApateView`].
    fn peel_from_depth(file: &mut File, layers: &[ApateView], cur_len: u64) -> Option<Self> {
        if cur_len < 6 {
            return None;
        }
        let mut tail4 = [0u8; 4];
        read_exact_at_depth(file, layers, layers.len(), cur_len - 4, &mut tail4).ok()?;
        let mask_len_i32 = i32::from_le_bytes(tail4);
        if mask_len_i32 <= 0 {
            return None;
        }
        Self::new(cur_len, mask_len_i32 as u64)
    }
}

/// Reads `buf.len()` bytes from the virtual stream at `depth`
/// (`0` = raw physical file, `1` = after peeling `layers[0]`, ..., `layers.len()` = fully peeled).
fn read_exact_at_depth(
    file: &mut File,
    layers: &[ApateView],
    depth: usize,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<()> {
    if depth == 0 {
        file.seek(SeekFrom::Start(offset))?;
        return file.read_exact(buf);
    }

    let view = layers[depth - 1];
    let len = buf.len() as u64;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
    if end > view.orig_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "apate virtual read out of bounds",
        ));
    }

    let mut written = 0usize;

    // Logical range [offset .. part1_end) inside [0 .. rev_head_len) lives reversed at
    // [file_len - 4 - part1_end .. file_len - 4 - offset) in the outer layer.
    if offset < view.rev_head_len {
        let part1_end = end.min(view.rev_head_len);
        let part1_len = (part1_end - offset) as usize;
        let phys_start = view.file_len - 4 - part1_end;
        read_exact_at_depth(file, layers, depth - 1, phys_start, &mut buf[..part1_len])?;
        buf[..part1_len].reverse();
        written = part1_len;
    }

    // Logical range [part2_start .. end) inside [rev_head_len .. orig_len) is untouched in the outer layer.
    if end > view.rev_head_len {
        let part2_start = offset.max(view.rev_head_len);
        let part2_len = (end - part2_start) as usize;
        read_exact_at_depth(
            file,
            layers,
            depth - 1,
            part2_start,
            &mut buf[written..written + part2_len],
        )?;
    }

    Ok(())
}

/// [`ByteSource`] adapter exposing the virtually-restored original stream across 1..N Apate layers in O(1).
pub struct LayeredApateSource<'a> {
    file: &'a mut File,
    file_len: u64,
    layers: &'a [ApateView],
}

impl<'a> LayeredApateSource<'a> {
    pub fn new(file: &'a mut File, file_len: u64, layers: &'a [ApateView]) -> Self {
        Self {
            file,
            file_len,
            layers,
        }
    }
}

impl ByteSource for LayeredApateSource<'_> {
    fn len(&self) -> u64 {
        self.layers
            .last()
            .map(|v| v.orig_len)
            .unwrap_or(self.file_len)
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        read_exact_at_depth(self.file, self.layers, self.layers.len(), offset, buf)
    }
}

pub struct ApateRestorer {
    /// Carrier labels ordered from outermost layer to innermost layer (e.g. `["JPG", "MP4"]`).
    pub carriers: Vec<String>,
    /// Mask byte lengths ordered from outermost layer to innermost layer.
    pub mask_lens: Vec<u64>,
}

impl StegoCodec for ApateCodec {
    fn id(&self) -> &'static str {
        "apate"
    }

    fn cost(&self) -> ProbeCost {
        ProbeCost::FastHeaderOrTail
    }

    fn probe(&self, ctx: &mut ProbeContext<'_>) -> Option<StegoMatch> {
        let mut layers: Vec<ApateView> = Vec::new();
        let mut carriers: Vec<String> = Vec::new();

        let mut cur_len = ctx.file_len;
        let mut cur_header = ctx.header[..ctx.header.len().min(32)].to_vec();
        let mut cur_ext = ctx.ext.to_string();
        let mut peeled_name = ctx
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string);

        for _ in 0..MAX_APATE_LAYERS {
            let view = ApateView::peel_from_depth(ctx.file, &layers, cur_len)?;
            if view.orig_len < 16 {
                break;
            }

            carriers.push(detect_apate_carrier_kind(&cur_header, &cur_ext));
            layers.push(view);
            cur_len = view.orig_len;

            // Peel one outer extension per layer to infer inner format hints (e.g. `game.iso.mp4.jpg`)
            peeled_name = peeled_name
                .as_deref()
                .and_then(|n| Path::new(n).file_stem())
                .and_then(|s| s.to_str())
                .map(str::to_string);
            let inner_ext = peeled_name
                .as_deref()
                .and_then(|n| Path::new(n).extension())
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let mut source = LayeredApateSource::new(ctx.file, ctx.file_len, &layers);
            if let Some(fmt) = detector::detect_strict_archive_in_source(
                &mut source,
                &inner_ext,
                ctx.opts,
                ctx.is_split,
            ) {
                let mask_lens: Vec<u64> = layers.iter().map(|v| v.mask_len).collect();
                return Some(StegoMatch {
                    format: fmt,
                    is_split: ctx.is_split,
                    disguised_split: ctx.disguised_split.cloned(),
                    restorer: Arc::new(ApateRestorer {
                        carriers,
                        mask_lens,
                    }),
                });
            }

            // Not a recognized archive yet — inspect next virtual layer's leading bytes as carrier
            let next_hdr_len = cur_len.min(32) as usize;
            cur_header.resize(next_hdr_len, 0);
            if read_exact_at_depth(ctx.file, &layers, layers.len(), 0, &mut cur_header).is_err() {
                break;
            }
            cur_ext = inner_ext;
        }

        None
    }
}

impl StegoRestorer for ApateRestorer {
    fn tool_id(&self) -> &'static str {
        "apate"
    }

    fn badge_text(&self, fmt: ArchiveFormat) -> String {
        if self.mask_lens.len() <= 1 {
            let carrier = self.carriers.first().map(String::as_str).unwrap_or("面具");
            let mask_len = self.mask_lens.first().copied().unwrap_or(0);
            format!(
                "Apate隐写/{} ({} · 面具 {})",
                carrier,
                fmt.display_name(),
                format_bytes(mask_len)
            )
        } else {
            format!(
                "Apate{}层隐写/{} ({})",
                self.mask_lens.len(),
                self.carriers.join("→"),
                fmt.display_name()
            )
        }
    }

    fn stage_label(&self, fmt: ArchiveFormat) -> String {
        if self.mask_lens.len() <= 1 {
            format!("正在还原 Apate 隐写 ({})", fmt.display_name())
        } else {
            format!(
                "正在还原 Apate {}层隐写 ({})",
                self.mask_lens.len(),
                fmt.display_name()
            )
        }
    }

    fn restored_log(&self, fmt: ArchiveFormat) -> String {
        if self.mask_lens.len() <= 1 {
            let mask_len = self.mask_lens.first().copied().unwrap_or(0);
            format!(
                "已还原 Apate 隐写载荷（面具 {}）→ 临时文件 ({})",
                format_bytes(mask_len),
                fmt.canonical_ext()
            )
        } else {
            format!(
                "已还原 {} 层 Apate 隐写载荷（{}）→ 临时文件 ({})",
                self.mask_lens.len(),
                self.carriers.join("→"),
                fmt.canonical_ext()
            )
        }
    }

    fn restore_to(
        &self,
        src: &Path,
        dst: &Path,
        cancel_flag: &AtomicBool,
        on_progress: &mut dyn FnMut(u8),
    ) -> Result<(), StegoError> {
        restore_apate_layers_to_path(src, dst, &self.mask_lens, cancel_flag, on_progress)
    }

    fn probe_split_sibling(
        &self,
        first_vol: &Path,
        sibling: &Path,
    ) -> Option<Box<dyn StegoRestorer>> {
        let sib_mask_lens = probe_apate_sibling_layers(first_vol, sibling, &self.mask_lens)?;
        Some(Box::new(ApateRestorer {
            carriers: self.carriers.clone(),
            mask_lens: sib_mask_lens,
        }))
    }
}

/// Stream-restores 1..N stacked Apate disguise layers directly from `src` into a single `dst` file
/// in one pass using O(1) memory (max 4 MB buffer).
/// Handles both `orig_len >= mask_len` and `orig_len < mask_len` at every layer.
pub fn restore_apate_layers_to_path(
    src: &Path,
    dst: &Path,
    mask_lens: &[u64],
    cancel_flag: &AtomicBool,
    on_progress: &mut dyn FnMut(u8),
) -> Result<(), StegoError> {
    if mask_lens.is_empty() {
        return Err(StegoError::Message("无效的 Apate 层级配置".into()));
    }

    let mut reader = File::open(src)
        .map_err(|e| StegoError::Message(format!("无法读取 Apate 源文件: {e}")))?;
    let file_len = reader
        .metadata()
        .map_err(|e| StegoError::Message(format!("无法读取 Apate 文件大小: {e}")))?
        .len();

    let mut layers = Vec::with_capacity(mask_lens.len());
    let mut cur_len = file_len;
    for &mlen in mask_lens {
        let view = ApateView::new(cur_len, mlen)
            .ok_or_else(|| StegoError::Message("无效的 Apate 隐写文件结构".into()))?;
        cur_len = view.orig_len;
        layers.push(view);
    }

    let orig_len = cur_len;
    let mut writer = File::create(dst)
        .map_err(|e| StegoError::Message(format!("无法创建 Apate 还原临时文件: {e}")))?;

    let buf_size = (orig_len.min(4 * 1024 * 1024) as usize).max(4096);
    let mut buf = vec![0u8; buf_size];
    let mut offset = 0u64;

    while offset < orig_len {
        if cancel_flag.load(Ordering::Relaxed) {
            return Err(StegoError::Cancelled);
        }
        let chunk = ((orig_len - offset) as usize).min(buf.len());
        read_exact_at_depth(&mut reader, &layers, layers.len(), offset, &mut buf[..chunk])
            .map_err(|e| StegoError::Message(format!("读取 Apate 隐写流失败: {e}")))?;
        writer
            .write_all(&buf[..chunk])
            .map_err(|e| StegoError::Message(format!("写入 Apate 还原文件失败: {e}")))?;
        offset += chunk as u64;
        on_progress(((offset.saturating_mul(100)) / orig_len).min(100) as u8);
    }

    writer
        .flush()
        .map_err(|e| StegoError::Message(format!("刷新 Apate 还原文件失败: {e}")))?;

    Ok(())
}

/// Checks whether a sibling split volume (e.g. `.002.mp4` or `.002.mp4.jpg`) was disguised with
/// the same number of Apate layers as the first volume and returns its per-layer mask lengths.
fn probe_apate_sibling_layers(
    first_vol: &Path,
    sibling: &Path,
    first_mask_lens: &[u64],
) -> Option<Vec<u64>> {
    let mut first_f = File::open(first_vol).ok()?;
    let mut first_cur_len = first_f.metadata().ok()?.len();
    let mut sib_f = File::open(sibling).ok()?;
    let mut sib_cur_len = sib_f.metadata().ok()?.len();

    let mut first_layers = Vec::with_capacity(first_mask_lens.len());
    let mut sib_layers = Vec::with_capacity(first_mask_lens.len());
    let mut out_lens = Vec::with_capacity(first_mask_lens.len());

    for &expected_mlen in first_mask_lens {
        let sib_view = ApateView::peel_from_depth(&mut sib_f, &sib_layers, sib_cur_len)?;
        let first_view = ApateView::new(first_cur_len, expected_mlen)?;

        let mut matched = sib_view.mask_len == expected_mlen;
        if !matched {
            let cmp_len = expected_mlen.min(sib_view.mask_len).min(16) as usize;
            if cmp_len > 0 {
                let mut a = vec![0u8; cmp_len];
                let mut b = vec![0u8; cmp_len];
                if read_exact_at_depth(&mut first_f, &first_layers, first_layers.len(), 0, &mut a)
                    .is_ok()
                    && read_exact_at_depth(&mut sib_f, &sib_layers, sib_layers.len(), 0, &mut b)
                        .is_ok()
                {
                    matched = a == b;
                }
            }
        }
        if !matched {
            return None;
        }

        out_lens.push(sib_view.mask_len);
        first_cur_len = first_view.orig_len;
        sib_cur_len = sib_view.orig_len;
        first_layers.push(first_view);
        sib_layers.push(sib_view);
    }

    Some(out_lens)
}

fn detect_apate_carrier_kind(header: &[u8], ext: &str) -> String {
    if header.len() >= 12 && &header[4..8] == b"ftyp" {
        return "MP4".into();
    }
    if header.len() >= 4 && &header[0..4] == b"moov" {
        return "MOV".into();
    }
    if header.len() >= 3 && header[0..3] == [0xFF, 0xD8, 0xFF] {
        return "JPG".into();
    }
    if header.len() >= 8 && header[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return "PNG".into();
    }
    if header.len() >= 6 && (&header[0..6] == b"GIF87a" || &header[0..6] == b"GIF89a") {
        return "GIF".into();
    }
    if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP" {
        return "WEBP".into();
    }
    if header.len() >= 2 && &header[0..2] == b"BM" {
        return "BMP".into();
    }
    if header.len() >= 4 && header[0..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return "MKV".into();
    }
    if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"AVI " {
        return "AVI".into();
    }
    if header.len() >= 4 && &header[0..4] == b"%PDF" {
        return "PDF".into();
    }
    if header.len() >= 2 && &header[0..2] == b"MZ" {
        return "EXE".into();
    }
    if !ext.is_empty() {
        ext.to_ascii_uppercase()
    } else {
        "面具".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{DetectOptions, TrickKind, detect_file, detect_file_with_context};
    use std::fs;

    /// Exact Rust replica of `apate::Program::Disguise(filePath, maskHead)`.
    pub(crate) fn apate_disguise(orig: &[u8], mask: &[u8]) -> Vec<u8> {
        let mut out = if orig.len() >= mask.len() {
            orig.to_vec()
        } else {
            vec![0u8; mask.len()]
        };
        let head_len = orig.len().min(mask.len());
        let mut rev_head = orig[..head_len].to_vec();
        rev_head.reverse();
        out[..mask.len()].copy_from_slice(mask);
        out.extend_from_slice(&rev_head);
        out.extend_from_slice(&(mask.len() as i32).to_le_bytes());
        out
    }

    fn make_minimal_zip(entry_name: &[u8]) -> Vec<u8> {
        let mut zip_bytes = Vec::new();
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        zip_bytes.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0; 12]);
        zip_bytes.extend_from_slice(&(entry_name.len() as u16).to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(entry_name);
        let cd_offset = zip_bytes.len() as u32;
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        zip_bytes.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0; 12]);
        zip_bytes.extend_from_slice(&(entry_name.len() as u16).to_le_bytes());
        zip_bytes.extend_from_slice(&[0; 14]);
        zip_bytes.extend_from_slice(&0u32.to_le_bytes());
        zip_bytes.extend_from_slice(entry_name);
        let cd_size = (zip_bytes.len() as u32) - cd_offset;
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&1u16.to_le_bytes());
        zip_bytes.extend_from_slice(&1u16.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_size.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_offset.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes
    }

    fn make_minimal_7z(extra_body: usize) -> Vec<u8> {
        let mut hdr = vec![0u8; 32 + extra_body];
        hdr[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
        hdr[6] = 0;
        hdr[7] = 4;
        let crc = crc32fast::hash(&hdr[12..32]);
        hdr[8..12].copy_from_slice(&crc.to_le_bytes());
        hdr
    }

    fn make_minimal_rar5() -> Vec<u8> {
        let mut out = b"Rar!\x1A\x07\x01\x00".to_vec();
        let crc_data = [3u8, 1u8, 0u8, 0u8];
        let crc = crc32fast::hash(&crc_data);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&crc_data);
        out.extend_from_slice(&[0u8; 16]);
        out
    }

    fn make_minimal_rar4() -> Vec<u8> {
        let mut out = b"Rar!\x1A\x07\x00".to_vec();
        let body = [0x73u8, 0x00, 0x00, 0x0D, 0x00, 0, 0, 0, 0, 0, 0];
        let crc16 = (crc32fast::hash(&body) & 0xFFFF) as u16;
        out.extend_from_slice(&crc16.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn make_minimal_tar() -> Vec<u8> {
        let mut hdr = vec![0u8; 512];
        hdr[0..9].copy_from_slice(b"hello.txt");
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[148..156].copy_from_slice(b"        ");
        let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
        let chk = format!("{sum:06o}\0 ");
        hdr[148..156].copy_from_slice(chk.as_bytes());
        hdr
    }

    #[test]
    fn test_apate_detection_all_modes_and_guards() {
        let dir = std::env::temp_dir().join("oh_unzip_apate_codec_tests");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let jpg_mask = [0xFFu8, 0xD8, 0xFF, 0xE1];
        let mov_mask = [0x6Du8, 0x6F, 0x6F, 0x76];
        let mut mp4_big_mask = vec![0u8; 4096];
        mp4_big_mask[..32].copy_from_slice(&[
            0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00,
            0x02, 0x00, 0x69, 0x73, 0x6F, 0x6D, 0x69, 0x73, 0x6F, 0x32, 0x61, 0x76, 0x63, 0x31,
            0x6D, 0x70, 0x34, 0x31,
        ]);
        let mut exe_mask = vec![0u8; 128];
        exe_mask[0..2].copy_from_slice(b"MZ");

        // 1. Case 1 (orig > mask): 4-byte JPG mask splits the 32-byte 7z header across tail & body
        let f_7z_jpg = dir.join("secret.7z.jpg");
        fs::write(&f_7z_jpg, apate_disguise(&make_minimal_7z(64), &jpg_mask)).unwrap();
        let det = detect_file(&f_7z_jpg, DetectOptions::default()).unwrap();
        assert_eq!(det.format, ArchiveFormat::SevenZ);
        assert!(det.is_stego_carrier());
        assert_eq!(det.stego_tool(), Some("apate"));
        assert!(matches!(
            det.trick,
            TrickKind::Stego { tool: "apate", ref badge } if badge.contains("JPG") && badge.contains("4 B")
        ));

        // 2. Case 2 (orig < mask): 4096-byte MP4 mask hiding a tiny ZIP
        let tiny_zip = make_minimal_zip(b"hello.txt");
        let f_zip_mp4 = dir.join("video.mp4");
        fs::write(&f_zip_mp4, apate_disguise(&tiny_zip, &mp4_big_mask)).unwrap();
        let det2 = detect_file(&f_zip_mp4, DetectOptions::default()).unwrap();
        assert_eq!(det2.format, ArchiveFormat::Zip);
        assert!(matches!(
            det2.trick,
            TrickKind::Stego { tool: "apate", ref badge } if badge.contains("MP4") && badge.contains("4.0 KB")
        ));

        // 3. Exact boundary (orig.len() == mask.len())
        let exact_mask = vec![0xAAu8; tiny_zip.len()];
        let f_exact = dir.join("exact.bin");
        fs::write(&f_exact, apate_disguise(&tiny_zip, &exact_mask)).unwrap();
        let det_exact = detect_file(&f_exact, DetectOptions::default()).unwrap();
        assert_eq!(det_exact.format, ArchiveFormat::Zip);
        assert_eq!(det_exact.stego_tool(), Some("apate"));

        // 4. MOV simple mask on RAR5 & EXE simple mask on RAR4 (including nested!)
        let f_rar5 = dir.join("clip.rar.mov");
        fs::write(&f_rar5, apate_disguise(&make_minimal_rar5(), &mov_mask)).unwrap();
        let det_r5 = detect_file(&f_rar5, DetectOptions::default()).unwrap();
        assert_eq!(det_r5.format, ArchiveFormat::Rar);
        assert!(matches!(
            det_r5.trick,
            TrickKind::Stego { tool: "apate", ref badge } if badge.contains("MOV")
        ));

        let f_rar4 = dir.join("pack.rar.exe");
        fs::write(&f_rar4, apate_disguise(&make_minimal_rar4(), &exe_mask)).unwrap();
        let det_r4 = detect_file_with_context(&f_rar4, DetectOptions::default(), true).unwrap();
        assert_eq!(det_r4.format, ArchiveFormat::Rar);
        assert!(matches!(
            det_r4.trick,
            TrickKind::Stego { tool: "apate", ref badge } if badge.contains("EXE")
        ));

        // 5. TAR disguised with MP4 mask
        let f_tar = dir.join("data.tar.mp4");
        fs::write(&f_tar, apate_disguise(&make_minimal_tar(), &mp4_big_mask)).unwrap();
        let det_tar = detect_file(&f_tar, DetectOptions::default()).unwrap();
        assert_eq!(det_tar.format, ArchiveFormat::Tar);

        // 6. Apate-disguised split first volume (`movie.7z.001.mp4`)
        let f_split = dir.join("movie.7z.001.mp4");
        fs::write(&f_split, apate_disguise(&make_minimal_7z(128), &mp4_big_mask)).unwrap();
        let det_split = detect_file(&f_split, DetectOptions::default()).unwrap();
        assert_eq!(det_split.format, ArchiveFormat::SevenZ);
        assert!(det_split.is_split);
        assert_eq!(
            det_split.disguised_split.as_ref().map(|s| s.clean_filename()),
            Some("movie.7z.001".into())
        );
        assert_eq!(det_split.stego_tool(), Some("apate"));

        // 7. Stacked multi-layer Apate (3 layers: 7z -> MP4 -> EXE -> JPG, mixing orig<mask & orig>mask!)
        let layer1 = apate_disguise(&make_minimal_7z(64), &mp4_big_mask);
        let layer2 = apate_disguise(&layer1, &exe_mask);
        let layer3 = apate_disguise(&layer2, &jpg_mask);
        let f_multi = dir.join("nested.7z.mp4.exe.jpg");
        fs::write(&f_multi, &layer3).unwrap();
        let det_multi = detect_file(&f_multi, DetectOptions::default()).unwrap();
        assert_eq!(det_multi.format, ArchiveFormat::SevenZ);
        assert_eq!(det_multi.stego_tool(), Some("apate"));
        assert!(matches!(
            det_multi.trick,
            TrickKind::Stego { tool: "apate", ref badge }
                if badge.contains("3层隐写") && badge.contains("JPG→EXE→MP4")
        ));

        // 8. Stacked multi-layer Apate with a real `.docx` mask inside `.mp4` mask!
        let docx_mask = make_minimal_zip(b"[Content_Types].xml/word/document.xml");
        let l1_docx = apate_disguise(&make_minimal_7z(64), &docx_mask);
        let l2_mp4 = apate_disguise(&l1_docx, &mp4_big_mask);
        let f_docx_layer = dir.join("secret.7z.docx.mp4");
        fs::write(&f_docx_layer, &l2_mp4).unwrap();
        let det_docx_layer = detect_file(&f_docx_layer, DetectOptions::default()).unwrap();
        assert_eq!(det_docx_layer.format, ArchiveFormat::SevenZ);
        assert!(matches!(
            det_docx_layer.trick,
            TrickKind::Stego { tool: "apate", ref badge } if badge.contains("2层隐写")
        ));

        // 9. Respects `detect_polyglot = false`
        let opts_off = DetectOptions {
            detect_polyglot: false,
            ..DetectOptions::default()
        };
        assert!(detect_file(&f_zip_mp4, opts_off).is_none());

        // 10. False-positive guard: non-Apate MP4 whose last 4 bytes happen to be a small positive i32
        let mut fake_mp4 = mp4_big_mask.clone();
        fake_mp4.extend_from_slice(&[0x11u8; 512]);
        fake_mp4.extend_from_slice(&32i32.to_le_bytes());
        let f_plain_mp4 = dir.join("normal_video.mp4");
        fs::write(&f_plain_mp4, &fake_mp4).unwrap();
        assert!(detect_file(&f_plain_mp4, DetectOptions::default()).is_none());

        // 11. Apate-disguised real Office `.docx` skipped when `skip_office_zip = true`
        let f_docx_apate = dir.join("report.docx.mp4");
        fs::write(&f_docx_apate, apate_disguise(&docx_mask, &mp4_big_mask)).unwrap();
        assert!(detect_file(&f_docx_apate, DetectOptions::default()).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_apate_restore_byte_exact_and_cancel() {
        let dir = std::env::temp_dir().join("oh_unzip_apate_restore_codec_tests");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let cancel = AtomicBool::new(false);

        // Single-layer cases (orig > mask, orig < mask, orig == mask, tiny split tail)
        let cases: &[(usize, usize)] = &[(20_000, 32), (100, 8192), (512, 512), (5, 1024)];
        for (idx, &(orig_len, mask_len)) in cases.iter().enumerate() {
            let orig: Vec<u8> = (0..orig_len).map(|i| ((i * 31 + 7) & 0xFF) as u8).collect();
            let mask: Vec<u8> = (0..mask_len).map(|i| ((i * 17 + 3) & 0xFF) as u8).collect();
            let disguised = apate_disguise(&orig, &mask);

            let src = dir.join(format!("case_{idx}.mp4"));
            let dst = dir.join(format!("case_{idx}.restored"));
            fs::write(&src, &disguised).unwrap();

            let mut saw_100 = false;
            restore_apate_layers_to_path(&src, &dst, &[mask_len as u64], &cancel, &mut |pct| {
                if pct == 100 {
                    saw_100 = true;
                }
            })
            .expect("single-layer restore should succeed");

            assert!(saw_100);
            assert_eq!(fs::read(&dst).unwrap(), orig);
        }

        // Multi-layer stacked cases:
        // A: 3 layers mixing Case 2 (orig < mask1), Case 1 (mid > mask2), Case 2 (mid2 < mask3)
        // B: 3 layers all Case 1 (orig > mask1, mask2, mask3) with straddling boundaries
        let multi_cases: &[(usize, &[usize])] = &[
            (257, &[1024, 16, 4096]),
            (15_000, &[4, 128, 3000]),
            (77, &[77, 158, 4]),
        ];
        for (idx, &(orig_len, mask_sizes)) in multi_cases.iter().enumerate() {
            let orig: Vec<u8> = (0..orig_len).map(|i| ((i * 53 + 19) & 0xFF) as u8).collect();
            let mut data = orig.clone();
            for (layer_idx, &msz) in mask_sizes.iter().enumerate() {
                let mask: Vec<u8> = (0..msz)
                    .map(|i| ((i * (layer_idx + 11) + 5) & 0xFF) as u8)
                    .collect();
                data = apate_disguise(&data, &mask);
            }
            // Outer-to-inner mask lengths for restoration
            let outer_to_inner: Vec<u64> = mask_sizes.iter().rev().map(|&m| m as u64).collect();

            let src = dir.join(format!("multi_{idx}.bin"));
            let dst = dir.join(format!("multi_{idx}.restored"));
            fs::write(&src, &data).unwrap();

            restore_apate_layers_to_path(&src, &dst, &outer_to_inner, &cancel, &mut |_| {})
                .expect("multi-layer restore should succeed");
            assert_eq!(fs::read(&dst).unwrap(), orig);
        }

        // Cancellation test
        let src = dir.join("case_0.mp4");
        let dst = dir.join("cancelled.out");
        let cancelled = AtomicBool::new(true);
        let res = restore_apate_layers_to_path(&src, &dst, &[32], &cancelled, &mut |_| {});
        assert!(matches!(res, Err(StegoError::Cancelled)));

        let _ = fs::remove_dir_all(&dir);
    }
}
