use super::{ProbeContext, ProbeCost, StegoCodec, StegoError, StegoMatch, StegoRestorer};
use crate::detector::{
    ArchiveFormat, FileSource, format_bytes, validate_7z_start_header, validate_rar5_header_at,
};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Codec for traditional polyglot / appended archives (e.g. `copy /b image.jpg+archive.zip`,
/// appended ZIP/7z/RAR inside JPEG/PNG/GIF/MP4/PDF/etc.).
pub struct PolyglotCodec;

pub struct OffsetRestorer {
    pub carrier: String,
    pub offset: u64,
}

impl StegoCodec for PolyglotCodec {
    fn id(&self) -> &'static str {
        "polyglot"
    }

    fn cost(&self) -> ProbeCost {
        ProbeCost::FallbackScan
    }

    fn probe(&self, ctx: &mut ProbeContext<'_>) -> Option<StegoMatch> {
        // Skip linear polyglot scanning on nested native binaries/installers inside software trees
        if ctx.is_nested && matches!(ctx.ext, "exe" | "dll" | "so" | "dylib" | "pyd" | "node") {
            return None;
        }

        let (fmt, offset) = scan_embedded_archive(ctx.file, ctx.file_len)?;
        let carrier = detect_carrier_kind(ctx.header, ctx.ext);
        Some(StegoMatch {
            format: fmt,
            is_split: false,
            disguised_split: None,
            restorer: Arc::new(OffsetRestorer { carrier, offset }),
        })
    }
}

impl StegoRestorer for OffsetRestorer {
    fn tool_id(&self) -> &'static str {
        "polyglot"
    }

    fn badge_text(&self, fmt: ArchiveFormat) -> String {
        format!(
            "隐写/{} ({} @ {})",
            self.carrier,
            fmt.display_name(),
            format_bytes(self.offset)
        )
    }

    fn stage_label(&self, fmt: ArchiveFormat) -> String {
        format!(
            "正在提取隐写载荷 ({} @ {})",
            fmt.display_name(),
            format_bytes(self.offset)
        )
    }

    fn restored_log(&self, fmt: ArchiveFormat) -> String {
        format!("已剥离隐写尾部载荷 → 临时文件 ({})", fmt.canonical_ext())
    }

    fn restore_to(
        &self,
        src: &Path,
        dst: &Path,
        cancel_flag: &AtomicBool,
        on_progress: &mut dyn FnMut(u8),
    ) -> Result<(), StegoError> {
        let mut reader = File::open(src)
            .map_err(|e| StegoError::Message(format!("无法读取源文件: {e}")))?;
        let file_len = reader
            .metadata()
            .map_err(|e| StegoError::Message(format!("无法读取源文件大小: {e}")))?
            .len();
        if self.offset >= file_len {
            return Err(StegoError::Message("无效的隐写偏移位置".into()));
        }
        let payload_len = file_len - self.offset;

        reader
            .seek(SeekFrom::Start(self.offset))
            .map_err(|e| StegoError::Message(format!("无法定位隐写偏移: {e}")))?;
        let mut writer = File::create(dst)
            .map_err(|e| StegoError::Message(format!("无法创建临时载荷文件: {e}")))?;

        let buf_size = (payload_len.min(4 * 1024 * 1024) as usize).max(4096);
        let mut buf = vec![0u8; buf_size];
        let mut copied = 0u64;
        loop {
            if cancel_flag.load(Ordering::Relaxed) {
                return Err(StegoError::Cancelled);
            }
            let n = reader
                .read(&mut buf)
                .map_err(|e| StegoError::Message(format!("读取源文件失败: {e}")))?;
            if n == 0 {
                break;
            }
            writer
                .write_all(&buf[..n])
                .map_err(|e| StegoError::Message(format!("写入临时载荷文件失败: {e}")))?;
            copied += n as u64;
            on_progress(((copied.saturating_mul(100)) / payload_len).min(100) as u8);
        }
        writer
            .flush()
            .map_err(|e| StegoError::Message(format!("刷新临时文件失败: {e}")))?;

        Ok(())
    }
}

fn detect_carrier_kind(header: &[u8], ext: &str) -> String {
    if header.len() >= 3 && header[0..3] == [0xFF, 0xD8, 0xFF] {
        return "JPEG图种".into();
    }
    if header.len() >= 8 && header[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return "PNG图种".into();
    }
    if header.len() >= 6 && (&header[0..6] == b"GIF87a" || &header[0..6] == b"GIF89a") {
        return "GIF图种".into();
    }
    if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP" {
        return "WEBP图种".into();
    }
    if header.len() >= 2 && &header[0..2] == b"BM" {
        return "BMP图种".into();
    }
    if header.len() >= 12 && &header[4..8] == b"ftyp" {
        return "MP4视频种".into();
    }
    if header.len() >= 4 && header[0..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return "MKV视频种".into();
    }
    if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"AVI " {
        return "AVI视频种".into();
    }
    if header.len() >= 4 && &header[0..4] == b"%PDF" {
        return "PDF隐写".into();
    }
    if header.len() >= 3
        && (&header[0..3] == b"ID3" || (header[0] == 0xFF && (header[1] & 0xE0) == 0xE0))
    {
        return "音频隐写".into();
    }
    if header.len() >= 4 && &header[0..4] == b"fLaC" {
        return "FLAC隐写".into();
    }
    if header.len() >= 2 && &header[0..2] == b"MZ" {
        return "EXE自解压/捆绑".into();
    }
    if !ext.is_empty() {
        format!(".{ext}隐写")
    } else {
        "文件拼接隐写".into()
    }
}

/// Scans a non-archive carrier file for an embedded/appended ZIP, 7z, or RAR archive.
fn scan_embedded_archive(file: &mut File, file_len: u64) -> Option<(ArchiveFormat, u64)> {
    if let Some(zip_offset) = find_embedded_zip_eocd(file, file_len) {
        return Some((ArchiveFormat::Zip, zip_offset));
    }

    if let Some((fmt, offset)) = scan_embedded_7z_or_rar(file, file_len) {
        return Some((fmt, offset));
    }

    None
}

fn find_embedded_zip_eocd(file: &mut File, file_len: u64) -> Option<u64> {
    if file_len < 22 {
        return None;
    }
    let tail_len = file_len.min(65_536 + 22) as usize;
    let tail_start = file_len - tail_len as u64;
    let mut tail = vec![0u8; tail_len];
    file.seek(SeekFrom::Start(tail_start)).ok()?;
    file.read_exact(&mut tail).ok()?;

    let mut i = tail_len.saturating_sub(22);
    loop {
        if tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06 {
            let comment_len = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
            let remaining = tail_len - (i + 22);
            if comment_len == remaining {
                let cd_size = u32::from_le_bytes([
                    tail[i + 12],
                    tail[i + 13],
                    tail[i + 14],
                    tail[i + 15],
                ]) as u64;
                let cd_offset = u32::from_le_bytes([
                    tail[i + 16],
                    tail[i + 17],
                    tail[i + 18],
                    tail[i + 19],
                ]) as u64;
                let eocd_abs = tail_start + i as u64;

                if let Some(cd_abs) = eocd_abs.checked_sub(cd_size) {
                    if let Some(zip_start) = cd_abs.checked_sub(cd_offset) {
                        if zip_start > 0
                            && verify_bytes_at(file, cd_abs, &[0x50, 0x4B, 0x01, 0x02])
                            && verify_bytes_at(file, zip_start, &[0x50, 0x4B, 0x03, 0x04])
                        {
                            return Some(zip_start);
                        }
                    }
                }

                if cd_offset > 0
                    && cd_offset + cd_size == eocd_abs
                    && verify_bytes_at(file, cd_offset, &[0x50, 0x4B, 0x01, 0x02])
                {
                    if let Some(local_off) = read_first_cd_local_offset(file, cd_offset) {
                        if local_off > 0
                            && verify_bytes_at(file, local_off, &[0x50, 0x4B, 0x03, 0x04])
                        {
                            return Some(local_off);
                        }
                    }
                }
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }

    None
}

fn read_first_cd_local_offset(file: &mut File, cd_abs: u64) -> Option<u64> {
    let mut cd_hdr = [0u8; 46];
    file.seek(SeekFrom::Start(cd_abs)).ok()?;
    file.read_exact(&mut cd_hdr).ok()?;
    if cd_hdr[0..4] != [0x50, 0x4B, 0x01, 0x02] {
        return None;
    }
    let off = u32::from_le_bytes([cd_hdr[42], cd_hdr[43], cd_hdr[44], cd_hdr[45]]) as u64;
    Some(off)
}

fn verify_bytes_at(file: &mut File, offset: u64, expected: &[u8]) -> bool {
    let mut buf = vec![0u8; expected.len()];
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return false;
    }
    if file.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == expected
}

fn scan_embedded_7z_or_rar(file: &mut File, file_len: u64) -> Option<(ArchiveFormat, u64)> {
    const CHUNK_SIZE: usize = 2 * 1024 * 1024;
    const OVERLAP: usize = 64;
    let ranges: Vec<(u64, u64)> = if file_len <= 512 * 1024 * 1024 {
        vec![(1, file_len)]
    } else {
        vec![
            (1, 64 * 1024 * 1024),
            (file_len - 128 * 1024 * 1024, file_len),
        ]
    };

    let mut buf = vec![0u8; CHUNK_SIZE + OVERLAP];

    for (range_start, range_end) in ranges {
        let mut pos = range_start;
        while pos < range_end {
            let to_read = ((range_end - pos) as usize).min(CHUNK_SIZE + OVERLAP);
            if file.seek(SeekFrom::Start(pos)).is_err() {
                break;
            }
            if file.read_exact(&mut buf[..to_read]).is_err() {
                break;
            }
            let slice = &buf[..to_read];

            let mut idx = 0;
            while idx + 32 <= slice.len() {
                if slice[idx] == 0x37
                    && slice[idx + 1] == 0x7A
                    && slice[idx + 2] == 0xBC
                    && slice[idx + 3] == 0xAF
                    && slice[idx + 4] == 0x27
                    && slice[idx + 5] == 0x1C
                {
                    let hdr = &slice[idx..idx + 32];
                    if validate_7z_start_header(hdr) {
                        let next_off = u64::from_le_bytes(hdr[12..20].try_into().unwrap());
                        let next_size = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
                        let abs_pos = pos + idx as u64;
                        if abs_pos
                            .checked_add(32)
                            .and_then(|v| v.checked_add(next_off))
                            .and_then(|v| v.checked_add(next_size))
                            .is_some_and(|end| end <= file_len)
                        {
                            return Some((ArchiveFormat::SevenZ, abs_pos));
                        }
                    }
                }

                if slice[idx] == 0x52
                    && slice[idx + 1] == 0x61
                    && slice[idx + 2] == 0x72
                    && slice[idx + 3] == 0x21
                    && slice[idx + 4] == 0x1A
                    && slice[idx + 5] == 0x07
                {
                    let abs_pos = pos + idx as u64;
                    if slice[idx + 6] == 0x01 && slice[idx + 7] == 0x00 {
                        let mut src = FileSource::new(file, file_len);
                        if validate_rar5_header_at(&mut src, abs_pos) {
                            return Some((ArchiveFormat::Rar, abs_pos));
                        }
                    } else if slice[idx + 6] == 0x00
                        && idx + 14 <= slice.len()
                        && slice[idx + 9] == 0x73
                    {
                        return Some((ArchiveFormat::Rar, abs_pos));
                    }
                }

                idx += 1;
            }

            if to_read <= OVERLAP {
                break;
            }
            pos += (to_read - OVERLAP) as u64;
        }
    }

    None
}
