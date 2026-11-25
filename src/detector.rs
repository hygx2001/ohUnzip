use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    SevenZ,
    Rar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lzma,
    Tar,
    Cab,
    Iso,
    Wim,
    Arj,
    Lzh,
    Deb,
    Rpm,
    Cpio,
    Dmg,
    Xar,
    Generic,
}

impl ArchiveFormat {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Zip => "ZIP",
            Self::SevenZ => "7Z",
            Self::Rar => "RAR",
            Self::Gzip => "GZIP",
            Self::Bzip2 => "BZIP2",
            Self::Xz => "XZ",
            Self::Zstd => "ZSTD",
            Self::Lzma => "LZMA",
            Self::Tar => "TAR",
            Self::Cab => "CAB",
            Self::Iso => "ISO",
            Self::Wim => "WIM",
            Self::Arj => "ARJ",
            Self::Lzh => "LZH",
            Self::Deb => "DEB",
            Self::Rpm => "RPM",
            Self::Cpio => "CPIO",
            Self::Dmg => "DMG",
            Self::Xar => "XAR",
            Self::Generic => "ARCHIVE",
        }
    }

    pub fn canonical_ext(&self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZ => "7z",
            Self::Rar => "rar",
            Self::Gzip => "gz",
            Self::Bzip2 => "bz2",
            Self::Xz => "xz",
            Self::Zstd => "zst",
            Self::Lzma => "lzma",
            Self::Tar => "tar",
            Self::Cab => "cab",
            Self::Iso => "iso",
            Self::Wim => "wim",
            Self::Arj => "arj",
            Self::Lzh => "lzh",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Cpio => "cpio",
            Self::Dmg => "dmg",
            Self::Xar => "xar",
            Self::Generic => "bin",
        }
    }

    pub fn seven_zip_type(&self) -> Option<&'static str> {
        match self {
            Self::Zip => Some("zip"),
            Self::SevenZ => Some("7z"),
            Self::Rar => Some("rar"),
            Self::Gzip => Some("gzip"),
            Self::Bzip2 => Some("bzip2"),
            Self::Xz => Some("xz"),
            Self::Zstd => Some("zstd"),
            Self::Lzma => Some("lzma"),
            Self::Tar => Some("tar"),
            Self::Cab => Some("cab"),
            Self::Iso => Some("iso"),
            Self::Wim => Some("wim"),
            Self::Arj => Some("arj"),
            Self::Lzh => Some("lzh"),
            Self::Deb => Some("deb"),
            Self::Rpm => Some("rpm"),
            Self::Cpio => Some("cpio"),
            Self::Dmg => Some("dmg"),
            Self::Xar => Some("xar"),
            Self::Generic => None,
        }
    }

    pub fn known_extensions(&self) -> &'static [&'static str] {
        match self {
            Self::Zip => &["zip", "zipx"],
            Self::SevenZ => &["7z"],
            Self::Rar => &["rar"],
            Self::Gzip => &["gz", "tgz", "gzip"],
            Self::Bzip2 => &["bz2", "tbz2", "tbz", "bzip2"],
            Self::Xz => &["xz", "txz"],
            Self::Zstd => &["zst", "tzst", "zstd"],
            Self::Lzma => &["lzma"],
            Self::Tar => &["tar"],
            Self::Cab => &["cab"],
            Self::Iso => &["iso"],
            Self::Wim => &["wim", "esd"],
            Self::Arj => &["arj"],
            Self::Lzh => &["lzh", "lha"],
            Self::Deb => &["deb"],
            Self::Rpm => &["rpm"],
            Self::Cpio => &["cpio"],
            Self::Dmg => &["dmg"],
            Self::Xar => &["xar"],
            Self::Generic => &[],
        }
    }

    /// Formats that are genuinely used as disguised archives when renamed to another extension.
    /// System/package container formats (like `deb`/`ar`, `rpm`, `cab`, `wim`, `iso`) are
    /// excluded so `.lib`, `.a`, `.dll`, `.exe`, etc. are NEVER misidentified as disguised archives.
    pub fn allow_disguised_detection(&self) -> bool {
        matches!(
            self,
            Self::Zip
                | Self::SevenZ
                | Self::Rar
                | Self::Gzip
                | Self::Bzip2
                | Self::Xz
                | Self::Zstd
                | Self::Tar
        )
    }

    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "zip" | "zipx" => Some(Self::Zip),
            "7z" => Some(Self::SevenZ),
            "rar" => Some(Self::Rar),
            "gz" | "tgz" | "gzip" => Some(Self::Gzip),
            "bz2" | "tbz2" | "tbz" | "bzip2" => Some(Self::Bzip2),
            "xz" | "txz" => Some(Self::Xz),
            "zst" | "tzst" | "zstd" => Some(Self::Zstd),
            "lzma" => Some(Self::Lzma),
            "tar" => Some(Self::Tar),
            "cab" => Some(Self::Cab),
            "iso" => Some(Self::Iso),
            "wim" | "esd" => Some(Self::Wim),
            "arj" => Some(Self::Arj),
            "lzh" | "lha" => Some(Self::Lzh),
            "deb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            "cpio" => Some(Self::Cpio),
            "dmg" => Some(Self::Dmg),
            "xar" => Some(Self::Xar),
            _ => None,
        }
    }

    pub fn from_7z_type_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "zip" => Some(Self::Zip),
            "7z" => Some(Self::SevenZ),
            "rar" | "rar5" => Some(Self::Rar),
            "gzip" => Some(Self::Gzip),
            "bzip2" => Some(Self::Bzip2),
            "xz" => Some(Self::Xz),
            "zstd" => Some(Self::Zstd),
            "lzma" => Some(Self::Lzma),
            "tar" => Some(Self::Tar),
            "cab" => Some(Self::Cab),
            "iso" | "udf" => Some(Self::Iso),
            "wim" => Some(Self::Wim),
            "arj" => Some(Self::Arj),
            "lzh" => Some(Self::Lzh),
            "deb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            "cpio" => Some(Self::Cpio),
            "dmg" => Some(Self::Dmg),
            "xar" => Some(Self::Xar),
            "split" => Some(Self::Generic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrickKind {
    Normal,
    DisguisedExtension { original_ext: String },
    Polyglot { carrier: String, offset: u64 },
    SplitVolume { label: String },
}

impl TrickKind {
    pub fn badge_text(&self, fmt: ArchiveFormat) -> Option<String> {
        match self {
            Self::Normal => Some(format!("{} 压缩包", fmt.display_name())),
            Self::DisguisedExtension { original_ext } => {
                if original_ext.is_empty() {
                    Some(format!("无后缀 → {}", fmt.display_name()))
                } else {
                    Some(format!("改后缀 .{} → {}", original_ext, fmt.display_name()))
                }
            }
            Self::Polyglot { carrier, offset } => Some(format!(
                "隐写/{} ({} @ {})",
                carrier,
                fmt.display_name(),
                format_bytes(*offset)
            )),
            Self::SplitVolume { label } => Some(format!("分卷 {} ({label})", fmt.display_name())),
        }
    }

    pub fn is_tricky(&self) -> bool {
        matches!(
            self,
            Self::DisguisedExtension { .. } | Self::Polyglot { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedArchive {
    pub format: ArchiveFormat,
    /// Byte offset where the archive stream begins. `0` for regular/disguised files, `> 0` for polyglots.
    pub offset: u64,
    pub trick: TrickKind,
    pub is_split: bool,
    /// Set when this is a disguised split first volume (e.g. `foo.7z.001.mp4`, `bar.part1.rar删`).
    pub disguised_split: Option<DisguisedSplitInfo>,
}

#[derive(Debug, Clone, Copy)]
pub struct DetectOptions {
    pub detect_disguised: bool,
    pub detect_polyglot: bool,
    pub skip_office_zip: bool,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            detect_disguised: true,
            detect_polyglot: true,
            skip_office_zip: true,
        }
    }
}

/// Extensions that represent genuine software packages, libraries, binaries, or structured
/// container formats (NOT disguised archives). These must NEVER be treated as "改后缀"
/// or unpacked automatically!
pub fn is_protected_component_ext(ext: &str) -> bool {
    matches!(
        ext,
        // Java / JVM / Eclipse / Android / iOS packages
        "jar" | "war" | "ear" | "jmod" | "aar" | "sar" | "har" | "apk" | "aab" | "ipa" | "xapk"
        // Python / Node / Ruby / Rust / .NET / IDE / Browser packages
        | "whl" | "egg" | "pyz" | "pex" | "vsix" | "nupkg" | "snupkg" | "xpi" | "crx"
        | "appx" | "msix" | "gem" | "crate" | "snap" | "flatpak"
        // Native libraries, object files, executables, installers
        | "lib" | "a" | "o" | "obj" | "dll" | "so" | "dylib" | "sys" | "ocx" | "msi"
        // Office / OpenDocument / E-books / Design / 3D / Comic / Game containers
        | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "xltx" | "potx"
        | "odt" | "ods" | "odp" | "odg" | "epub" | "oxps" | "xps"
        | "pages" | "numbers" | "key"
        | "kra" | "ora" | "sketch" | "fig" | "3mf" | "kmz" | "rbz" | "svgz" | "blend"
        | "cbz" | "cbr" | "cb7"
        | "mcpack" | "mcworld" | "mcaddon" | "love" | "pak" | "vpk" | "pk3" | "pk4" | "scs"
        | "unitypackage" | "woff" | "woff2" | "nbt" | "mca"
    )
}

/// Extensions of Office/ebook documents where someone *occasionally* renames a real zip to `.docx`
/// when dropping a file directly at top-level. We check internal markers to tell a real `.docx`
/// apart from a fake `.docx` ONLY for these extensions when `allow_fake_doc_check` is true.
fn is_inspectable_doc_ext(ext: &str) -> bool {
    matches!(ext, "docx" | "xlsx" | "pptx" | "epub")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisguisedSplitInfo {
    /// Prefix before the volume number (e.g. `"movie.7z."` or `"game.part"`).
    pub prefix: String,
    /// Digit width / token for this part (e.g. `"001"` or `"01"`).
    pub number_str: String,
    /// Parsed 1-based volume number.
    pub part_num: u32,
    /// Optional real archive suffix right after the number (e.g. `".rar"` for `.part01.rar.mp4`, empty for `.7z.001.mp4`).
    pub mid_suffix: String,
    /// Trailing disguise suffix appended after the real volume name (e.g. `".mp4"`, `"删"`, `"1"`).
    pub disguise_tail: String,
}

impl DisguisedSplitInfo {
    /// Clean filename with the trailing disguise removed (e.g. `"movie.7z.001"` or `"game.part01.rar"`).
    pub fn clean_filename(&self) -> String {
        format!("{}{}{}", self.prefix, self.number_str, self.mid_suffix)
    }
}

/// Detects disguised split archive filenames such as:
/// - `movie.7z.001.mp4`, `movie.7z.001删`, `movie.zip.001.bak`, `archive.001.jpg`
/// - `game.part1.rar.mp4`, `game.part01.rar删`, `game.part01.rar1`
pub fn parse_disguised_split_filename(name: &str) -> Option<DisguisedSplitInfo> {
    let lower = name.to_ascii_lowercase();

    // Pattern A: `*.part<digits>.rar<tail>` where <tail> is non-empty (e.g. `.mp4`, `删`, `1`)
    if let Some(part_pos) = lower.rfind(".part") {
        let after_part = &name[part_pos + 5..];
        let digit_len = after_part.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digit_len > 0 {
            let num_str = &after_part[..digit_len];
            let rest = &after_part[digit_len..];
            let rest_lower = rest.to_ascii_lowercase();
            if rest_lower.starts_with(".rar") && rest.len() > 4 {
                let tail = &rest[4..];
                if let Ok(part_num) = num_str.parse::<u32>() {
                    if part_num >= 1 {
                        return Some(DisguisedSplitInfo {
                            prefix: name[..part_pos + 5].to_string(),
                            number_str: num_str.to_string(),
                            part_num,
                            mid_suffix: rest[..4].to_string(),
                            disguise_tail: tail.to_string(),
                        });
                    }
                }
            }
        }
    }

    // Pattern B: `*.<3+ digits><tail>` where <tail> is non-empty and preceded by a dot
    // e.g. `movie.7z.001.mp4`, `movie.7z.001删`, `pack.001.jpg`
    let bytes = name.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] == b'.' {
            let after_dot = &name[i + 1..];
            let digit_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
            if digit_len >= 3 && digit_len < after_dot.len() {
                let num_str = &after_dot[..digit_len];
                let tail = &after_dot[digit_len..];
                // Avoid matching year/date stamps like `foo.2026.mp4` (4-digit years 1900..2100)
                if let Ok(part_num) = num_str.parse::<u32>() {
                    if (1..=999).contains(&part_num) && !(digit_len == 4 && part_num >= 1900) {
                        // Require either an archive hint before `.001` (like `.7z.001`, `.zip.001`, `.rar.001`)
                        // OR a clearly non-date 3-digit volume like `.001`..`.999`
                        if digit_len == 3 {
                            return Some(DisguisedSplitInfo {
                                prefix: name[..i + 1].to_string(),
                                number_str: num_str.to_string(),
                                part_num,
                                mid_suffix: String::new(),
                                disguise_tail: tail.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    None
}

/// Returns true if the file is a secondary split archive part that must NOT be extracted independently.
pub fn is_non_first_split_volume(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();

    // Disguised secondary split volume (e.g. `movie.7z.002.mp4`, `movie.7z.002删`, `game.part2.rar1`)
    if let Some(info) = parse_disguised_split_filename(name) {
        if info.part_num > 1 {
            return true;
        }
    }

    // `.part2.rar`, `.part02.rar`, `.part003.rar`
    if let Some(before_rar) = lower.strip_suffix(".rar") {
        if let Some(pos) = before_rar.rfind(".part") {
            let digits = &before_rar[pos + 5..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(num) = digits.parse::<u32>() {
                    return num > 1;
                }
            }
        }
    }

    // `.002` .. `.999` (numeric extension > 1, 3+ digits)
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if ext_lower.len() >= 3 && ext_lower.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(num) = ext_lower.parse::<u32>() {
                return num > 1;
            }
        }
        // `.z01`..`.z99` or `.r00`..`.r99`
        if ext_lower.len() == 3 {
            let bytes = ext_lower.as_bytes();
            if (bytes[0] == b'z' || bytes[0] == b'r')
                && bytes[1].is_ascii_digit()
                && bytes[2].is_ascii_digit()
            {
                return true;
            }
        }
    }

    false
}

/// Check if the filename indicates a first split volume (e.g., `.001`, `.part1.rar`, `.part01.rar`).
pub fn split_first_volume_label(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();

    if let Some(before_rar) = lower.strip_suffix(".rar") {
        if let Some(pos) = before_rar.rfind(".part") {
            let digits = &before_rar[pos + 5..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                if digits.parse::<u32>().ok() == Some(1) {
                    return Some(format!(".part{digits}.rar"));
                }
            }
        }
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
            if ext.parse::<u32>().ok() == Some(1) {
                return Some(format!(".{ext}"));
            }
        }
    }

    None
}

fn infer_split_format_from_name(path: &Path) -> ArchiveFormat {
    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.ends_with(".rar") {
        return ArchiveFormat::Rar;
    }
    if let Some(dot_idx) = lower.rfind('.') {
        let before = &lower[..dot_idx];
        if let Some(prev_dot) = before.rfind('.') {
            let inner_ext = &before[prev_dot + 1..];
            if let Some(fmt) = ArchiveFormat::from_extension(inner_ext) {
                return fmt;
            }
        }
    }
    ArchiveFormat::Generic
}

/// Detect whether `path` is an archive (normal, disguised extension, split volume, or polyglot/stego).
/// `is_nested`: true when scanning inside an already-extracted directory (stricter against false positives).
pub fn detect_file(path: &Path, opts: DetectOptions) -> Option<DetectedArchive> {
    detect_file_with_context(path, opts, false)
}

pub fn detect_file_with_context(
    path: &Path,
    opts: DetectOptions,
    is_nested: bool,
) -> Option<DetectedArchive> {
    if !path.is_file() {
        return None;
    }
    if is_non_first_split_volume(path) {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len < 16 {
        return None;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Protect software/library/package components (`.jar`, `.whl`, `.lib`, `.a`, `.apk`, `.dll`, etc.)
    // They are real components, NOT disguised archives!
    if opts.skip_office_zip && is_protected_component_ext(&ext) {
        // For top-level `.docx`/`.xlsx`/`.pptx`/`.epub` explicitly dropped by user, still allow
        // detecting if someone renamed a plain zip/7z/rar to `.docx` (i.e. NOT a real Office doc).
        // For all other components (`.jar`, `.whl`, `.lib`, `.a`, `.apk`, `.vsix`, etc.) or nested files,
        // skip unconditionally!
        if is_nested || !is_inspectable_doc_ext(&ext) {
            return None;
        }
    }

    let split_label = split_first_volume_label(path);
    let disguised_split_first = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(parse_disguised_split_filename)
        .filter(|info| info.part_num == 1);
    let is_split = split_label.is_some() || disguised_split_first.is_some();

    // Read header buffer (first 4096 bytes for magic + zip local entry + tar ustar)
    let header_len = file_len.min(4096) as usize;
    let mut header = vec![0u8; header_len];
    file.read_exact(&mut header).ok()?;

    // 1. Check Magic Bytes at offset 0
    if let Some(fmt) = detect_magic_at_start(&header, &mut file, file_len, &ext) {
        let is_expected_ext = fmt.known_extensions().contains(&ext.as_str());

        // If top-level `.docx`/`.xlsx`/`.pptx`/`.epub` is actually a real Office/EPUB document, skip it
        if fmt == ArchiveFormat::Zip
            && !is_expected_ext
            && opts.skip_office_zip
            && is_real_zip_document(&header, &mut file, file_len, &ext)
        {
            return None;
        }

        if let Some(info) = disguised_split_first {
            if opts.detect_disguised {
                let label = format!("改后缀分卷 {}", info.clean_filename());
                return Some(DetectedArchive {
                    format: fmt,
                    offset: 0,
                    trick: TrickKind::SplitVolume { label },
                    is_split: true,
                    disguised_split: Some(info),
                });
            }
        }

        if let Some(label) = split_label {
            return Some(DetectedArchive {
                format: fmt,
                offset: 0,
                trick: TrickKind::SplitVolume { label },
                is_split: true,
                disguised_split: None,
            });
        }

        if is_expected_ext {
            return Some(DetectedArchive {
                format: fmt,
                offset: 0,
                trick: TrickKind::Normal,
                is_split,
                disguised_split: None,
            });
        }

        // Disguised extension: only allow real archive formats (never treat `.lib` as `.deb`!)
        if opts.detect_disguised && fmt.allow_disguised_detection() {
            return Some(DetectedArchive {
                format: fmt,
                offset: 0,
                trick: TrickKind::DisguisedExtension { original_ext: ext },
                is_split,
                disguised_split: None,
            });
        } else {
            return None;
        }
    }

    // 2. Normal archive & split-volume recognition by standard extension
    if let Some(info) = disguised_split_first {
        if opts.detect_disguised {
            let label = format!("改后缀分卷 {}", info.clean_filename());
            return Some(DetectedArchive {
                format: infer_split_format_from_name(Path::new(&info.clean_filename())),
                offset: 0,
                trick: TrickKind::SplitVolume { label },
                is_split: true,
                disguised_split: Some(info),
            });
        }
    }

    if let Some(label) = split_label {
        return Some(DetectedArchive {
            format: infer_split_format_from_name(path),
            offset: 0,
            trick: TrickKind::SplitVolume { label },
            is_split: true,
            disguised_split: None,
        });
    }

    if let Some(ext_fmt) = ArchiveFormat::from_extension(&ext) {
        return Some(DetectedArchive {
            format: ext_fmt,
            offset: 0,
            trick: TrickKind::Normal,
            is_split: false,
            disguised_split: None,
        });
    }

    // 3. Polyglot / Steganography / Appended Archive scan (offset > 0)
    // Skip polyglot scan on protected component files (e.g. `.exe` installers/dlls inside a software tree)
    if opts.detect_polyglot && (!is_nested || !matches!(ext.as_str(), "exe" | "dll" | "so" | "dylib" | "pyd" | "node")) {
        let carrier = detect_carrier_kind(&header, &ext);
        if let Some((fmt, offset)) = scan_embedded_archive(&mut file, file_len) {
            return Some(DetectedArchive {
                format: fmt,
                offset,
                trick: TrickKind::Polyglot { carrier, offset },
                is_split: false,
                disguised_split: None,
            });
        }
    }

    None
}

fn detect_magic_at_start(
    header: &[u8],
    file: &mut File,
    file_len: u64,
    ext: &str,
) -> Option<ArchiveFormat> {
    if header.len() < 6 {
        return None;
    }

    // 7z: 37 7A BC AF 27 1C + CRC validation
    if header.len() >= 32
        && &header[0..6] == b"7z\xBC\xAF\x27\x1C"
        && validate_7z_start_header(&header[0..32])
    {
        return Some(ArchiveFormat::SevenZ);
    }

    // RAR5 / RAR4
    if header.len() >= 8 && &header[0..8] == b"Rar!\x1A\x07\x01\x00" {
        return Some(ArchiveFormat::Rar);
    }
    if header.len() >= 7 && &header[0..7] == b"Rar!\x1A\x07\x00" {
        return Some(ArchiveFormat::Rar);
    }

    // ZIP: PK\x03\x04, PK\x05\x06, PK\x07\x08
    if header.len() >= 4
        && header[0] == 0x50
        && header[1] == 0x4B
        && matches!((header[2], header[3]), (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08))
    {
        return Some(ArchiveFormat::Zip);
    }

    // GZIP: 1F 8B 08
    if header[0] == 0x1F && header[1] == 0x8B && header[2] == 0x08 {
        return Some(ArchiveFormat::Gzip);
    }

    // BZIP2: BZh[1-9] + block magic
    if header.len() >= 10
        && &header[0..3] == b"BZh"
        && (b'1'..=b'9').contains(&header[3])
        && (&header[4..10] == b"\x31\x41\x59\x26\x53\x59"
            || &header[4..10] == b"\x17\x72\x45\x38\x50\x90")
    {
        return Some(ArchiveFormat::Bzip2);
    }

    // XZ: FD 37 7A 58 5A 00
    if &header[0..6] == b"\xFD7zXZ\x00" {
        return Some(ArchiveFormat::Xz);
    }

    // ZSTD: 28 B5 2F FD
    if header[0..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Some(ArchiveFormat::Zstd);
    }

    // CAB: MSCF + reserved zeros (only matched when extension is .cab)
    if ext == "cab"
        && header.len() >= 16
        && &header[0..4] == b"MSCF"
        && header[4..8] == [0, 0, 0, 0]
        && header[12..16] == [0, 0, 0, 0]
    {
        return Some(ArchiveFormat::Cab);
    }

    // WIM: MSWIM\0\0\0 (only matched when extension is .wim/.esd)
    if matches!(ext, "wim" | "esd") && header.len() >= 8 && &header[0..8] == b"MSWIM\0\0\0" {
        return Some(ArchiveFormat::Wim);
    }

    // TAR: "ustar" at offset 257
    if header.len() >= 263 && (&header[257..263] == b"ustar\0" || &header[257..263] == b"ustar ") {
        return Some(ArchiveFormat::Tar);
    }

    // ISO 9660: \x01CD001\x01 at offset 0x8000 (only matched when extension is .iso)
    if ext == "iso" && file_len >= 0x8008 {
        let mut buf = [0u8; 7];
        if file.seek(SeekFrom::Start(0x8000)).is_ok() && file.read_exact(&mut buf).is_ok() {
            if &buf == b"\x01CD001\x01" {
                return Some(ArchiveFormat::Iso);
            }
        }
    }

    None
}

/// Validates a 32-byte 7z signature header using its embedded CRC32.
pub fn validate_7z_start_header(hdr: &[u8]) -> bool {
    if hdr.len() < 32 || &hdr[0..6] != b"7z\xBC\xAF\x27\x1C" {
        return false;
    }
    let major = hdr[6];
    if major != 0 {
        return false;
    }
    let expected_crc = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let actual_crc = crc32fast::hash(&hdr[12..32]);
    expected_crc == actual_crc
}

/// Distinguishes genuine Office/EPUB ZIP-based documents from a plain ZIP renamed to `.docx`.
fn is_real_zip_document(header: &[u8], file: &mut File, file_len: u64, ext: &str) -> bool {
    let mut probe_buf = header.to_vec();
    if file_len > 4096 {
        let tail_size = file_len.min(65536) as usize;
        let mut tail = vec![0u8; tail_size];
        if file.seek(SeekFrom::Start(file_len - tail_size as u64)).is_ok()
            && file.read_exact(&mut tail).is_ok()
        {
            probe_buf.extend_from_slice(&tail);
        }
    }

    let contains_marker = |marker: &[u8]| {
        probe_buf
            .windows(marker.len())
            .any(|w| w.eq_ignore_ascii_case(marker))
    };

    let has_office_marker = contains_marker(b"[Content_Types].xml")
        && (contains_marker(b"word/")
            || contains_marker(b"xl/")
            || contains_marker(b"ppt/")
            || contains_marker(b"_rels/.rels"));
    let has_epub_marker = contains_marker(b"application/epub+zip")
        || (contains_marker(b"META-INF/container.xml") && ext == "epub");

    has_office_marker || has_epub_marker
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
    if header.len() >= 3 && (&header[0..3] == b"ID3" || (header[0] == 0xFF && (header[1] & 0xE0) == 0xE0)) {
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
                        if local_off > 0 && verify_bytes_at(file, local_off, &[0x50, 0x4B, 0x03, 0x04]) {
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
                        if validate_rar5_header(file, abs_pos, file_len) {
                            return Some((ArchiveFormat::Rar, abs_pos));
                        }
                    } else if slice[idx + 6] == 0x00 {
                        if idx + 14 <= slice.len() && slice[idx + 9] == 0x73 {
                            return Some((ArchiveFormat::Rar, abs_pos));
                        }
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

fn validate_rar5_header(file: &mut File, abs_pos: u64, file_len: u64) -> bool {
    if abs_pos + 16 > file_len {
        return false;
    }
    let mut head = [0u8; 64];
    let avail = (file_len - (abs_pos + 8)).min(64) as usize;
    if file.seek(SeekFrom::Start(abs_pos + 8)).is_err() {
        return false;
    }
    if file.read_exact(&mut head[..avail]).is_err() {
        return false;
    }
    let expected_crc = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);

    let mut header_size: u64 = 0;
    let mut shift = 0;
    let mut vint_len = 0;
    for &b in &head[4..avail] {
        vint_len += 1;
        header_size |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return false;
        }
    }

    if header_size == 0 || header_size > 4096 {
        return false;
    }
    let total_crc_data = vint_len + header_size as usize;
    if abs_pos + 8 + 4 + total_crc_data as u64 > file_len {
        return false;
    }

    let mut crc_buf = vec![0u8; total_crc_data];
    if file.seek(SeekFrom::Start(abs_pos + 12)).is_err() {
        return false;
    }
    if file.read_exact(&mut crc_buf).is_err() {
        return false;
    }
    crc32fast::hash(&crc_buf) == expected_crc
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Extract potential password hints from arbitrary text (filenames, archive comments, sidecar txt).
pub fn extract_password_hints_from_text(text: &str) -> Vec<String> {
    let keywords = [
        "解压密码",
        "解压码",
        "提取码",
        "密码",
        "password",
        "passwd",
        "pwd",
        "pw",
    ];
    let lower = text.to_lowercase();
    let mut hints = Vec::new();

    for kw in keywords {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(kw) {
            let start = search_from + rel + kw.len();
            if start < text.len() && text.is_char_boundary(start) {
                let rest = &text[start..];
                let trimmed = rest.trim_start_matches(|c: char| {
                    matches!(
                        c,
                        ':' | '：' | '=' | '-' | '_' | ' ' | '\t' | '【' | '[' | '(' | '（' | '"' | '\''
                    )
                });
                let candidate: String = trimmed
                    .chars()
                    .take_while(|c| {
                        !matches!(
                            c,
                            '\r' | '\n'
                                | ' '
                                | '\t'
                                | ']'
                                | '】'
                                | ')'
                                | '）'
                                | ','
                                | '，'
                                | ';'
                                | '；'
                                | '/'
                                | '\\'
                                | '"'
                                | '\''
                        )
                    })
                    .collect();
                let candidate = candidate.trim_end_matches(|c: char| matches!(c, '.' | '_' | '-'));
                if !candidate.is_empty()
                    && candidate.len() <= 64
                    && !hints.iter().any(|h| h == candidate)
                {
                    hints.push(candidate.to_string());
                }
            }
            search_from += rel + kw.len();
            if search_from >= lower.len() {
                break;
            }
        }
    }

    hints
}

/// Extract potential password hints embedded in a filename (e.g. `资源_密码123456.zip`, `test[解压码abc].7z`).
pub fn extract_password_hints_from_filename(path: &Path) -> Vec<String> {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    extract_password_hints_from_text(stem)
}

/// Scan small sibling `.txt`/`.nfo`/`.md` files in the archive's directory for password hints
/// (e.g., `密码.txt`, `解压密码.txt`, `说明.txt`, or `<archive_stem>.txt`).
pub fn extract_password_hints_from_sibling_txt(archive_path: &Path) -> Vec<String> {
    let Some(parent) = archive_path.parent() else {
        return Vec::new();
    };
    let stem_low = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut hints = Vec::new();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return hints;
    };

    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() || p == archive_path {
            continue;
        }
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(ext.as_str(), "txt" | "nfo" | "md") {
            continue;
        }
        let Ok(meta) = p.metadata() else {
            continue;
        };
        if meta.len() == 0 || meta.len() > 32 * 1024 {
            continue;
        }
        let name_low = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let is_pw_note = name_low.contains("密码")
            || name_low.contains("解压")
            || name_low.contains("说明")
            || name_low.contains("readme")
            || name_low.contains("pass")
            || name_low.contains("pwd")
            || (!stem_low.is_empty() && name_low.starts_with(&stem_low));
        if !is_pw_note {
            continue;
        }

        if let Ok(bytes) = std::fs::read(&p) {
            let text = crate::config::decode_text_bytes(&bytes);
            for h in extract_password_hints_from_text(&text) {
                if !hints.contains(&h) {
                    hints.push(h);
                }
            }
            // If the file is literally a tiny 1-line password file (e.g. `密码.txt` containing just `abc123`)
            let trimmed = text.trim();
            if !trimmed.is_empty()
                && !trimmed.contains('\n')
                && !trimmed.contains(' ')
                && trimmed.len() <= 48
                && (name_low.contains("密码") || name_low.contains("pass") || name_low.contains("pwd"))
                && !hints.iter().any(|h| h == trimmed)
            {
                hints.push(trimmed.to_string());
            }
        }
    }

    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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

    #[test]
    fn test_split_volume_detection() {
        assert!(is_non_first_split_volume(Path::new("movie.7z.002")));
        assert!(is_non_first_split_volume(Path::new("movie.010")));
        assert!(is_non_first_split_volume(Path::new("game.part2.rar")));
        assert!(is_non_first_split_volume(Path::new("game.part02.rar")));
        assert!(is_non_first_split_volume(Path::new("archive.z01")));
        assert!(is_non_first_split_volume(Path::new("archive.r00")));
        assert!(is_non_first_split_volume(Path::new("movie.7z.002.mp4")));
        assert!(is_non_first_split_volume(Path::new("movie.7z.002删")));
        assert!(is_non_first_split_volume(Path::new("game.part02.rar1")));

        assert!(!is_non_first_split_volume(Path::new("movie.7z.001")));
        assert!(!is_non_first_split_volume(Path::new("movie.7z.001.mp4")));
        assert!(!is_non_first_split_volume(Path::new("game.part01.rar删")));
        assert!(!is_non_first_split_volume(Path::new("game.part1.rar")));
        assert!(!is_non_first_split_volume(Path::new("game.part01.rar")));
        assert!(!is_non_first_split_volume(Path::new("archive.zip")));

        let info = parse_disguised_split_filename("movie.7z.001.mp4").unwrap();
        assert_eq!(info.clean_filename(), "movie.7z.001");
        assert_eq!(info.part_num, 1);
        let info2 = parse_disguised_split_filename("game.part01.rar删").unwrap();
        assert_eq!(info2.clean_filename(), "game.part01.rar");
        assert_eq!(info2.part_num, 1);
    }

    #[test]
    fn test_protected_components_never_treated_as_disguised() {
        let dir = std::env::temp_dir().join("oh_unzip_component_guard_tests");
        let _ = std::fs::create_dir_all(&dir);

        // Eclipse P2 artifacts.jar (no META-INF/MANIFEST.MF!) must NOT be unpacked
        let jar = dir.join("artifacts.jar");
        std::fs::write(&jar, make_minimal_zip(b"artifacts.xml")).unwrap();
        assert!(detect_file(&jar, DetectOptions::default()).is_none());

        // Python wheel (.whl) must NOT be unpacked
        let whl = dir.join("pkg-1.0-py3-none-any.whl");
        std::fs::write(&whl, make_minimal_zip(b"pkg/__init__.py")).unwrap();
        assert!(detect_file(&whl, DetectOptions::default()).is_none());

        // MSVC static library (.lib with ar magic `!<arch>\n`) must NOT be treated as DEB
        let lib = dir.join("foo.lib");
        let mut ar_bytes = b"!<arch>\n".to_vec();
        ar_bytes.extend_from_slice(&[0u8; 64]);
        std::fs::write(&lib, &ar_bytes).unwrap();
        assert!(detect_file(&lib, DetectOptions::default()).is_none());

        // Real .deb STILL works when explicitly named .deb
        let deb = dir.join("pkg.deb");
        std::fs::write(&deb, &ar_bytes).unwrap();
        let det_deb = detect_file(&deb, DetectOptions::default()).unwrap();
        assert_eq!(det_deb.format, ArchiveFormat::Deb);
        assert_eq!(det_deb.trick, TrickKind::Normal);

        // Real .zip containing AndroidManifest.xml STILL extracts normally
        let normal_zip = dir.join("android_src.zip");
        std::fs::write(&normal_zip, make_minimal_zip(b"AndroidManifest.xml")).unwrap();
        let det_norm = detect_file(&normal_zip, DetectOptions::default()).unwrap();
        assert_eq!(det_norm.format, ArchiveFormat::Zip);
        assert_eq!(det_norm.trick, TrickKind::Normal);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_filename_password_hints() {
        let hints = extract_password_hints_from_filename(Path::new("资料_解压密码：ohunzip2026.7z"));
        assert!(hints.contains(&"ohunzip2026".to_string()));

        let hints2 = extract_password_hints_from_filename(Path::new("pack[pw=abc123].zip"));
        assert!(hints2.contains(&"abc123".to_string()));
    }

    #[test]
    fn test_normal_disguised_and_polyglot_detection() {
        let dir = std::env::temp_dir().join("oh_unzip_detector_tests_v3");
        let _ = std::fs::create_dir_all(&dir);

        // Disguised .docx (top-level only, non-Office zip) MUST be detected
        let fake_docx = dir.join("secret.docx");
        std::fs::write(&fake_docx, make_minimal_zip(b"hello.txt")).unwrap();
        let det_fake = detect_file(&fake_docx, DetectOptions::default()).unwrap();
        assert_eq!(det_fake.format, ArchiveFormat::Zip);
        assert!(matches!(
            det_fake.trick,
            TrickKind::DisguisedExtension { ref original_ext } if original_ext == "docx"
        ));

        // Disguised 7z named `.mp4`
        let fake_mp4 = dir.join("disguised.mp4");
        {
            let mut hdr = [0u8; 32];
            hdr[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
            hdr[6] = 0;
            hdr[7] = 4;
            let crc = crc32fast::hash(&hdr[12..32]);
            hdr[8..12].copy_from_slice(&crc.to_le_bytes());
            let mut f = File::create(&fake_mp4).unwrap();
            f.write_all(&hdr).unwrap();
        }
        let det = detect_file(&fake_mp4, DetectOptions::default()).unwrap();
        assert_eq!(det.format, ArchiveFormat::SevenZ);
        assert_eq!(det.offset, 0);
        assert!(matches!(
            det.trick,
            TrickKind::DisguisedExtension { ref original_ext } if original_ext == "mp4"
        ));

        // Polyglot JPEG + minimal valid ZIP
        let poly_jpg = dir.join("tuzhong.jpg");
        {
            let jpeg_prefix = [
                0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9,
            ];
            let mut f = File::create(&poly_jpg).unwrap();
            f.write_all(&jpeg_prefix).unwrap();
            f.write_all(&make_minimal_zip(b"a.txt")).unwrap();
        }
        let det2 = detect_file(&poly_jpg, DetectOptions::default()).unwrap();
        assert_eq!(det2.format, ArchiveFormat::Zip);
        assert_eq!(det2.offset, 12);
        assert!(matches!(det2.trick, TrickKind::Polyglot { offset: 12, .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
