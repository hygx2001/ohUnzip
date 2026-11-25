use crate::config::{AppConfig, OutputMode};
use crate::detector::{
    self, ArchiveFormat, DetectOptions, DetectedArchive, DisguisedSplitInfo, TrickKind,
    extract_password_hints_from_filename,
};
use crate::seven_zip::new_hidden_command;
use crate::trash;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub enum ExtractEvent {
    Log(String),
    Stage(String),
    Progress(u8),
    Format(ArchiveFormat),
    Badge(String),
    NestingDepth(usize),
    PasswordMatched(String),
    NeedPassword {
        archive_path: PathBuf,
        message: String,
    },
    Completed {
        output_dir: PathBuf,
        extracted_files: usize,
        max_depth_reached: usize,
    },
    Cancelled,
    Failed(String),
}

struct TempFileGuard(PathBuf);
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ExtractionContext {
    seven_zip: PathBuf,
    config: AppConfig,
    manual_password: Option<String>,
    codepage: Option<u32>,
    cancel_flag: Arc<AtomicBool>,
    tx: Sender<ExtractEvent>,
    total_extracted_bytes: u64,
    max_depth_reached: usize,
    matched_passwords: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum OutputTarget {
    ConfigDefault,
    SameDir,
    SpecificDir(PathBuf),
}

#[allow(clippy::too_many_arguments)]
pub fn run_extraction_job(
    source_path: PathBuf,
    seven_zip: PathBuf,
    config: AppConfig,
    manual_password: Option<String>,
    output_target: OutputTarget,
    codepage: Option<u32>,
    cancel_flag: Arc<AtomicBool>,
    tx: Sender<ExtractEvent>,
) {
    let mut ctx = ExtractionContext {
        seven_zip,
        config,
        manual_password,
        codepage,
        cancel_flag,
        tx,
        total_extracted_bytes: 0,
        max_depth_reached: 0,
        matched_passwords: Vec::new(),
    };

    if ctx.is_cancelled() {
        let _ = ctx.tx.send(ExtractEvent::Cancelled);
        return;
    }

    if !source_path.exists() {
        let _ = ctx.tx.send(ExtractEvent::Failed("文件不存在或已被移除".into()));
        return;
    }

    let detect_opts = DetectOptions {
        detect_disguised: ctx.config.detect_disguised,
        detect_polyglot: ctx.config.detect_polyglot,
        skip_office_zip: ctx.config.skip_office_zip,
    };

    let _ = ctx.tx.send(ExtractEvent::Stage("正在分析文件特征...".into()));
    let detected = match detector::detect_file(&source_path, detect_opts) {
        Some(d) => d,
        None => match ctx.probe_unknown_with_7z(&source_path) {
            Some(d) => d,
            None => {
                let _ = ctx.tx.send(ExtractEvent::Failed(
                    "未检测到压缩包特征（非压缩包，或已跳过组件/文档）".into(),
                ));
                return;
            }
        },
    };

    let _ = ctx.tx.send(ExtractEvent::Format(detected.format));
    if let Some(cp) = ctx.codepage {
        ctx.log(format!("使用指定编码重解: codepage {cp}"));
    }

    let base_output_parent = match output_target {
        OutputTarget::SameDir => source_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        OutputTarget::SpecificDir(dir) => dir,
        OutputTarget::ConfigDefault => match ctx.config.output_mode {
            OutputMode::CustomDir if !ctx.config.custom_output_dir.trim().is_empty() => {
                PathBuf::from(ctx.config.custom_output_dir.trim())
            }
            _ => source_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        },
    };

    let desired_name = clean_archive_stem(&source_path);
    let final_output_dir = unique_dir_path(&base_output_parent, &desired_name);

    match ctx.extract_recursive(&source_path, &detected, &final_output_dir, 0) {
        Ok(()) => {
            if ctx.config.move_source_to_trash && detected.offset == 0 {
                let to_trash = collect_source_files_to_trash(&source_path, &detected);
                let mut trashed = 0usize;
                for p in &to_trash {
                    if let Err(err) = trash::move_to_trash(p) {
                        ctx.log(format!("移入回收站失败 ({}): {err}", p.display()));
                    } else {
                        trashed += 1;
                    }
                }
                if trashed > 0 {
                    ctx.log(format!("已将原压缩包（共 {trashed} 个文件）移入回收站"));
                }
            }

            let file_count = count_files_recursively(&final_output_dir);
            let _ = ctx.tx.send(ExtractEvent::Progress(100));
            let _ = ctx.tx.send(ExtractEvent::Completed {
                output_dir: final_output_dir,
                extracted_files: file_count,
                max_depth_reached: ctx.max_depth_reached,
            });
        }
        Err(ExtractError::Cancelled) => {
            let _ = ctx.tx.send(ExtractEvent::Cancelled);
        }
        Err(ExtractError::NeedPassword {
            archive_path,
            message,
        }) => {
            let _ = ctx.tx.send(ExtractEvent::NeedPassword {
                archive_path,
                message,
            });
        }
        Err(ExtractError::Fatal(msg)) => {
            let _ = ctx.tx.send(ExtractEvent::Failed(msg));
        }
    }
}

enum ExtractError {
    Cancelled,
    NeedPassword {
        archive_path: PathBuf,
        message: String,
    },
    Fatal(String),
}

impl ExtractionContext {
    fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed)
    }

    fn log(&self, msg: impl Into<String>) {
        let _ = self.tx.send(ExtractEvent::Log(msg.into()));
    }

    fn stage(&self, msg: impl Into<String>) {
        let _ = self.tx.send(ExtractEvent::Stage(msg.into()));
    }

    fn extract_recursive(
        &mut self,
        archive_path: &Path,
        detected: &DetectedArchive,
        target_dir: &Path,
        depth: usize,
    ) -> Result<(), ExtractError> {
        if self.is_cancelled() {
            return Err(ExtractError::Cancelled);
        }

        if depth > self.max_depth_reached {
            self.max_depth_reached = depth;
            let _ = self.tx.send(ExtractEvent::NestingDepth(depth));
        }

        let name = archive_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archive");

        if let Some(badge) = detected.trick.badge_text(detected.format) {
            let _ = self.tx.send(ExtractEvent::Badge(badge.clone()));
            self.log(format!("[第{}层] 识别到 {} — {}", depth + 1, name, badge));
        } else {
            self.log(format!(
                "[第{}层] 识别到 {} ({})",
                depth + 1,
                name,
                detected.format.display_name()
            ));
        }

        // Prepare source file for 7z:
        // - Polyglot (offset > 0): carve payload to temp file
        // - Disguised split volumes (e.g. `movie.7z.001.mp4` + `.002.mp4`): hard-link clean names into temp dir
        let mut _carved_guard: Option<TempFileGuard> = None;
        let mut _split_guard: Option<TempDirGuard> = None;

        let (actual_archive, force_type) = if detected.offset > 0 {
            self.stage(format!(
                "正在提取隐写载荷 ({} @ {})...",
                detected.format.display_name(),
                detector::format_bytes(detected.offset)
            ));
            let carved = carve_payload_to_temp(archive_path, detected.offset, detected.format)
                .map_err(ExtractError::Fatal)?;
            self.log(format!(
                "[第{}层] 已剥离隐写尾部载荷 → 临时文件 ({})",
                depth + 1,
                detected.format.canonical_ext()
            ));
            let path = carved.0.clone();
            _carved_guard = Some(carved);
            (path, detected.format.seven_zip_type())
        } else if let Some(ref split_info) = detected.disguised_split {
            let (guard, first_clean, linked_count) =
                stage_disguised_split_volumes(archive_path, split_info)
                    .map_err(ExtractError::Fatal)?;
            self.log(format!(
                "[第{}层] 已硬链接还原 {} 个改后缀分卷 → {}",
                depth + 1,
                linked_count,
                split_info.clean_filename()
            ));
            _split_guard = Some(guard);
            (first_clean, None)
        } else {
            let ftype = match detected.trick {
                TrickKind::DisguisedExtension { .. } if !detected.is_split => {
                    detected.format.seven_zip_type()
                }
                _ => None,
            };
            (archive_path.to_path_buf(), ftype)
        };

        let candidates = self.build_password_candidates(archive_path);
        let staging_dir = make_staging_dir(target_dir).map_err(ExtractError::Fatal)?;
        let extract_result = self.extract_with_passwords(
            &actual_archive,
            archive_path,
            force_type,
            &staging_dir,
            &candidates,
            depth,
        );

        match extract_result {
            Ok(used_password) => {
                if !used_password.is_empty() {
                    if !self.matched_passwords.contains(&used_password) {
                        self.matched_passwords.push(used_password.clone());
                    }
                    let _ = self
                        .tx
                        .send(ExtractEvent::PasswordMatched(used_password.clone()));
                    self.log(format!("[第{}层] 密码命中: {}", depth + 1, used_password));
                }

                let layer_bytes = dir_size_bytes(&staging_dir);
                self.total_extracted_bytes = self.total_extracted_bytes.saturating_add(layer_bytes);
                let max_bytes = self.config.max_total_extract_mb.saturating_mul(1024 * 1024);
                if max_bytes > 0 && self.total_extracted_bytes > max_bytes {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(ExtractError::Fatal(format!(
                        "触发防压缩炸弹保护：累计解压体积已超过 {} MB",
                        self.config.max_total_extract_mb
                    )));
                }

                finalize_staging_dir(&staging_dir, target_dir).map_err(ExtractError::Fatal)?;
                self.log(format!(
                    "[第{}层] 解压完成 → {}",
                    depth + 1,
                    target_dir.display()
                ));
            }
            Err(err) => {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(err);
            }
        }

        drop(_carved_guard);
        drop(_split_guard);

        if self.is_cancelled() {
            return Err(ExtractError::Cancelled);
        }

        if depth + 1 < self.config.max_depth {
            self.scan_and_extract_nested(target_dir, depth + 1)?;
        } else {
            self.log(format!(
                "已达到最大嵌套深度 ({} 层)，停止继续递归",
                self.config.max_depth
            ));
        }

        Ok(())
    }

    fn scan_and_extract_nested(&mut self, dir: &Path, next_depth: usize) -> Result<(), ExtractError> {
        if self.is_cancelled() {
            return Err(ExtractError::Cancelled);
        }

        let detect_opts = DetectOptions {
            detect_disguised: self.config.detect_disguised,
            detect_polyglot: self.config.detect_polyglot,
            skip_office_zip: self.config.skip_office_zip,
        };

        let all_files = collect_files_recursively(dir);
        if all_files.is_empty() {
            return Ok(());
        }

        const MAX_FILES_FOR_NESTED_SCAN: usize = 64;
        if all_files.len() > MAX_FILES_FOR_NESTED_SCAN {
            self.log(format!(
                "[第{}层] 已解出完整文件目录（共 {} 个文件，非套娃壳），停止继续递归",
                next_depth,
                all_files.len()
            ));
            return Ok(());
        }

        let mut nested_archives: Vec<(PathBuf, DetectedArchive)> = Vec::new();
        let mut real_payload_files = 0usize;

        for file_path in &all_files {
            if !file_path.exists() {
                continue;
            }
            if detector::is_non_first_split_volume(file_path) {
                continue;
            }

            if let Some(det) = detector::detect_file_with_context(file_path, detect_opts, true) {
                nested_archives.push((file_path.clone(), det));
            } else if !is_sidecar_note_file(file_path) {
                real_payload_files += 1;
            }
        }

        if nested_archives.is_empty() {
            return Ok(());
        }

        let archives_to_extract: Vec<(PathBuf, DetectedArchive)> = if real_payload_files <= 2 {
            nested_archives
        } else {
            let tricky_only: Vec<_> = nested_archives
                .into_iter()
                .filter(|(_, d)| d.trick.is_tricky())
                .collect();
            if tricky_only.is_empty() {
                self.log(format!(
                    "[第{}层] 目录包含 {} 个常规文件（非套娃压缩包），保留内部子压缩包不自动拆解",
                    next_depth, real_payload_files
                ));
                return Ok(());
            }
            tricky_only
        };

        for (file_path, nested_det) in archives_to_extract {
            if self.is_cancelled() {
                return Err(ExtractError::Cancelled);
            }
            if !file_path.exists() {
                continue;
            }

            let parent = file_path.parent().unwrap_or(dir);
            let sub_name = clean_archive_stem(&file_path);
            let nested_target = unique_dir_path(parent, &sub_name);

            self.extract_recursive(&file_path, &nested_det, &nested_target, next_depth)?;

            if self.config.clean_intermediate && nested_det.offset == 0 {
                if nested_det.is_split {
                    for p in collect_source_files_to_trash(&file_path, &nested_det) {
                        let _ = fs::remove_file(p);
                    }
                } else {
                    let _ = fs::remove_file(&file_path);
                }
                self.log(format!(
                    "[第{}层] 已清理中间嵌套压缩包: {}",
                    next_depth + 1,
                    file_path.file_name().and_then(|n| n.to_str()).unwrap_or("")
                ));
            }
        }

        Ok(())
    }

    fn build_password_candidates(&self, archive_path: &Path) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();

        let mut push_unique = |s: String| {
            if seen.insert(s.clone()) {
                out.push(s);
            }
        };

        if let Some(ref manual) = self.manual_password {
            if !manual.is_empty() {
                push_unique(manual.clone());
            }
        }

        push_unique(String::new());

        for p in &self.matched_passwords {
            push_unique(p.clone());
        }

        if self.config.extract_filename_password_hint {
            for hint in extract_password_hints_from_filename(archive_path) {
                push_unique(hint);
            }
            for hint in detector::extract_password_hints_from_sibling_txt(archive_path) {
                push_unique(hint);
            }
        }

        for entry in &self.config.passwords {
            push_unique(entry.value.clone());
        }

        out
    }

    fn extract_with_passwords(
        &self,
        actual_archive: &Path,
        original_archive: &Path,
        force_type: Option<&str>,
        staging_dir: &Path,
        base_candidates: &[String],
        depth: usize,
    ) -> Result<String, ExtractError> {
        if self.is_cancelled() {
            return Err(ExtractError::Cancelled);
        }

        let (probe, comment_hints) = self.probe_archive_encryption(actual_archive, force_type);

        // Merge any password hints discovered inside the archive's Comment field right near the front!
        let mut candidates: Vec<String> = Vec::with_capacity(base_candidates.len() + comment_hints.len());
        if !comment_hints.is_empty() && self.config.extract_filename_password_hint {
            self.log(format!(
                "[第{}层] 从压缩包注释提取到 {} 个候选密码",
                depth + 1,
                comment_hints.len()
            ));
            for h in &comment_hints {
                if !candidates.contains(h) {
                    candidates.push(h.clone());
                }
            }
        }
        for c in base_candidates {
            if !candidates.contains(c) {
                candidates.push(c.clone());
            }
        }
        let candidates = &candidates[..];

        match probe {
            EncryptionProbe::Unencrypted => {
                self.stage(format!("[第{}层] 正在解压...", depth + 1));
                match self.run_7z_extract(actual_archive, force_type, staging_dir, "") {
                    Ok(()) => return Ok(String::new()),
                    Err(SevenZRunError::Cancelled) => return Err(ExtractError::Cancelled),
                    Err(_) => {
                        clear_dir_contents(staging_dir);
                    }
                }
            }
            EncryptionProbe::HeaderEncrypted => {
                self.log(format!(
                    "[第{}层] 检测到加密文件头，开始快速匹配 {} 个候选密码...",
                    depth + 1,
                    candidates.len()
                ));
                for (idx, pw) in candidates.iter().enumerate() {
                    if self.is_cancelled() {
                        return Err(ExtractError::Cancelled);
                    }
                    if pw.is_empty() {
                        continue;
                    }
                    self.stage(format!(
                        "[第{}层] 尝试密码 ({}/{})...",
                        depth + 1,
                        idx + 1,
                        candidates.len()
                    ));
                    if self.test_7z_list_password(actual_archive, force_type, pw) {
                        self.stage(format!("[第{}层] 密码匹配，正在解压...", depth + 1));
                        match self.run_7z_extract(actual_archive, force_type, staging_dir, pw) {
                            Ok(()) => return Ok(pw.clone()),
                            Err(SevenZRunError::Cancelled) => return Err(ExtractError::Cancelled),
                            Err(_) => clear_dir_contents(staging_dir),
                        }
                    }
                }
                return Err(ExtractError::NeedPassword {
                    archive_path: original_archive.to_path_buf(),
                    message: format!(
                        "压缩包已加密，已尝试 {} 个密码均不匹配，请输入正确密码重试",
                        candidates.len()
                    ),
                });
            }
            EncryptionProbe::DataEncrypted { smallest_entry } => {
                self.log(format!(
                    "[第{}层] 检测到加密内容，开始匹配 {} 个候选密码...",
                    depth + 1,
                    candidates.len()
                ));
                for (idx, pw) in candidates.iter().enumerate() {
                    if self.is_cancelled() {
                        return Err(ExtractError::Cancelled);
                    }
                    if pw.is_empty() {
                        continue;
                    }
                    self.stage(format!(
                        "[第{}层] 尝试密码 ({}/{})...",
                        depth + 1,
                        idx + 1,
                        candidates.len()
                    ));
                    if let Some(ref entry) = smallest_entry {
                        if !self.test_7z_entry_password(actual_archive, force_type, pw, entry) {
                            continue;
                        }
                    }
                    self.stage(format!("[第{}层] 密码匹配，正在解压...", depth + 1));
                    match self.run_7z_extract(actual_archive, force_type, staging_dir, pw) {
                        Ok(()) => return Ok(pw.clone()),
                        Err(SevenZRunError::Cancelled) => return Err(ExtractError::Cancelled),
                        Err(SevenZRunError::WrongPassword) => {
                            clear_dir_contents(staging_dir);
                            continue;
                        }
                        Err(SevenZRunError::Other(msg)) => {
                            return Err(ExtractError::Fatal(msg));
                        }
                    }
                }
                return Err(ExtractError::NeedPassword {
                    archive_path: original_archive.to_path_buf(),
                    message: format!(
                        "压缩包已加密，已尝试 {} 个密码均不匹配，请输入正确密码重试",
                        candidates.len()
                    ),
                });
            }
            EncryptionProbe::Unknown => {}
        }

        // Fallback: direct extract loop over candidates
        let mut saw_wrong_password = false;
        let mut last_error = String::new();

        for (idx, pw) in candidates.iter().enumerate() {
            if self.is_cancelled() {
                return Err(ExtractError::Cancelled);
            }
            if !pw.is_empty() {
                self.stage(format!(
                    "[第{}层] 尝试密码 ({}/{})...",
                    depth + 1,
                    idx + 1,
                    candidates.len()
                ));
            } else {
                self.stage(format!("[第{}层] 正在解压...", depth + 1));
            }

            match self.run_7z_extract(actual_archive, force_type, staging_dir, pw) {
                Ok(()) => return Ok(pw.clone()),
                Err(SevenZRunError::Cancelled) => return Err(ExtractError::Cancelled),
                Err(SevenZRunError::WrongPassword) => {
                    saw_wrong_password = true;
                    clear_dir_contents(staging_dir);
                }
                Err(SevenZRunError::Other(msg)) => {
                    if force_type.is_some() && idx == 0 {
                        clear_dir_contents(staging_dir);
                        match self.run_7z_extract(actual_archive, None, staging_dir, pw) {
                            Ok(()) => return Ok(pw.clone()),
                            Err(SevenZRunError::Cancelled) => return Err(ExtractError::Cancelled),
                            Err(SevenZRunError::WrongPassword) => {
                                saw_wrong_password = true;
                                clear_dir_contents(staging_dir);
                                continue;
                            }
                            Err(SevenZRunError::Other(m2)) => {
                                last_error = m2;
                                break;
                            }
                        }
                    }
                    last_error = msg;
                    break;
                }
            }
        }

        if saw_wrong_password {
            Err(ExtractError::NeedPassword {
                archive_path: original_archive.to_path_buf(),
                message: format!("压缩包需要密码，已尝试 {} 个密码均未成功", candidates.len()),
            })
        } else {
            Err(ExtractError::Fatal(if last_error.is_empty() {
                "7z 解压失败".into()
            } else {
                last_error
            }))
        }
    }

    fn probe_unknown_with_7z(&self, path: &Path) -> Option<DetectedArchive> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if self.config.skip_office_zip && detector::is_protected_component_ext(&ext) {
            return None;
        }
        if !self.config.detect_disguised {
            return None;
        }

        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("l")
            .arg("-slt")
            .arg("-y")
            .arg("-sccUTF-8")
            .arg("-p-")
            .arg("--")
            .arg(path);
        let out = cmd.output().ok()?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        if is_wrong_password_output(&combined) {
            return Some(DetectedArchive {
                format: ArchiveFormat::Generic,
                offset: 0,
                trick: TrickKind::DisguisedExtension { original_ext: ext },
                is_split: false,
                disguised_split: None,
            });
        }
        if !out.status.success() {
            return None;
        }
        for line in combined.lines() {
            if let Some(ty) = line.trim().strip_prefix("Type = ") {
                if let Some(fmt) = ArchiveFormat::from_7z_type_name(ty) {
                    if !fmt.allow_disguised_detection()
                        && !fmt.known_extensions().contains(&ext.as_str())
                    {
                        return None;
                    }
                    let trick = if fmt.known_extensions().contains(&ext.as_str()) {
                        TrickKind::Normal
                    } else {
                        TrickKind::DisguisedExtension { original_ext: ext }
                    };
                    return Some(DetectedArchive {
                        format: fmt,
                        offset: 0,
                        trick,
                        is_split: false,
                        disguised_split: None,
                    });
                }
            }
        }
        None
    }

    fn probe_archive_encryption(
        &self,
        archive: &Path,
        force_type: Option<&str>,
    ) -> (EncryptionProbe, Vec<String>) {
        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("l")
            .arg("-slt")
            .arg("-y")
            .arg("-sccUTF-8")
            .arg("-p-");
        if let Some(t) = force_type {
            cmd.arg(format!("-t{t}"));
        }
        cmd.arg("--").arg(archive);

        let Ok(out) = cmd.output() else {
            return (EncryptionProbe::Unknown, Vec::new());
        };
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        let comment_hints = extract_comment_hints_from_slt(&combined);

        if is_wrong_password_output(&combined) {
            return (EncryptionProbe::HeaderEncrypted, comment_hints);
        }

        if !out.status.success() {
            return (EncryptionProbe::Unknown, comment_hints);
        }

        let mut any_encrypted = false;
        let mut smallest: Option<(u64, String)> = None;

        let mut cur_path: Option<String> = None;
        let mut cur_size: Option<u64> = None;
        let mut cur_encrypted = false;
        let mut cur_folder = false;

        let flush_block = |cur_path: &mut Option<String>,
                           cur_size: &mut Option<u64>,
                           cur_encrypted: &mut bool,
                           cur_folder: &mut bool,
                           any_encrypted: &mut bool,
                           smallest: &mut Option<(u64, String)>| {
            if *cur_encrypted && !*cur_folder {
                *any_encrypted = true;
                if let Some(p) = cur_path.take() {
                    let sz = cur_size.unwrap_or(u64::MAX);
                    if smallest.as_ref().is_none_or(|(best, _)| sz < *best) {
                        *smallest = Some((sz, p));
                    }
                }
            }
            *cur_path = None;
            *cur_size = None;
            *cur_encrypted = false;
            *cur_folder = false;
        };

        let mut in_entries = false;
        for line in combined.lines() {
            let line = line.trim();
            if line == "----------" {
                in_entries = true;
                continue;
            }
            if !in_entries {
                continue;
            }
            if line.is_empty() {
                flush_block(
                    &mut cur_path,
                    &mut cur_size,
                    &mut cur_encrypted,
                    &mut cur_folder,
                    &mut any_encrypted,
                    &mut smallest,
                );
                continue;
            }
            if let Some(val) = line.strip_prefix("Path = ") {
                cur_path = Some(val.to_string());
            } else if let Some(val) = line.strip_prefix("Size = ") {
                cur_size = val.parse::<u64>().ok();
            } else if line == "Encrypted = +" {
                cur_encrypted = true;
            } else if line == "Folder = +" {
                cur_folder = true;
            }
        }
        flush_block(
            &mut cur_path,
            &mut cur_size,
            &mut cur_encrypted,
            &mut cur_folder,
            &mut any_encrypted,
            &mut smallest,
        );

        if any_encrypted {
            (
                EncryptionProbe::DataEncrypted {
                    smallest_entry: smallest.map(|(_, p)| p),
                },
                comment_hints,
            )
        } else {
            (EncryptionProbe::Unencrypted, comment_hints)
        }
    }

    fn test_7z_list_password(&self, archive: &Path, force_type: Option<&str>, pw: &str) -> bool {
        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("l").arg("-y").arg("-sccUTF-8");
        add_password_arg(&mut cmd, pw);
        if let Some(t) = force_type {
            cmd.arg(format!("-t{t}"));
        }
        cmd.arg("--").arg(archive);
        cmd.output().is_ok_and(|o| o.status.success())
    }

    fn test_7z_entry_password(
        &self,
        archive: &Path,
        force_type: Option<&str>,
        pw: &str,
        entry: &str,
    ) -> bool {
        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("t").arg("-y").arg("-sccUTF-8");
        add_password_arg(&mut cmd, pw);
        if let Some(t) = force_type {
            cmd.arg(format!("-t{t}"));
        }
        cmd.arg("--").arg(archive).arg(entry);
        cmd.output().is_ok_and(|o| o.status.success())
    }

    /// Streams `7z x -bsp1` so we report real-time progress percentages and support instant cancellation.
    fn run_7z_extract(
        &self,
        archive: &Path,
        force_type: Option<&str>,
        out_dir: &Path,
        pw: &str,
    ) -> Result<(), SevenZRunError> {
        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("x")
            .arg("-y")
            .arg("-aou")
            .arg("-sccUTF-8")
            .arg("-bsp1");
        add_password_arg(&mut cmd, pw);
        if let Some(cp) = self.codepage {
            cmd.arg(format!("-mcp={cp}"));
        }
        cmd.arg(format!("-o{}", out_dir.display()));
        if let Some(t) = force_type {
            cmd.arg(format!("-t{t}"));
        }
        cmd.arg("--").arg(archive);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| SevenZRunError::Other(format!("无法启动 7z 进程: {e}")))?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
        let out_handle = std::thread::spawn(move || {
            let mut full = Vec::new();
            if let Some(mut reader) = stdout {
                let mut buf = [0u8; 512];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let chunk = buf[..n].to_vec();
                    full.extend_from_slice(&chunk);
                    let _ = out_tx.send(chunk);
                }
            }
            full
        });

        let err_handle = std::thread::spawn(move || {
            let mut full = Vec::new();
            if let Some(mut reader) = stderr {
                let _ = reader.read_to_end(&mut full);
            }
            full
        });

        let mut last_pct: Option<u8> = None;
        let mut pending = String::new();

        loop {
            if self.is_cancelled() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SevenZRunError::Cancelled);
            }

            match out_rx.recv_timeout(Duration::from_millis(75)) {
                Ok(chunk) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk));
                    if let Some(pct) = parse_latest_progress_percent(&pending) {
                        if last_pct != Some(pct) {
                            last_pct = Some(pct);
                            let _ = self.tx.send(ExtractEvent::Progress(pct));
                        }
                    }
                    // Keep only the trailing tail of `pending` to avoid unbounded growth
                    if pending.len() > 256 {
                        let keep_from = pending.len() - 64;
                        let safe_from = pending.ceil_char_boundary(keep_from);
                        pending.drain(..safe_from);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        let status = child
            .wait()
            .map_err(|e| SevenZRunError::Other(format!("等待 7z 进程失败: {e}")))?;

        let stdout_bytes = out_handle.join().unwrap_or_default();
        let stderr_bytes = err_handle.join().unwrap_or_default();

        if self.is_cancelled() {
            return Err(SevenZRunError::Cancelled);
        }

        if status.success() {
            return Ok(());
        }

        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&stdout_bytes),
            String::from_utf8_lossy(&stderr_bytes)
        );

        if is_wrong_password_output(&combined) {
            return Err(SevenZRunError::WrongPassword);
        }

        let err_line = combined
            .lines()
            .map(str::trim)
            .filter(|l| {
                let low = l.to_ascii_lowercase();
                low.contains("error")
                    || low.contains("cannot open")
                    || low.contains("can not open")
                    || low.contains("unsupported")
            })
            .last()
            .or_else(|| combined.lines().map(str::trim).filter(|l| !l.is_empty()).last())
            .unwrap_or("7z 解压返回错误");

        Err(SevenZRunError::Other(err_line.to_string()))
    }
}

enum EncryptionProbe {
    Unencrypted,
    HeaderEncrypted,
    DataEncrypted { smallest_entry: Option<String> },
    Unknown,
}

enum SevenZRunError {
    Cancelled,
    WrongPassword,
    Other(String),
}

fn extract_comment_hints_from_slt(slt_output: &str) -> Vec<String> {
    let mut comment_buf = String::new();
    let mut in_comment = false;
    for line in slt_output.lines() {
        if line.trim() == "----------" {
            break;
        }
        if let Some(rest) = line.strip_prefix("Comment = ") {
            in_comment = true;
            comment_buf.push_str(rest);
            comment_buf.push('\n');
        } else if in_comment {
            if line.contains(" = ") {
                in_comment = false;
            } else {
                comment_buf.push_str(line);
                comment_buf.push('\n');
            }
        }
    }
    if comment_buf.trim().is_empty() {
        Vec::new()
    } else {
        detector::extract_password_hints_from_text(&comment_buf)
    }
}

fn add_password_arg(cmd: &mut std::process::Command, pw: &str) {
    if pw.is_empty() {
        cmd.arg("-p-");
    } else {
        cmd.arg(format!("-p{pw}"));
    }
}

fn parse_latest_progress_percent(text: &str) -> Option<u8> {
    let bytes = text.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] == b'%' {
            let mut start = i;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            if start < i {
                if let Ok(val) = text[start..i].parse::<u16>() {
                    if val <= 100 {
                        return Some(val as u8);
                    }
                }
            }
        }
    }
    None
}

fn is_wrong_password_output(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("wrong password")
        || lower.contains("can not open encrypted archive")
        || lower.contains("cannot open encrypted archive")
        || lower.contains("data error in encrypted file")
        || lower.contains("crc failed in encrypted file")
        || lower.contains("headers error") && lower.contains("encrypted")
}

/// Hard-links all sibling disguised split volumes (e.g. `movie.7z.001.mp4`, `.002.mp4`...)
/// into a hidden temp directory in the same parent folder with restored clean names
/// (`movie.7z.001`, `movie.7z.002`...) at zero extra disk space.
fn stage_disguised_split_volumes(
    first_vol: &Path,
    info: &DisguisedSplitInfo,
) -> Result<(TempDirGuard, PathBuf, usize), String> {
    let parent = first_vol.parent().unwrap_or_else(|| Path::new("."));
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stage_dir = parent.join(format!(".ohunzip_split_{ts}"));
    fs::create_dir_all(&stage_dir).map_err(|e| format!("无法创建分卷还原临时目录: {e}"))?;

    let siblings = find_disguised_split_siblings(first_vol, info);
    let mut linked = 0usize;
    let first_clean_path = stage_dir.join(info.clean_filename());

    for (src_path, clean_name) in siblings {
        let dst = stage_dir.join(&clean_name);
        if fs::hard_link(&src_path, &dst).is_err() {
            fs::copy(&src_path, &dst).map_err(|e| format!("无法准备分卷文件 {clean_name}: {e}"))?;
        }
        linked += 1;
    }

    if !first_clean_path.exists() {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err("未能还原首卷分卷文件".into());
    }

    Ok((TempDirGuard(stage_dir), first_clean_path, linked))
}

fn find_disguised_split_siblings(
    first_vol: &Path,
    info: &DisguisedSplitInfo,
) -> Vec<(PathBuf, String)> {
    let Some(parent) = first_vol.parent() else {
        return vec![(first_vol.to_path_buf(), info.clean_filename())];
    };
    let prefix_low = info.prefix.to_ascii_lowercase();
    let mid_low = info.mid_suffix.to_ascii_lowercase();
    let tail_low = info.disguise_tail.to_ascii_lowercase();

    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if let Some(cand) = detector::parse_disguised_split_filename(name) {
                    if cand.prefix.to_ascii_lowercase() == prefix_low
                        && cand.mid_suffix.to_ascii_lowercase() == mid_low
                        && cand.disguise_tail.to_ascii_lowercase() == tail_low
                    {
                        out.push((p, cand.clean_filename()));
                    }
                }
            }
        }
    }
    if out.is_empty() {
        out.push((first_vol.to_path_buf(), info.clean_filename()));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

fn carve_payload_to_temp(
    src: &Path,
    offset: u64,
    fmt: ArchiveFormat,
) -> Result<TempFileGuard, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_path = std::env::temp_dir().join(format!(
        "ohunzip_carve_{}_{}.{}",
        std::process::id(),
        ts,
        fmt.canonical_ext()
    ));

    let mut reader = File::open(src).map_err(|e| format!("无法读取源文件: {e}"))?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("无法定位隐写偏移: {e}"))?;
    let mut writer =
        File::create(&temp_path).map_err(|e| format!("无法创建临时载荷文件: {e}"))?;

    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("读取源文件失败: {e}"))?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .map_err(|e| format!("写入临时载荷文件失败: {e}"))?;
    }
    writer
        .flush()
        .map_err(|e| format!("刷新临时文件失败: {e}"))?;

    Ok(TempFileGuard(temp_path))
}

/// Produce a clean folder stem name from an archive filename (stripping `.tar.gz`, `.part1.rar`, `.7z.001`, disguised splits, etc.).
pub fn clean_archive_stem(path: &Path) -> String {
    let raw_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("extracted");

    // If it's a disguised split like `movie.7z.001.mp4`, strip the disguise first
    let normalized = detector::parse_disguised_split_filename(raw_name)
        .map(|info| info.clean_filename())
        .unwrap_or_else(|| raw_name.to_string());

    let name = normalized.as_str();
    let lower = name.to_ascii_lowercase();

    for compound in [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".7z.001", ".zip.001", ".rar.001",
    ] {
        if lower.ends_with(compound) {
            let stem = &name[..name.len() - compound.len()];
            if !stem.is_empty() {
                return sanitize_folder_name(stem);
            }
        }
    }

    if let Some(before_rar) = lower.strip_suffix(".rar") {
        if let Some(pos) = before_rar.rfind(".part") {
            let digits = &before_rar[pos + 5..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                let stem = &name[..pos];
                if !stem.is_empty() {
                    return sanitize_folder_name(stem);
                }
            }
        }
    }

    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    sanitize_folder_name(stem)
}

fn sanitize_folder_name(name: &str) -> String {
    let cleaned = name.trim().trim_end_matches('.');
    if cleaned.is_empty() {
        "extracted".to_string()
    } else {
        cleaned.to_string()
    }
}

fn unique_dir_path(parent: &Path, desired: &str) -> PathBuf {
    let first = parent.join(desired);
    if !first.exists() {
        return first;
    }
    for i in 1..1000 {
        let candidate = parent.join(format!("{desired}_{i}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    parent.join(format!("{desired}_out"))
}

fn make_staging_dir(target_dir: &Path) -> Result<PathBuf, String> {
    let parent = target_dir.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("无法创建输出目录: {e}"))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging = parent.join(format!(".ohunzip_tmp_{ts}"));
    fs::create_dir_all(&staging).map_err(|e| format!("无法创建临时解压目录: {e}"))?;
    Ok(staging)
}

fn finalize_staging_dir(staging_dir: &Path, target_dir: &Path) -> Result<(), String> {
    let entries: Vec<_> = fs::read_dir(staging_dir)
        .map_err(|e| format!("读取解压目录失败: {e}"))?
        .filter_map(Result::ok)
        .collect();

    if entries.len() == 1 && entries[0].path().is_dir() {
        let single_dir = entries[0].path();
        if fs::rename(&single_dir, target_dir).is_ok() {
            let _ = fs::remove_dir_all(staging_dir);
            return Ok(());
        }
    }

    if fs::rename(staging_dir, target_dir).is_err() {
        copy_dir_all(staging_dir, target_dir).map_err(|e| format!("移动解压文件失败: {e}"))?;
        let _ = fs::remove_dir_all(staging_dir);
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

fn clear_dir_contents(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let _ = fs::remove_dir_all(&p);
            } else {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

fn is_sidecar_note_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(u64::MAX);

    match ext.as_str() {
        "txt" | "url" | "lnk" | "nfo" | "md" | "ini" | "diz" => size <= 512 * 1024,
        "html" | "htm" => size <= 128 * 1024,
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" => size <= 4 * 1024 * 1024,
        _ => false,
    }
}

fn collect_files_recursively(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&cur) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

fn count_files_recursively(dir: &Path) -> usize {
    collect_files_recursively(dir).len()
}

fn dir_size_bytes(dir: &Path) -> u64 {
    collect_files_recursively(dir)
        .into_iter()
        .filter_map(|p| fs::metadata(p).ok().map(|m| m.len()))
        .sum()
}

/// Collect the archive file and any sibling split volume files (including disguised split siblings).
fn collect_source_files_to_trash(first_vol: &Path, detected: &DetectedArchive) -> Vec<PathBuf> {
    if let Some(ref info) = detected.disguised_split {
        return find_disguised_split_siblings(first_vol, info)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
    }

    if !detected.is_split {
        return vec![first_vol.to_path_buf()];
    }

    let Some(parent) = first_vol.parent() else {
        return vec![first_vol.to_path_buf()];
    };
    let Some(name) = first_vol.file_name().and_then(|n| n.to_str()) else {
        return vec![first_vol.to_path_buf()];
    };
    let lower = name.to_ascii_lowercase();
    let mut out = Vec::new();

    if let Some(ext) = first_vol.extension().and_then(|e| e.to_str()) {
        if ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
            let prefix = &name[..name.len() - ext.len()];
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(n) = p.file_name().and_then(|x| x.to_str()) {
                        if let Some(rest) = n.strip_prefix(prefix) {
                            if rest.len() >= 3 && rest.bytes().all(|b| b.is_ascii_digit()) {
                                out.push(p);
                            }
                        }
                    }
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }

    if let Some(before_rar) = lower.strip_suffix(".rar") {
        if let Some(pos) = before_rar.rfind(".part") {
            let prefix = &lower[..pos + 5];
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(n) = p.file_name().and_then(|x| x.to_str()) {
                        let nl = n.to_ascii_lowercase();
                        if nl.starts_with(prefix) && nl.ends_with(".rar") {
                            out.push(p);
                        }
                    }
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }

    vec![first_vol.to_path_buf()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_archive_stem() {
        assert_eq!(clean_archive_stem(Path::new("demo.tar.gz")), "demo");
        assert_eq!(clean_archive_stem(Path::new("game.part01.rar")), "game");
        assert_eq!(clean_archive_stem(Path::new("video.7z.001")), "video");
        assert_eq!(clean_archive_stem(Path::new("movie.7z.001.mp4")), "movie");
        assert_eq!(clean_archive_stem(Path::new("pack.part01.rar删")), "pack");
        assert_eq!(clean_archive_stem(Path::new("secret.mp4")), "secret");
    }

    #[test]
    fn test_parse_progress_percent() {
        assert_eq!(parse_latest_progress_percent("  0%"), Some(0));
        assert_eq!(parse_latest_progress_percent(" 12% 3 - file.bin\r 47%"), Some(47));
        assert_eq!(parse_latest_progress_percent("100% Everything is Ok"), Some(100));
        assert_eq!(parse_latest_progress_percent("Scanning..."), None);
    }
}
