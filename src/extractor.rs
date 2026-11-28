use crate::config::{AppConfig, OutputMode};
use crate::detector::{
    self, ArchiveFormat, DetectOptions, DetectedArchive, DisguisedSplitInfo, TrickKind,
    extract_password_hints_from_filename,
};
use crate::lz4::{self, Lz4Error};
use crate::seven_zip::new_hidden_command;
use crate::stego::{StegoError, StegoRestorer};
use crate::trash;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
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
            if ctx.config.move_source_to_trash && !detected.is_stego_carrier() {
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

#[derive(Debug)]
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
        // - Stego/polyglot carrier (single file or split volumes): stream-restore via `StegoRestorer`
        // - Disguised split volumes (e.g. `movie.7z.001.mp4` + `.002.mp4`): hard-link clean names into temp dir
        let mut _carved_guard: Option<TempFileGuard> = None;
        let mut _split_guard: Option<TempDirGuard> = None;

        let (actual_archive, force_type) = if let Some(ref stego) = detected.stego {
            if detected.is_split {
                let (guard, first_clean, restored_count, total_count) = self
                    .stage_stego_split_volumes(
                        archive_path,
                        detected,
                        stego.as_ref(),
                        target_dir,
                        depth,
                    )?;
                self.log(format!(
                    "[第{}层] 已还原 {}/{} 个隐写分卷 ({}) → {}",
                    depth + 1,
                    restored_count,
                    total_count,
                    stego.tool_id(),
                    first_clean
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                ));
                _split_guard = Some(guard);
                (first_clean, None)
            } else {
                let restored = self.restore_stego_to_temp(
                    archive_path,
                    stego.as_ref(),
                    detected.format,
                    target_dir,
                    depth,
                )?;
                self.log(format!(
                    "[第{}层] {}",
                    depth + 1,
                    stego.restored_log(detected.format)
                ));
                let path = restored.0.clone();
                let ftype = resolve_seven_zip_type(&path, detected.format);
                _carved_guard = Some(restored);
                (path, ftype)
            }
        } else if let Some(ref split_info) = detected.disguised_split {
            let (guard, first_clean, total_count, unwrapped_count) =
                self.stage_disguised_split_volumes(archive_path, split_info, depth)?;
            if unwrapped_count > 0 {
                self.log(format!(
                    "[第{}层] 已准备 {} 个分卷（解包 {} 个外层压缩分卷）→ {}",
                    depth + 1,
                    total_count,
                    unwrapped_count,
                    split_info.clean_filename()
                ));
            } else {
                self.log(format!(
                    "[第{}层] 已硬链接还原 {} 个改后缀分卷 → {}",
                    depth + 1,
                    total_count,
                    split_info.clean_filename()
                ));
            }
            _split_guard = Some(guard);
            (first_clean, None)
        } else if detected.is_split {
            // Plain first split volume (e.g. `sample.part1.rar`) whose sibling parts may still be
            // wrapped/disguised (e.g. `sample.part2.rar.bz2` / `.lz4` / `.mp4`)
            let plain_split_info = archive_path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(detector::parse_any_split_filename);
            if let Some(ref info) = plain_split_info {
                if has_wrapped_or_disguised_siblings(archive_path, info) {
                    let (guard, first_clean, total_count, unwrapped_count) =
                        self.stage_disguised_split_volumes(archive_path, info, depth)?;
                    self.log(format!(
                        "[第{}层] 检测到混合外层分卷，已准备 {} 个分卷（解包 {} 个外层）→ {}",
                        depth + 1,
                        total_count,
                        unwrapped_count,
                        info.clean_filename()
                    ));
                    _split_guard = Some(guard);
                    (first_clean, None)
                } else {
                    (archive_path.to_path_buf(), None)
                }
            } else {
                (archive_path.to_path_buf(), None)
            }
        } else {
            let ftype = match detected.trick {
                TrickKind::DisguisedExtension { .. } if !detected.is_split => {
                    resolve_seven_zip_type(archive_path, detected.format)
                }
                _ => None,
            };
            (archive_path.to_path_buf(), ftype)
        };

        let staging_dir = make_staging_dir(target_dir).map_err(ExtractError::Fatal)?;
        let extract_result = if detected.format == ArchiveFormat::Lz4
            && !detected.is_split
            && detected.disguised_split.is_none()
        {
            self.extract_standalone_lz4(&actual_archive, archive_path, &staging_dir, depth)
        } else {
            let candidates = self.build_password_candidates(archive_path);
            self.extract_with_passwords(
                &actual_archive,
                archive_path,
                force_type,
                &staging_dir,
                &candidates,
                depth,
            )
        };

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

            if self.config.clean_intermediate && !nested_det.is_stego_carrier() {
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

        let mut force_type = force_type;
        let (mut probe, mut comment_hints) =
            self.probe_archive_encryption(actual_archive, force_type);
        // Defense in depth: if an explicit `-t<type>` failed to open the archive (e.g. type mismatch),
        // retry letting 7-Zip auto-detect from magic bytes before giving up.
        if force_type.is_some()
            && matches!(probe, EncryptionProbe::Fatal(_) | EncryptionProbe::Unknown)
        {
            let (retry_probe, retry_hints) = self.probe_archive_encryption(actual_archive, None);
            if !matches!(
                retry_probe,
                EncryptionProbe::Fatal(_) | EncryptionProbe::Unknown
            ) {
                force_type = None;
                probe = retry_probe;
                if !retry_hints.is_empty() {
                    comment_hints = retry_hints;
                }
            }
        }

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
                    Err(SevenZRunError::Other(msg)) => {
                        clear_dir_contents(staging_dir);
                        return Err(ExtractError::Fatal(msg));
                    }
                    Err(SevenZRunError::WrongPassword) => {
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
                    match self.test_7z_list_password(actual_archive, force_type, pw) {
                        PasswordTestResult::Matched => {
                            self.stage(format!("[第{}层] 密码匹配，正在解压...", depth + 1));
                            match self.run_7z_extract(actual_archive, force_type, staging_dir, pw) {
                                Ok(()) => return Ok(pw.clone()),
                                Err(SevenZRunError::Cancelled) => {
                                    return Err(ExtractError::Cancelled);
                                }
                                Err(SevenZRunError::WrongPassword) => {
                                    clear_dir_contents(staging_dir);
                                }
                                Err(SevenZRunError::Other(msg)) => {
                                    clear_dir_contents(staging_dir);
                                    return Err(ExtractError::Fatal(msg));
                                }
                            }
                        }
                        PasswordTestResult::WrongPassword => continue,
                        PasswordTestResult::FatalError(msg) => {
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
                        match self.test_7z_entry_password(actual_archive, force_type, pw, entry) {
                            PasswordTestResult::Matched => {}
                            PasswordTestResult::WrongPassword => continue,
                            PasswordTestResult::FatalError(msg) => {
                                return Err(ExtractError::Fatal(msg));
                            }
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
            EncryptionProbe::Fatal(msg) => {
                return Err(ExtractError::Fatal(msg));
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
                trick: TrickKind::DisguisedExtension { original_ext: ext },
                is_split: false,
                disguised_split: None,
                stego: None,
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
                        trick,
                        is_split: false,
                        disguised_split: None,
                        stego: None,
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

        if let Some(fatal) = classify_7z_missing_volume(&combined) {
            return (EncryptionProbe::Fatal(fatal), comment_hints);
        }

        if is_wrong_password_output(&combined) {
            return (EncryptionProbe::HeaderEncrypted, comment_hints);
        }

        if !out.status.success() {
            if let Some(fatal) = classify_7z_non_password_fatal(&combined) {
                return (EncryptionProbe::Fatal(fatal), comment_hints);
            }
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
            // Only pre-test the smallest entry via `7z t` if it's <= 32 MB.
            // For huge single-entry archives (e.g. a 2.7 GB nested .zip inside RAR5),
            // running `7z t` before `7z x` would decompress the entire multi-GB entry twice
            // without a progress bar; going straight to `7z x` rejects wrong passwords in ~50ms
            // and extracts right passwords in one pass with live progress & cancellation.
            const MAX_PRETEST_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
            let smallest_entry = smallest.and_then(|(sz, p)| {
                (sz <= MAX_PRETEST_ENTRY_BYTES).then_some(p)
            });
            (
                EncryptionProbe::DataEncrypted { smallest_entry },
                comment_hints,
            )
        } else {
            (EncryptionProbe::Unencrypted, comment_hints)
        }
    }

    fn test_7z_list_password(
        &self,
        archive: &Path,
        force_type: Option<&str>,
        pw: &str,
    ) -> PasswordTestResult {
        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("l").arg("-y").arg("-sccUTF-8");
        add_password_arg(&mut cmd, pw);
        if let Some(t) = force_type {
            cmd.arg(format!("-t{t}"));
        }
        cmd.arg("--").arg(archive);
        let Ok(out) = cmd.output() else {
            return PasswordTestResult::FatalError("无法启动 7z 进程".into());
        };
        if out.status.success() {
            return PasswordTestResult::Matched;
        }
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if let Some(fatal) = classify_7z_missing_volume(&combined) {
            return PasswordTestResult::FatalError(fatal);
        }
        if is_wrong_password_output(&combined) {
            return PasswordTestResult::WrongPassword;
        }
        if let Some(fatal) = classify_7z_non_password_fatal(&combined) {
            return PasswordTestResult::FatalError(fatal);
        }
        PasswordTestResult::FatalError(extract_7z_error_line(&combined))
    }

    fn test_7z_entry_password(
        &self,
        archive: &Path,
        force_type: Option<&str>,
        pw: &str,
        entry: &str,
    ) -> PasswordTestResult {
        let mut cmd = new_hidden_command(&self.seven_zip);
        cmd.arg("t").arg("-y").arg("-sccUTF-8");
        add_password_arg(&mut cmd, pw);
        if let Some(t) = force_type {
            cmd.arg(format!("-t{t}"));
        }
        cmd.arg("--").arg(archive).arg(entry);
        let Ok(out) = cmd.output() else {
            return PasswordTestResult::FatalError("无法启动 7z 进程".into());
        };
        if out.status.success() {
            return PasswordTestResult::Matched;
        }
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if let Some(fatal) = classify_7z_missing_volume(&combined) {
            return PasswordTestResult::FatalError(fatal);
        }
        if is_wrong_password_output(&combined) {
            return PasswordTestResult::WrongPassword;
        }
        if let Some(fatal) = classify_7z_non_password_fatal(&combined) {
            return PasswordTestResult::FatalError(fatal);
        }
        PasswordTestResult::WrongPassword
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

        if let Some(fatal) = classify_7z_missing_volume(&combined) {
            return Err(SevenZRunError::Other(fatal));
        }

        if is_wrong_password_output(&combined) {
            return Err(SevenZRunError::WrongPassword);
        }

        if let Some(fatal) = classify_7z_non_password_fatal(&combined) {
            return Err(SevenZRunError::Other(fatal));
        }

        Err(SevenZRunError::Other(extract_7z_error_line(&combined)))
    }

    /// Decompresses a standalone LZ4 Frame file natively in pure Rust into `staging_dir`.
    fn extract_standalone_lz4(
        &self,
        actual_archive: &Path,
        original_archive: &Path,
        staging_dir: &Path,
        depth: usize,
    ) -> Result<String, ExtractError> {
        self.stage(format!("[第{}层] 正在解压 LZ4...", depth + 1));
        let orig_name = original_archive
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("output.lz4");
        let lower = orig_name.to_ascii_lowercase();
        let inner_name = if lower.ends_with(".lz4") && orig_name.len() > 4 {
            orig_name[..orig_name.len() - 4].to_string()
        } else {
            format!("{orig_name}.out")
        };
        let dst = staging_dir.join(inner_name);
        let max_bytes = self.config.max_total_extract_mb.saturating_mul(1024 * 1024);
        let budget = max_bytes.saturating_sub(self.total_extracted_bytes);
        lz4::decompress_file(actual_archive, &dst, budget, &self.cancel_flag)
            .map_err(map_lz4_error)?;
        Ok(String::new())
    }

    /// Prepares all sibling split volumes (supporting mixed outer compression wrappers like
    /// `.part1.rar.lz4` + `.part2.rar.bz2`, plain + wrapped combinations, and renamed splits)
    /// into a temporary directory with clean volume names and validates headers before passing to 7z.
    fn stage_disguised_split_volumes(
        &self,
        first_vol: &Path,
        info: &DisguisedSplitInfo,
        depth: usize,
    ) -> Result<(TempDirGuard, PathBuf, usize, usize), ExtractError> {
        let parent = first_vol.parent().unwrap_or_else(|| Path::new("."));
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stage_dir = parent.join(format!(".ohunzip_split_{}_{}", std::process::id(), ts));
        fs::create_dir_all(&stage_dir)
            .map_err(|e| ExtractError::Fatal(format!("无法创建分卷还原临时目录: {e}")))?;
        let guard = TempDirGuard(stage_dir.clone());

        let siblings = find_disguised_split_siblings_detailed(first_vol, info);
        if let Some(missing_name) = find_missing_split_gap(&siblings, info) {
            return Err(ExtractError::Fatal(format!(
                "分卷不完整，缺少分卷文件: {missing_name}"
            )));
        }

        let inner_fmt = detector::infer_split_format_from_name(Path::new(&info.clean_filename()));
        let first_clean_path = stage_dir.join(info.clean_filename());
        let total = siblings.len();
        let mut unwrapped_count = 0usize;

        for (idx, sib) in siblings.into_iter().enumerate() {
            if self.is_cancelled() {
                return Err(ExtractError::Cancelled);
            }
            let dst = stage_dir.join(&sib.clean_name);
            let did_unwrap = self.prepare_single_split_volume(
                &sib.src_path,
                &dst,
                &stage_dir,
                inner_fmt,
                depth,
                idx + 1,
                total,
            )?;
            if did_unwrap {
                unwrapped_count += 1;
            }
            validate_staged_split_volume(&sib.src_path, &dst, sib.part_num, inner_fmt)?;
        }

        if !first_clean_path.exists() {
            return Err(ExtractError::Fatal("未能还原首卷分卷文件".into()));
        }

        Ok((guard, first_clean_path, total, unwrapped_count))
    }

    /// Unwraps 0..4 outer compression layers (LZ4, BZip2, GZip, XZ, Zstd, or outer ZIP/7z/TAR)
    /// around a single split volume into `dst`. Returns `true` if at least one outer layer was unpacked.
    #[allow(clippy::too_many_arguments)]
    fn prepare_single_split_volume(
        &self,
        src_path: &Path,
        dst: &Path,
        stage_dir: &Path,
        inner_fmt: ArchiveFormat,
        depth: usize,
        vol_idx: usize,
        vol_total: usize,
    ) -> Result<bool, ExtractError> {
        const MAX_OUTER_LAYERS: usize = 4;
        let mut cur_src = src_path.to_path_buf();
        let mut temp_guards: Vec<TempFileGuard> = Vec::new();
        let mut unwrapped_layers = 0usize;

        for layer in 0..MAX_OUTER_LAYERS {
            if self.is_cancelled() {
                return Err(ExtractError::Cancelled);
            }
            let Some(outer_fmt) = detect_outer_wrapper_format(&cur_src, inner_fmt) else {
                break;
            };

            self.stage(format!(
                "[第{}层] 正在解包外层 {} 分卷 ({}/{})...",
                depth + 1,
                outer_fmt.display_name(),
                vol_idx,
                vol_total
            ));

            let layer_out = stage_dir.join(format!(
                ".unwrap_v{vol_idx}_l{layer}_{}.bin",
                std::process::id()
            ));
            let layer_guard = TempFileGuard(layer_out.clone());

            match outer_fmt {
                ArchiveFormat::Lz4 => {
                    let max_bytes = self.config.max_total_extract_mb.saturating_mul(1024 * 1024);
                    let budget = max_bytes.saturating_sub(self.total_extracted_bytes);
                    lz4::decompress_file(&cur_src, &layer_out, budget, &self.cancel_flag)
                        .map_err(map_lz4_error)?;
                }
                _ => {
                    self.decompress_outer_volume_with_7z(
                        &cur_src,
                        outer_fmt,
                        &layer_out,
                        stage_dir,
                    )?;
                }
            }

            cur_src = layer_out;
            temp_guards.push(layer_guard);
            unwrapped_layers += 1;
        }

        if unwrapped_layers > 0 {
            if fs::rename(&cur_src, dst).is_err() {
                fs::copy(&cur_src, dst)
                    .map_err(|e| ExtractError::Fatal(format!("无法移动解包后的分卷文件: {e}")))?;
            }
            return Ok(true);
        }

        if fs::hard_link(src_path, dst).is_err() {
            fs::copy(src_path, dst)
                .map_err(|e| ExtractError::Fatal(format!("无法准备分卷文件: {e}")))?;
        }
        Ok(false)
    }

    fn decompress_outer_volume_with_7z(
        &self,
        src: &Path,
        outer_fmt: ArchiveFormat,
        dst_file: &Path,
        stage_dir: &Path,
    ) -> Result<(), ExtractError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_dir = stage_dir.join(format!(".unwrap_7z_{ts}"));
        fs::create_dir_all(&tmp_dir)
            .map_err(|e| ExtractError::Fatal(format!("无法创建外层解包临时目录: {e}")))?;
        let _dir_guard = TempDirGuard(tmp_dir.clone());

        match self.run_7z_extract(src, resolve_seven_zip_type(src, outer_fmt), &tmp_dir, "") {
            Ok(()) => {}
            Err(SevenZRunError::Cancelled) => return Err(ExtractError::Cancelled),
            Err(SevenZRunError::WrongPassword) => {
                return Err(ExtractError::Fatal(format!(
                    "分卷外层压缩包需要密码（{}），请先单独解开外层",
                    src.file_name().and_then(|n| n.to_str()).unwrap_or("")
                )));
            }
            Err(SevenZRunError::Other(msg)) => {
                return Err(ExtractError::Fatal(format!(
                    "解包分卷外层 {} 失败（{}）: {msg}",
                    outer_fmt.display_name(),
                    src.file_name().and_then(|n| n.to_str()).unwrap_or("")
                )));
            }
        }

        let extracted = collect_files_recursively(&tmp_dir);
        if extracted.len() != 1 {
            return Err(ExtractError::Fatal(format!(
                "分卷外层 {} 解包后包含 {} 个文件（预期 1 个分卷文件）",
                outer_fmt.display_name(),
                extracted.len()
            )));
        }

        if fs::rename(&extracted[0], dst_file).is_err() {
            fs::copy(&extracted[0], dst_file)
                .map_err(|e| ExtractError::Fatal(format!("无法整理外层解包结果: {e}")))?;
        }
        Ok(())
    }

    /// Restores a single stego/polyglot file to a temporary file without modifying the original.
    fn restore_stego_to_temp(
        &self,
        src: &Path,
        restorer: &dyn StegoRestorer,
        fmt: ArchiveFormat,
        target_dir: &Path,
        depth: usize,
    ) -> Result<TempFileGuard, ExtractError> {
        let base_label = restorer.stage_label(fmt);
        self.stage(format!("[第{}层] {base_label}...", depth + 1));

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_name = format!(
            ".ohunzip_stego_{}_{}_{}.{}",
            restorer.tool_id(),
            std::process::id(),
            ts,
            fmt.canonical_ext()
        );

        // Prefer placing the restored temp file on the same drive as `target_dir` so multi-GB
        // stego files don't exhaust a small C: temp partition; fall back to system temp dir.
        let temp_path = target_dir
            .parent()
            .filter(|p| fs::create_dir_all(p).is_ok())
            .map(|p| p.join(&temp_name))
            .and_then(|candidate| File::create(&candidate).ok().map(|_| candidate))
            .unwrap_or_else(|| std::env::temp_dir().join(&temp_name));

        let guard = TempFileGuard(temp_path.clone());
        let mut last_pct = 0u8;
        restorer
            .restore_to(src, &temp_path, &self.cancel_flag, &mut |pct| {
                if pct >= last_pct.saturating_add(2) || pct == 100 {
                    last_pct = pct;
                    let _ = self.tx.send(ExtractEvent::Stage(format!(
                        "[第{}层] {base_label} ({pct}%)...",
                        depth + 1
                    )));
                }
            })
            .map_err(map_stego_error)?;
        Ok(guard)
    }

    /// Restores all sibling volumes of a stego-disguised split archive into a temporary directory.
    fn stage_stego_split_volumes(
        &self,
        first_vol: &Path,
        detected: &DetectedArchive,
        first_restorer: &dyn StegoRestorer,
        target_dir: &Path,
        depth: usize,
    ) -> Result<(TempDirGuard, PathBuf, usize, usize), ExtractError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir_name = format!(
            ".ohunzip_stego_split_{}_{}_{}",
            first_restorer.tool_id(),
            std::process::id(),
            ts
        );
        let stage_dir = target_dir
            .parent()
            .or_else(|| first_vol.parent())
            .filter(|p| fs::create_dir_all(p).is_ok())
            .map(|p| p.join(&dir_name))
            .unwrap_or_else(|| std::env::temp_dir().join(&dir_name));

        fs::create_dir_all(&stage_dir)
            .map_err(|e| ExtractError::Fatal(format!("无法创建隐写分卷临时目录: {e}")))?;
        let guard = TempDirGuard(stage_dir.clone());

        let siblings = find_split_siblings_with_clean_names(first_vol, detected);
        let total = siblings.len();
        let mut restored_count = 0usize;
        let mut first_clean_path: Option<PathBuf> = None;

        for (idx, (src_path, clean_name)) in siblings.into_iter().enumerate() {
            if self.is_cancelled() {
                return Err(ExtractError::Cancelled);
            }
            let dst = stage_dir.join(&clean_name);
            let is_first = src_path == first_vol;
            if is_first {
                first_clean_path = Some(dst.clone());
                self.stage(format!(
                    "[第{}层] 正在还原隐写分卷 ({}/{})...",
                    depth + 1,
                    idx + 1,
                    total
                ));
                first_restorer
                    .restore_to(&src_path, &dst, &self.cancel_flag, &mut |_| {})
                    .map_err(map_stego_error)?;
                restored_count += 1;
            } else if let Some(sib_restorer) =
                first_restorer.probe_split_sibling(first_vol, &src_path)
            {
                self.stage(format!(
                    "[第{}层] 正在还原隐写分卷 ({}/{})...",
                    depth + 1,
                    idx + 1,
                    total
                ));
                sib_restorer
                    .restore_to(&src_path, &dst, &self.cancel_flag, &mut |_| {})
                    .map_err(map_stego_error)?;
                restored_count += 1;
            } else if fs::hard_link(&src_path, &dst).is_err() {
                fs::copy(&src_path, &dst).map_err(|e| {
                    ExtractError::Fatal(format!("无法准备分卷文件 {clean_name}: {e}"))
                })?;
            }
        }

        let first_clean = first_clean_path
            .ok_or_else(|| ExtractError::Fatal("未能还原首卷隐写分卷文件".into()))?;
        Ok((guard, first_clean, restored_count, total))
    }
}

fn map_stego_error(err: StegoError) -> ExtractError {
    match err {
        StegoError::Cancelled => ExtractError::Cancelled,
        StegoError::Message(msg) => ExtractError::Fatal(msg),
    }
}

fn map_lz4_error(err: Lz4Error) -> ExtractError {
    match err {
        Lz4Error::Cancelled => ExtractError::Cancelled,
        Lz4Error::Message(msg) => ExtractError::Fatal(msg),
    }
}

/// Resolves the exact 7-Zip `-t<type>` switch for `path`.
/// Crucially, 7-Zip uses `-trar` ONLY for RAR4 (`Rar!\x1A\x07\x00`) and `-trar5` for RAR5
/// (`Rar!\x1A\x07\x01\x00`); passing `-trar` on a RAR5 archive fails with "Is not archive".
fn resolve_seven_zip_type(path: &Path, fmt: ArchiveFormat) -> Option<&'static str> {
    if fmt == ArchiveFormat::Rar {
        let mut buf = [0u8; 8];
        if let Ok(mut f) = File::open(path) {
            if let Ok(n) = f.read(&mut buf) {
                if n >= 8 && &buf[0..8] == b"Rar!\x1A\x07\x01\x00" {
                    return Some("rar5");
                }
                if n >= 7 && &buf[0..7] == b"Rar!\x1A\x07\x00" {
                    return Some("rar");
                }
            }
        }
        return None;
    }
    fmt.seven_zip_type()
}

enum EncryptionProbe {
    Unencrypted,
    HeaderEncrypted,
    DataEncrypted { smallest_entry: Option<String> },
    Fatal(String),
    Unknown,
}

enum PasswordTestResult {
    Matched,
    WrongPassword,
    FatalError(String),
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

/// Detects explicit missing-volume errors from 7-Zip output so they are NEVER misreported as wrong passwords.
fn classify_7z_missing_volume(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();
        if let Some(pos) = low.find("missing volume") {
            let after = trimmed[pos + "missing volume".len()..]
                .trim_start_matches([':', ' ', '\t']);
            if !after.is_empty() {
                return Some(format!("缺少分卷文件: {after}"));
            }
            return Some("分卷不完整，缺少后续分卷文件".into());
        }
    }
    None
}

/// Classifies non-password fatal 7-Zip errors into clear user-facing diagnostics.
fn classify_7z_non_password_fatal(text: &str) -> Option<String> {
    if let Some(m) = classify_7z_missing_volume(text) {
        return Some(m);
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("unsupported method") {
        return Some("压缩包使用了当前 7-Zip 不支持的压缩算法".into());
    }
    if lower.contains("unexpected end of data") || lower.contains("unexpected end of archive") {
        return Some("压缩包或分卷数据不完整（可能缺少后续分卷或外层未解开）".into());
    }
    if (lower.contains("cannot open the file as archive")
        || lower.contains("can not open the file as archive")
        || lower.contains("is not archive"))
        && !is_wrong_password_output(text)
    {
        return Some("无法作为有效压缩包打开（文件可能损坏或外层格式不受支持）".into());
    }
    None
}

fn extract_7z_error_line(combined: &str) -> String {
    combined
        .lines()
        .map(str::trim)
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            low.contains("error")
                || low.contains("cannot open")
                || low.contains("can not open")
                || low.contains("unsupported")
                || low.contains("missing volume")
        })
        .last()
        .or_else(|| combined.lines().map(str::trim).filter(|l| !l.is_empty()).last())
        .unwrap_or("7z 解压返回错误")
        .to_string()
}

/// Checks whether `path` starts with an outer compression wrapper that should be unpacked
/// before treating the file as a raw split volume of `inner_fmt`.
fn detect_outer_wrapper_format(path: &Path, inner_fmt: ArchiveFormat) -> Option<ArchiveFormat> {
    let magic_fmt = detector::detect_magic_at_start_of_file(path)?;
    // Single-stream compressors (LZ4/BZip2/GZip/XZ/Zstd) are always outer wrappers around split volumes
    if matches!(
        magic_fmt,
        ArchiveFormat::Lz4
            | ArchiveFormat::Bzip2
            | ArchiveFormat::Gzip
            | ArchiveFormat::Xz
            | ArchiveFormat::Zstd
    ) {
        return Some(magic_fmt);
    }
    // Container archive wrapping a different split archive (e.g. `sample.part1.rar.zip` or `.7z`)
    if inner_fmt != ArchiveFormat::Generic && magic_fmt != inner_fmt {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if magic_fmt.known_extensions().contains(&ext.as_str()) {
            return Some(magic_fmt);
        }
    }
    None
}

/// Validates that a staged split volume has a valid header for `inner_fmt` so unsupported outer
/// wrappers (e.g. `.lzo`, `.br`) produce an explicit error instead of misleading password errors.
fn validate_staged_split_volume(
    orig_src: &Path,
    staged_path: &Path,
    part_num: u32,
    inner_fmt: ArchiveFormat,
) -> Result<(), ExtractError> {
    let should_check = match inner_fmt {
        // Every RAR4/RAR5 split volume starts with `Rar!\x1A\x07`
        ArchiveFormat::Rar => true,
        // 7z and ZIP raw byte splits only carry the archive magic on volume 1
        ArchiveFormat::SevenZ | ArchiveFormat::Zip => part_num == 1,
        _ => false,
    };
    if !should_check {
        return Ok(());
    }

    let actual_fmt = detector::detect_magic_at_start_of_file(staged_path);
    if actual_fmt == Some(inner_fmt) {
        return Ok(());
    }

    let orig_name = orig_src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("分卷文件");
    let ext = orig_src
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !ext.is_empty() && !inner_fmt.known_extensions().contains(&ext.to_ascii_lowercase().as_str())
    {
        Err(ExtractError::Fatal(format!(
            "分卷外层格式不受支持或文件已损坏：{orig_name}（外层 .{ext} 无法还原为有效的 {} 分卷）",
            inner_fmt.display_name()
        )))
    } else {
        Err(ExtractError::Fatal(format!(
            "分卷文件头无效或已损坏：{orig_name}（不是有效的 {} 分卷）",
            inner_fmt.display_name()
        )))
    }
}

struct SplitSibling {
    part_num: u32,
    src_path: PathBuf,
    clean_name: String,
    disguise_tail: String,
}

fn find_missing_split_gap(siblings: &[SplitSibling], info: &DisguisedSplitInfo) -> Option<String> {
    let max_part = siblings.iter().map(|s| s.part_num).max().unwrap_or(1);
    let present: HashSet<u32> = siblings.iter().map(|s| s.part_num).collect();
    let width = info.number_str.len();
    for expected in 1..=max_part {
        if !present.contains(&expected) {
            let num_fmt = if width > 1 {
                format!("{expected:0width$}")
            } else {
                format!("{expected}")
            };
            return Some(format!("{}{}{}", info.prefix, num_fmt, info.mid_suffix));
        }
    }
    None
}

fn has_wrapped_or_disguised_siblings(first_vol: &Path, info: &DisguisedSplitInfo) -> bool {
    let siblings = find_disguised_split_siblings_detailed(first_vol, info);
    siblings.iter().any(|s| !s.disguise_tail.is_empty())
}

/// Finds all sibling split volumes matching `(prefix, mid_suffix)` regardless of outer wrapper
/// suffix (supporting mixed wrappers like `.part1.rar.lz4` + `.part2.rar.bz2` + `.part3.rar`).
fn find_disguised_split_siblings_detailed(
    first_vol: &Path,
    info: &DisguisedSplitInfo,
) -> Vec<SplitSibling> {
    let mut by_part: BTreeMap<u32, SplitSibling> = BTreeMap::new();
    by_part.insert(
        info.part_num,
        SplitSibling {
            part_num: info.part_num,
            src_path: first_vol.to_path_buf(),
            clean_name: info.clean_filename(),
            disguise_tail: info.disguise_tail.clone(),
        },
    );

    let Some(parent) = first_vol.parent() else {
        return by_part.into_values().collect();
    };
    let prefix_low = info.prefix.to_ascii_lowercase();
    let mid_low = info.mid_suffix.to_ascii_lowercase();
    let tail_low = info.disguise_tail.to_ascii_lowercase();

    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_file() || p == first_vol {
                continue;
            }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(cand) = detector::parse_any_split_filename(name) else {
                continue;
            };
            if cand.prefix.to_ascii_lowercase() != prefix_low
                || cand.mid_suffix.to_ascii_lowercase() != mid_low
            {
                continue;
            }
            if cand.part_num == info.part_num {
                continue;
            }

            let cand_tail_low = cand.disguise_tail.to_ascii_lowercase();
            let candidate = SplitSibling {
                part_num: cand.part_num,
                src_path: p,
                clean_name: cand.clean_filename(),
                disguise_tail: cand.disguise_tail,
            };

            match by_part.get(&cand.part_num) {
                None => {
                    by_part.insert(cand.part_num, candidate);
                }
                Some(existing) => {
                    // Prefer an exact same outer tail (when non-empty), otherwise prefer plain unwrapped volume
                    let existing_tail_low = existing.disguise_tail.to_ascii_lowercase();
                    let prefer_new = (!tail_low.is_empty()
                        && cand_tail_low == tail_low
                        && existing_tail_low != tail_low)
                        || (existing_tail_low != tail_low
                            && cand_tail_low.is_empty()
                            && !existing_tail_low.is_empty());
                    if prefer_new {
                        by_part.insert(cand.part_num, candidate);
                    }
                }
            }
        }
    }

    by_part.into_values().collect()
}

fn find_disguised_split_siblings(
    first_vol: &Path,
    info: &DisguisedSplitInfo,
) -> Vec<(PathBuf, String)> {
    find_disguised_split_siblings_detailed(first_vol, info)
        .into_iter()
        .map(|s| (s.src_path, s.clean_name))
        .collect()
}

/// Finds all sibling split volumes along with their restored clean filenames (works for both
/// disguised splits like `movie.7z.001.mp4` and standard splits like `movie.7z.001` / `.part1.rar`).
fn find_split_siblings_with_clean_names(
    first_vol: &Path,
    detected: &DetectedArchive,
) -> Vec<(PathBuf, String)> {
    if let Some(ref info) = detected.disguised_split {
        return find_disguised_split_siblings(first_vol, info);
    }
    let mut out: Vec<(PathBuf, String)> = collect_source_files_to_trash(first_vol, detected)
        .into_iter()
        .map(|p| {
            let clean = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vol")
                .to_string();
            (p, clean)
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Produce a clean folder stem name from an archive filename (stripping `.tar.gz`, `.part1.rar`,
/// `.7z.001`, disguised splits, and Apate double extensions like `.zip.mp4` / `.tar.gz.mp4`).
pub fn clean_archive_stem(path: &Path) -> String {
    let raw_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("extracted");

    // If it's a disguised split like `movie.7z.001.mp4`, strip the disguise first
    let normalized = detector::parse_disguised_split_filename(raw_name)
        .map(|info| info.clean_filename())
        .unwrap_or_else(|| detector::strip_outer_disguise_exts(raw_name));

    let name = normalized.as_str();
    let lower = name.to_ascii_lowercase();

    for compound in [
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tar.zst",
        ".tar.lz4",
        ".7z.001",
        ".zip.001",
        ".rar.001",
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
        assert_eq!(clean_archive_stem(Path::new("secret.zip.mp4")), "secret");
        assert_eq!(clean_archive_stem(Path::new("secret.zip.mp4.jpg")), "secret");
        assert_eq!(clean_archive_stem(Path::new("backup.tar.gz.mp4")), "backup");
        assert_eq!(clean_archive_stem(Path::new("backup.tar.gz.mp4.exe")), "backup");
        assert_eq!(clean_archive_stem(Path::new("movie.7z.001.mp4.jpg")), "movie");
        assert_eq!(clean_archive_stem(Path::new("my.v1.2.mp4")), "my.v1.2");
    }

    #[test]
    fn test_parse_progress_percent() {
        assert_eq!(parse_latest_progress_percent("  0%"), Some(0));
        assert_eq!(parse_latest_progress_percent(" 12% 3 - file.bin\r 47%"), Some(47));
        assert_eq!(parse_latest_progress_percent("100% Everything is Ok"), Some(100));
        assert_eq!(parse_latest_progress_percent("Scanning..."), None);
    }

    #[test]
    fn test_resolve_seven_zip_type_distinguishes_rar5_and_rar4() {
        let dir = std::env::temp_dir().join("oh_unzip_rar5_type_tests");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let rar5 = dir.join("disguised_rar5.jpg");
        fs::write(&rar5, b"Rar!\x1A\x07\x01\x00extra-bytes").unwrap();
        assert_eq!(resolve_seven_zip_type(&rar5, ArchiveFormat::Rar), Some("rar5"));

        let rar4 = dir.join("disguised_rar4.jpg");
        fs::write(&rar4, b"Rar!\x1A\x07\x00extra-bytes").unwrap();
        assert_eq!(resolve_seven_zip_type(&rar4, ArchiveFormat::Rar), Some("rar"));

        let _ = fs::remove_dir_all(&dir);
    }

    fn apate_disguise_bytes(orig: &[u8], mask: &[u8]) -> Vec<u8> {
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

    #[test]
    fn test_apate_end_to_end_extraction_with_7z() {
        let Some(sz) = crate::seven_zip::detect_seven_zip("") else {
            return;
        };

        let dir = std::env::temp_dir().join("oh_unzip_apate_e2e_tests");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let payload_file = dir.join("hello.txt");
        let payload_bytes = b"Hello from OhUnzip Apate steganography test!\n".repeat(400);
        fs::write(&payload_file, &payload_bytes).unwrap();

        // 1. Single ZIP archive disguised with Apate OneKey-like big MP4 mask (orig < mask)
        let raw_zip = dir.join("sample.zip");
        let status = new_hidden_command(&sz.path)
            .args(["a", "-tzip", "-y"])
            .arg(&raw_zip)
            .arg(&payload_file)
            .status()
            .unwrap();
        assert!(status.success());

        let zip_bytes = fs::read(&raw_zip).unwrap();
        let mut mp4_mask = vec![0xABu8; 64 * 1024];
        mp4_mask[..32].copy_from_slice(&[
            0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00,
            0x02, 0x00, 0x69, 0x73, 0x6F, 0x6D, 0x69, 0x73, 0x6F, 0x32, 0x61, 0x76, 0x63, 0x31,
            0x6D, 0x70, 0x34, 0x31,
        ]);
        let apate_zip = dir.join("sample.zip.mp4");
        fs::write(&apate_zip, apate_disguise_bytes(&zip_bytes, &mp4_mask)).unwrap();

        let mut cfg = AppConfig::default();
        cfg.move_source_to_trash = true; // Verify stego carrier is NEVER trashed!
        let (tx, rx) = mpsc::channel();
        run_extraction_job(
            apate_zip.clone(),
            sz.path.clone(),
            cfg.clone(),
            None,
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx,
        );

        let mut completed_dir = None;
        while let Ok(ev) = rx.try_recv() {
            if let ExtractEvent::Completed { output_dir, .. } = ev {
                completed_dir = Some(output_dir);
            }
        }
        let out_dir = completed_dir.expect("Apate single ZIP extraction should succeed");
        assert_eq!(out_dir.file_name().and_then(|n| n.to_str()), Some("sample"));
        assert_eq!(fs::read(out_dir.join("hello.txt")).unwrap(), payload_bytes);
        assert!(apate_zip.exists(), "Apate source file must never be trashed or mutated");

        // 2. Polyglot JPEG + ZIP end-to-end extraction via OffsetRestorer
        let poly_jpg = dir.join("cover.jpg");
        let mut poly_bytes = vec![
            0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9,
        ];
        poly_bytes.extend_from_slice(&zip_bytes);
        fs::write(&poly_jpg, &poly_bytes).unwrap();

        let (tx_p, rx_p) = mpsc::channel();
        run_extraction_job(
            poly_jpg.clone(),
            sz.path.clone(),
            cfg.clone(),
            None,
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx_p,
        );
        let mut poly_out_dir = None;
        while let Ok(ev) = rx_p.try_recv() {
            if let ExtractEvent::Completed { output_dir, .. } = ev {
                poly_out_dir = Some(output_dir);
            }
        }
        let poly_out = poly_out_dir.expect("Polyglot JPEG+ZIP extraction should succeed");
        assert_eq!(fs::read(poly_out.join("hello.txt")).unwrap(), payload_bytes);
        assert!(poly_jpg.exists(), "Polyglot carrier file must never be trashed");

        // 3. Split 7z archive (`splitpack.7z.001.mp4` + `.002.mp4` + ...) disguised with Apate
        let split_dir = dir.join("splits");
        fs::create_dir_all(&split_dir).unwrap();
        let big_payload = split_dir.join("data.bin");
        let big_bytes: Vec<u8> = (0..12_000).map(|i| ((i * 73 + 11) & 0xFF) as u8).collect();
        fs::write(&big_payload, &big_bytes).unwrap();

        let raw_7z_base = split_dir.join("splitpack.7z");
        let status2 = new_hidden_command(&sz.path)
            .args(["a", "-t7z", "-mx=0", "-v4k", "-y"])
            .arg(&raw_7z_base)
            .arg(&big_payload)
            .status()
            .unwrap();
        assert!(status2.success());

        // Disguise every split volume with Apate JPG 4-byte mask and append `.mp4`
        let jpg_mask = [0xFFu8, 0xD8, 0xFF, 0xE1];
        let mut disguised_first = None;
        for entry in fs::read_dir(&split_dir).unwrap().flatten() {
            let p = entry.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("splitpack.7z.") {
                let raw = fs::read(&p).unwrap();
                let new_path = split_dir.join(format!("{name}.mp4"));
                fs::write(&new_path, apate_disguise_bytes(&raw, &jpg_mask)).unwrap();
                fs::remove_file(&p).unwrap();
                if name.ends_with(".001") {
                    disguised_first = Some(new_path);
                }
            }
        }
        let first_vol = disguised_first.expect("split .001 volume must exist");

        let (tx2, rx2) = mpsc::channel();
        run_extraction_job(
            first_vol,
            sz.path.clone(),
            cfg.clone(),
            None,
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx2,
        );

        let mut split_out_dir = None;
        while let Ok(ev) = rx2.try_recv() {
            if let ExtractEvent::Completed { output_dir, .. } = ev {
                split_out_dir = Some(output_dir);
            }
        }
        let split_out = split_out_dir.expect("Apate split 7z extraction should succeed");
        assert_eq!(fs::read(split_out.join("data.bin")).unwrap(), big_bytes);

        // 4. Stacked 2-layer Apate single ZIP (`double.zip.mp4.jpg`: inner MP4 64KB + outer JPG 4B)
        let double_layer_bytes =
            apate_disguise_bytes(&apate_disguise_bytes(&zip_bytes, &mp4_mask), &jpg_mask);
        let double_apate = dir.join("double.zip.mp4.jpg");
        fs::write(&double_apate, &double_layer_bytes).unwrap();

        let (tx3, rx3) = mpsc::channel();
        run_extraction_job(
            double_apate.clone(),
            sz.path.clone(),
            cfg.clone(),
            None,
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx3,
        );
        let mut double_out_dir = None;
        while let Ok(ev) = rx3.try_recv() {
            if let ExtractEvent::Completed { output_dir, .. } = ev {
                double_out_dir = Some(output_dir);
            }
        }
        let double_out = double_out_dir.expect("2-layer stacked Apate ZIP extraction should succeed");
        assert_eq!(double_out.file_name().and_then(|n| n.to_str()), Some("double"));
        assert_eq!(fs::read(double_out.join("hello.txt")).unwrap(), payload_bytes);
        assert!(double_apate.exists());

        // 5. Stacked 2-layer Apate split 7z (`splits2/multi.7z.001.mp4.jpg` + `.002.mp4.jpg` + ...)
        let split2_dir = dir.join("splits2");
        fs::create_dir_all(&split2_dir).unwrap();
        let raw_7z_base2 = split2_dir.join("multi.7z");
        let status3 = new_hidden_command(&sz.path)
            .args(["a", "-t7z", "-mx=0", "-v4k", "-y"])
            .arg(&raw_7z_base2)
            .arg(&big_payload)
            .status()
            .unwrap();
        assert!(status3.success());

        let mut disguised_first2 = None;
        for entry in fs::read_dir(&split2_dir).unwrap().flatten() {
            let p = entry.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("multi.7z.") {
                let raw = fs::read(&p).unwrap();
                let l1 = apate_disguise_bytes(&raw, &mp4_mask);
                let l2 = apate_disguise_bytes(&l1, &jpg_mask);
                let new_path = split2_dir.join(format!("{name}.mp4.jpg"));
                fs::write(&new_path, &l2).unwrap();
                fs::remove_file(&p).unwrap();
                if name.ends_with(".001") {
                    disguised_first2 = Some(new_path);
                }
            }
        }
        let first_vol2 = disguised_first2.expect("2-layer split .001 volume must exist");

        let (tx4, rx4) = mpsc::channel();
        run_extraction_job(
            first_vol2,
            sz.path.clone(),
            cfg,
            None,
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx4,
        );
        let mut split2_out_dir = None;
        while let Ok(ev) = rx4.try_recv() {
            if let ExtractEvent::Completed { output_dir, .. } = ev {
                split2_out_dir = Some(output_dir);
            }
        }
        let split2_out = split2_out_dir.expect("2-layer stacked Apate split 7z should succeed");
        assert_eq!(fs::read(split2_out.join("data.bin")).unwrap(), big_bytes);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mixed_outer_wrapped_encrypted_splits_and_clear_errors() {
        let Some(sz) = crate::seven_zip::detect_seven_zip("") else {
            return;
        };

        let dir = std::env::temp_dir().join("oh_unzip_mixed_split_tests");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // 1. Standalone LZ4 file extraction
        let lz4_payload = b"Standalone LZ4 content verified!\n".repeat(120);
        let standalone_lz4 = dir.join("note.txt.lz4");
        fs::write(
            &standalone_lz4,
            crate::lz4::tests::encode_lz4_frame_uncompressed(&lz4_payload),
        )
        .unwrap();
        let (tx_lz, rx_lz) = mpsc::channel();
        run_extraction_job(
            standalone_lz4,
            sz.path.clone(),
            AppConfig::default(),
            None,
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx_lz,
        );
        let mut lz_out_dir = None;
        while let Ok(ev) = rx_lz.try_recv() {
            if let ExtractEvent::Completed { output_dir, .. } = ev {
                lz_out_dir = Some(output_dir);
            }
        }
        let lz_out = lz_out_dir.expect("standalone .lz4 extraction should succeed");
        assert_eq!(fs::read(lz_out.join("note.txt")).unwrap(), lz4_payload);

        // 2. Header-encrypted 3-volume 7z where vol1=.lz4, vol2=.bz2, vol3=plain!
        let mix_dir = dir.join("mixed");
        fs::create_dir_all(&mix_dir).unwrap();
        let secret_file = mix_dir.join("secret.bin");
        let secret_bytes: Vec<u8> = (0..10_000).map(|i| ((i * 41 + 9) & 0xFF) as u8).collect();
        fs::write(&secret_file, &secret_bytes).unwrap();

        let base_7z = mix_dir.join("pack.7z");
        let st = new_hidden_command(&sz.path)
            .args(["a", "-t7z", "-mx=0", "-mhe=on", "-pMixPass123", "-v4k", "-y"])
            .arg(&base_7z)
            .arg(&secret_file)
            .status()
            .unwrap();
        assert!(st.success());

        // Wrap vol 1 in LZ4, vol 2 in BZip2, keep vol 3 plain
        let v1_raw = fs::read(mix_dir.join("pack.7z.001")).unwrap();
        let v1_lz4 = mix_dir.join("pack.7z.001.lz4");
        fs::write(&v1_lz4, crate::lz4::tests::encode_lz4_frame_uncompressed(&v1_raw)).unwrap();
        fs::remove_file(mix_dir.join("pack.7z.001")).unwrap();

        let v2_plain = mix_dir.join("pack.7z.002");
        let v2_bz2 = mix_dir.join("pack.7z.002.bz2");
        let st_bz = new_hidden_command(&sz.path)
            .args(["a", "-tbzip2", "-y"])
            .arg(&v2_bz2)
            .arg(&v2_plain)
            .status()
            .unwrap();
        assert!(st_bz.success());
        fs::remove_file(&v2_plain).unwrap();

        // 2a. Wrong password must ask for password
        let (tx_w, rx_w) = mpsc::channel();
        run_extraction_job(
            v1_lz4.clone(),
            sz.path.clone(),
            AppConfig::default(),
            Some("WrongPass".into()),
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx_w,
        );
        let mut saw_need_pw = false;
        while let Ok(ev) = rx_w.try_recv() {
            if matches!(ev, ExtractEvent::NeedPassword { .. }) {
                saw_need_pw = true;
            }
        }
        assert!(saw_need_pw, "wrong password on wrapped header-encrypted split must return NeedPassword");

        // 2b. Correct password must unwrap vol1 (.lz4) + vol2 (.bz2) + join plain vol3 and extract!
        let (tx_ok, rx_ok) = mpsc::channel();
        run_extraction_job(
            v1_lz4.clone(),
            sz.path.clone(),
            AppConfig::default(),
            Some("MixPass123".into()),
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx_ok,
        );
        let mut ok_out_dir = None;
        let mut fail_msg = None;
        while let Ok(ev) = rx_ok.try_recv() {
            match ev {
                ExtractEvent::Completed { output_dir, .. } => ok_out_dir = Some(output_dir),
                ExtractEvent::Failed(m) => fail_msg = Some(m),
                _ => {}
            }
        }
        let ok_out = ok_out_dir.unwrap_or_else(|| {
            panic!("mixed LZ4+BZ2+plain encrypted split should succeed, failed: {fail_msg:?}")
        });
        assert_eq!(fs::read(ok_out.join("secret.bin")).unwrap(), secret_bytes);

        // 3. Missing volume gap (remove vol2.bz2 while vol3 still exists) => MUST fail explicitly, NOT NeedPassword!
        fs::remove_file(&v2_bz2).unwrap();
        let (tx_gap, rx_gap) = mpsc::channel();
        run_extraction_job(
            v1_lz4,
            sz.path.clone(),
            AppConfig::default(),
            Some("MixPass123".into()),
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx_gap,
        );
        let mut gap_err = None;
        while let Ok(ev) = rx_gap.try_recv() {
            if let ExtractEvent::Failed(m) = ev {
                gap_err = Some(m);
            }
        }
        let gap_msg = gap_err.expect("missing volume gap must fail with explicit Fatal error");
        assert!(gap_msg.contains("缺少分卷"), "unexpected error: {gap_msg}");

        // 4. Unsupported outer format (`bad.part1.rar.lzo` with garbage bytes) => MUST fail explicitly, NOT NeedPassword!
        let bad_dir = dir.join("unsupported");
        fs::create_dir_all(&bad_dir).unwrap();
        let bad_vol = bad_dir.join("bad.part1.rar.lzo");
        fs::write(&bad_vol, b"\x89LZO\x00\x0d\x0a\x1a\x0anot-a-rar-volume-at-all").unwrap();
        let (tx_bad, rx_bad) = mpsc::channel();
        run_extraction_job(
            bad_vol,
            sz.path.clone(),
            AppConfig::default(),
            Some("any".into()),
            OutputTarget::SameDir,
            None,
            Arc::new(AtomicBool::new(false)),
            tx_bad,
        );
        let mut bad_err = None;
        while let Ok(ev) = rx_bad.try_recv() {
            if let ExtractEvent::Failed(m) = ev {
                bad_err = Some(m);
            }
        }
        let bad_msg = bad_err.expect("unsupported outer wrapper must return explicit Fatal error");
        assert!(bad_msg.contains("不受支持"), "unexpected error: {bad_msg}");

        let _ = fs::remove_dir_all(&dir);
    }
}
