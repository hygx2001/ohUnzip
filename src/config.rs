use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputMode {
    SameDir,
    CustomDir,
}

impl Default for OutputMode {
    fn default() -> Self {
        Self::SameDir
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordEntry {
    pub value: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub use_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDelimiter {
    Auto,
    Newline,
    Comma,
    Semicolon,
    Space,
    Custom,
}

impl ImportDelimiter {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "自动",
            Self::Newline => "换行",
            Self::Comma => "逗号",
            Self::Semicolon => "分号",
            Self::Space => "空格",
            Self::Custom => "自定义",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Txt,
    Json,
    Csv,
}

impl ExportFormat {
    pub fn suggested_filename(&self) -> &'static str {
        match self {
            Self::Txt => "ohunzip_passwords.txt",
            Self::Json => "ohunzip_passwords.json",
            Self::Csv => "ohunzip_passwords.csv",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub seven_zip_path: String,
    pub passwords: Vec<PasswordEntry>,
    pub max_depth: usize,
    pub detect_disguised: bool,
    pub detect_polyglot: bool,
    pub skip_office_zip: bool,
    pub clean_intermediate: bool,
    pub extract_filename_password_hint: bool,
    pub output_mode: OutputMode,
    pub custom_output_dir: String,
    pub max_total_extract_mb: u64,
    pub logs_expanded: bool,
    pub theme: String,
    pub move_source_to_trash: bool,
    pub notify_on_complete: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            seven_zip_path: String::new(),
            passwords: Vec::new(),
            max_depth: 10,
            detect_disguised: true,
            detect_polyglot: true,
            skip_office_zip: true,
            clean_intermediate: true,
            extract_filename_password_hint: true,
            output_mode: OutputMode::SameDir,
            custom_output_dir: String::new(),
            max_total_extract_mb: 20_480,
            logs_expanded: false,
            theme: "light".to_string(),
            move_source_to_trash: false,
            notify_on_complete: true,
        }
    }
}

impl AppConfig {
    /// Returns the portable config path (`<exe_dir>/config.json`) if it exists,
    /// otherwise the standard user config directory (`%APPDATA%/OhUnzip/config.json`).
    pub fn is_portable_mode() -> bool {
        Self::portable_config_path().is_some_and(|p| p.is_file())
    }

    fn portable_config_path() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        Some(exe.parent()?.join("config.json"))
    }

    pub fn config_file_path() -> PathBuf {
        if let Some(portable) = Self::portable_config_path() {
            if portable.is_file() {
                return portable;
            }
        }
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("OhUnzip").join("config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_file_path();
        if let Ok(text) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&text) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("无法创建配置目录: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("序列化配置失败: {e}"))?;
        fs::write(&path, json).map_err(|e| format!("保存配置失败: {e}"))?;
        Ok(())
    }

    /// Add a single password if not already present. Returns true if newly added.
    pub fn add_password(&mut self, value: &str, note: &str) -> bool {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(existing) = self.passwords.iter_mut().find(|p| p.value == trimmed) {
            if existing.note.is_empty() && !note.trim().is_empty() {
                existing.note = note.trim().to_string();
            }
            return false;
        }
        self.passwords.push(PasswordEntry {
            value: trimmed.to_string(),
            note: note.trim().to_string(),
            use_count: 0,
        });
        true
    }

    /// Add multiple passwords from multi-line text.
    pub fn add_passwords_bulk(&mut self, text: &str) -> usize {
        let items = parse_import_passwords(text, ImportDelimiter::Newline, "");
        let mut added = 0;
        for pw in items {
            if self.add_password(&pw, "") {
                added += 1;
            }
        }
        added
    }

    pub fn add_passwords_list(&mut self, items: &[String]) -> usize {
        let mut added = 0;
        for pw in items {
            if self.add_password(pw, "") {
                added += 1;
            }
        }
        added
    }

    pub fn remove_password(&mut self, idx: usize) {
        if idx < self.passwords.len() {
            self.passwords.remove(idx);
        }
    }

    pub fn move_password_up(&mut self, idx: usize) {
        if idx > 0 && idx < self.passwords.len() {
            self.passwords.swap(idx, idx - 1);
        }
    }

    pub fn move_password_down(&mut self, idx: usize) {
        if idx + 1 < self.passwords.len() {
            self.passwords.swap(idx, idx + 1);
        }
    }

    pub fn record_password_hit(&mut self, password: &str) {
        if password.is_empty() {
            return;
        }
        if let Some(entry) = self.passwords.iter_mut().find(|p| p.value == password) {
            entry.use_count += 1;
        }
    }

    pub fn export_passwords(&self, format: ExportFormat) -> String {
        match format {
            ExportFormat::Txt => self
                .passwords
                .iter()
                .map(|p| p.value.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            ExportFormat::Json => {
                serde_json::to_string_pretty(&self.passwords).unwrap_or_else(|_| "[]".into())
            }
            ExportFormat::Csv => {
                let mut lines = Vec::with_capacity(self.passwords.len() + 1);
                lines.push("password,note,use_count".to_string());
                for p in &self.passwords {
                    lines.push(format!(
                        "{},{},{}",
                        csv_escape(&p.value),
                        csv_escape(&p.note),
                        p.use_count
                    ));
                }
                lines.join("\n")
            }
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Decode text file bytes supporting UTF-8 (with optional BOM) and UTF-16 LE/BE (Windows Notepad).
pub fn decode_text_bytes(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() >= 2 {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) && bytes.len() >= 2 {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Parse passwords from raw text according to the chosen delimiter mode.
/// Deduplicates results while preserving order.
pub fn parse_import_passwords(raw: &str, mode: ImportDelimiter, custom_sep: &str) -> Vec<String> {
    let cleaned = raw.trim_start_matches('\u{FEFF}').trim();
    if cleaned.is_empty() {
        return Vec::new();
    }

    let candidates: Vec<String> = match mode {
        ImportDelimiter::Auto => parse_auto_formats(cleaned),
        ImportDelimiter::Newline => cleaned
            .lines()
            .map(|l| l.trim().to_string())
            .collect(),
        ImportDelimiter::Comma => cleaned
            .split([',', '，', '\n', '\r'])
            .map(|s| unquote_csv_field(s.trim()))
            .collect(),
        ImportDelimiter::Semicolon => cleaned
            .split([';', '；', '\n', '\r'])
            .map(|s| s.trim().to_string())
            .collect(),
        ImportDelimiter::Space => cleaned
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
        ImportDelimiter::Custom => {
            let sep = unescape_delimiter(custom_sep);
            if sep.is_empty() {
                cleaned.lines().map(|l| l.trim().to_string()).collect()
            } else {
                cleaned
                    .split(&sep)
                    .map(|s| s.trim().to_string())
                    .collect()
            }
        }
    };

    dedup_non_empty(candidates)
}

fn unescape_delimiter(sep: &str) -> String {
    let mut out = String::with_capacity(sep.len());
    let mut chars = sep.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_auto_formats(text: &str) -> Vec<String> {
    // 1. Try JSON (array of strings, array of objects, or object with `passwords` array)
    if (text.starts_with('[') || text.starts_with('{'))
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(text)
    {
        let extracted = extract_from_json(&val);
        if !extracted.is_empty() {
            return extracted;
        }
    }

    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Vec::new();
    }

    // 2. Single-line delimited list (e.g. `123, 456, 789` or `a;b;c` or `a|b|c`)
    if lines.len() == 1 {
        let single = lines[0];
        if let Some(stripped) = strip_password_label(single) {
            return vec![stripped];
        }
        if single.contains([',', '，']) {
            return single
                .split([',', '，'])
                .map(|s| unquote_csv_field(s.trim()))
                .collect();
        }
        if single.contains([';', '；']) {
            return single
                .split([';', '；'])
                .map(|s| s.trim().to_string())
                .collect();
        }
        for sep in ['|', '\t'] {
            if single.contains(sep) {
                return single
                    .split(sep)
                    .map(|s| unquote_csv_field(s.trim()))
                    .collect();
            }
        }
        return vec![single.to_string()];
    }

    // 3. CSV / TSV table with header row (e.g. `password,note,use_count` or `密码,备注`)
    let first_lower = lines[0].to_ascii_lowercase();
    let is_csv_header = (first_lower.contains(',') || first_lower.contains('\t'))
        && (first_lower.starts_with("password")
            || first_lower.starts_with("value")
            || first_lower.starts_with("pwd")
            || first_lower.starts_with("\"password\"")
            || lines[0].starts_with("密码")
            || lines[0].starts_with("解压密码"));

    if is_csv_header {
        let sep = if lines[0].contains('\t') { '\t' } else { ',' };
        return lines[1..]
            .iter()
            .filter_map(|line| parse_first_delimited_col(line, sep))
            .collect();
    }

    // 4. Multi-line plaintext / netdisk / comment-annotated lists
    let mut out = Vec::new();
    for line in lines {
        // Skip comment lines
        if line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // Strip common Chinese/English password labels (e.g. `解压密码：abc123`, `pwd=123`)
        if let Some(stripped) = strip_password_label(line) {
            out.push(stripped);
            continue;
        }
        // TSV line (`password\tnote`)
        if let Some((first, _)) = line.split_once('\t') {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
                continue;
            }
        }
        out.push(line.to_string());
    }
    out
}

fn extract_from_json(val: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                match item {
                    serde_json::Value::String(s) => out.push(s.trim().to_string()),
                    serde_json::Value::Number(n) => out.push(n.to_string()),
                    serde_json::Value::Object(map) => {
                        for key in ["value", "password", "pwd", "pass", "key", "密码"] {
                            if let Some(serde_json::Value::String(s)) = map.get(key) {
                                out.push(s.trim().to_string());
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["passwords", "items", "list", "data"] {
                if let Some(sub) = map.get(key) {
                    out.extend(extract_from_json(sub));
                }
            }
        }
        _ => {}
    }
    out
}

fn strip_password_label(line: &str) -> Option<String> {
    const PREFIXES: &[&str] = &[
        "解压密码：",
        "解压密码:",
        "解压密码=",
        "解压码：",
        "解压码:",
        "解压码=",
        "提取码：",
        "提取码:",
        "密码：",
        "密码:",
        "密码=",
    ];
    for p in PREFIXES {
        if let Some(rest) = line.strip_prefix(p) {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    let lower = line.to_ascii_lowercase();
    for p in ["password:", "password=", "passwd:", "passwd=", "pwd:", "pwd="] {
        if lower.starts_with(p) {
            let v = line[p.len()..].trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn parse_first_delimited_col(line: &str, sep: char) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        let mut col = String::new();
        let mut chars = rest.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    col.push('"');
                } else {
                    break;
                }
            } else {
                col.push(c);
            }
        }
        let col = col.trim().to_string();
        return (!col.is_empty()).then_some(col);
    }
    let first = trimmed.split(sep).next()?.trim();
    (!first.is_empty()).then(|| first.to_string())
}

fn unquote_csv_field(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].replace("\"\"", "\"")
    } else {
        s.to_string()
    }
}

fn dedup_non_empty(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let trimmed = item.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_auto_formats() {
        // JSON array of strings
        let r1 = parse_import_passwords(r#"["aaa", "bbb", "aaa"]"#, ImportDelimiter::Auto, "");
        assert_eq!(r1, vec!["aaa", "bbb"]);

        // JSON array of PasswordEntry objects
        let r2 = parse_import_passwords(
            r#"[{"value":"p1","note":"","use_count":2},{"password":"p2"}]"#,
            ImportDelimiter::Auto,
            "",
        );
        assert_eq!(r2, vec!["p1", "p2"]);

        // CSV with header & quoted value
        let r3 = parse_import_passwords(
            "password,note,use_count\n\"a,b\",memo,1\n123456,,0",
            ImportDelimiter::Auto,
            "",
        );
        assert_eq!(r3, vec!["a,b", "123456"]);

        // Netdisk lines + comments
        let r4 = parse_import_passwords(
            "# 常用密码\n解压密码：ohunzip\npwd=hello123\nplain_pw",
            ImportDelimiter::Auto,
            "",
        );
        assert_eq!(r4, vec!["ohunzip", "hello123", "plain_pw"]);

        // Single-line comma list
        let r5 = parse_import_passwords("111, 222，333", ImportDelimiter::Auto, "");
        assert_eq!(r5, vec!["111", "222", "333"]);
    }

    #[test]
    fn test_import_custom_delimiter() {
        let r = parse_import_passwords("a | b | c | a", ImportDelimiter::Custom, "|");
        assert_eq!(r, vec!["a", "b", "c"]);

        let r2 = parse_import_passwords("x\ty\tz", ImportDelimiter::Custom, r"\t");
        assert_eq!(r2, vec!["x", "y", "z"]);
    }
}
