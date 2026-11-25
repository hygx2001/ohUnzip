use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SevenZipSource {
    Custom,
    Registry,
    PathEnv,
    CommonDir,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZipInfo {
    pub path: PathBuf,
    pub version: String,
    pub source: SevenZipSource,
}

pub fn new_hidden_command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.stdin(Stdio::null());
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Probe a candidate path and extract 7-Zip version string if executable is valid.
pub fn probe_seven_zip(candidate: &Path) -> Option<(PathBuf, String)> {
    let resolved = if candidate.is_dir() {
        #[cfg(windows)]
        let p = candidate.join("7z.exe");
        #[cfg(not(windows))]
        let p = candidate.join("7z");
        p
    } else {
        candidate.to_path_buf()
    };

    if !resolved.is_file() {
        return None;
    }

    let output = new_hidden_command(&resolved).output().ok()?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let version_line = combined
        .lines()
        .map(str::trim)
        .find(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("7-zip")
                || lower.contains("nanazip")
                || lower.contains("p7zip")
                || lower.contains("igor pavlov")
        })?;

    // Trim copyright tail if present
    let short_version = version_line
        .split(':')
        .next()
        .unwrap_or(version_line)
        .trim()
        .to_string();

    Some((resolved, short_version))
}

/// Detect 7z executable. If `custom_path` is non-empty, only probe that path.
pub fn detect_seven_zip(custom_path: &str) -> Option<SevenZipInfo> {
    let trimmed = custom_path.trim();
    if !trimmed.is_empty() {
        let p = PathBuf::from(trimmed);
        return probe_seven_zip(&p).map(|(path, version)| SevenZipInfo {
            path,
            version,
            source: SevenZipSource::Custom,
        });
    }

    auto_detect_seven_zip()
}

pub fn auto_detect_seven_zip() -> Option<SevenZipInfo> {
    // 1. Windows Registry
    #[cfg(windows)]
    {
        for candidate in detect_from_windows_registry() {
            if let Some((path, version)) = probe_seven_zip(&candidate) {
                return Some(SevenZipInfo {
                    path,
                    version,
                    source: SevenZipSource::Registry,
                });
            }
        }
    }

    // 2. PATH environment variable
    for candidate in detect_from_path_env() {
        if let Some((path, version)) = probe_seven_zip(&candidate) {
            return Some(SevenZipInfo {
                path,
                version,
                source: SevenZipSource::PathEnv,
            });
        }
    }

    // 3. Common installation directories
    for candidate in common_install_candidates() {
        if let Some((path, version)) = probe_seven_zip(&candidate) {
            return Some(SevenZipInfo {
                path,
                version,
                source: SevenZipSource::CommonDir,
            });
        }
    }

    None
}

#[cfg(windows)]
fn detect_from_windows_registry() -> Vec<PathBuf> {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut results = Vec::new();
    let hives = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER];
    let subkeys = [r"SOFTWARE\7-Zip", r"SOFTWARE\WOW6432Node\7-Zip"];
    let value_names = ["Path64", "Path"];

    for hive in hives {
        let root = RegKey::predef(hive);
        for subkey in subkeys {
            if let Ok(key) = root.open_subkey(subkey) {
                for val_name in value_names {
                    if let Ok(dir) = key.get_value::<String, _>(val_name) {
                        let exe = PathBuf::from(dir).join("7z.exe");
                        if !results.contains(&exe) {
                            results.push(exe);
                        }
                    }
                }
            }
        }
    }
    results
}

fn detect_from_path_env() -> Vec<PathBuf> {
    let mut results = Vec::new();
    #[cfg(windows)]
    let names = ["7z.exe", "7za.exe", "7zz.exe", "NanaZipC.exe"];
    #[cfg(not(windows))]
    let names = ["7zz", "7z", "7za"];

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in names {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    results.push(candidate);
                }
            }
        }
    }
    results
}

fn common_install_candidates() -> Vec<PathBuf> {
    let mut list = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(pf) = std::env::var("ProgramFiles") {
            list.push(PathBuf::from(&pf).join("7-Zip").join("7z.exe"));
        }
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            list.push(PathBuf::from(&pf86).join("7-Zip").join("7z.exe"));
        }
        list.push(PathBuf::from(r"C:\Program Files\7-Zip\7z.exe"));
        list.push(PathBuf::from(r"C:\Program Files (x86)\7-Zip\7z.exe"));
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            list.push(PathBuf::from(&local).join("Programs").join("7-Zip").join("7z.exe"));
            list.push(
                PathBuf::from(&local)
                    .join("Microsoft")
                    .join("WindowsApps")
                    .join("NanaZipC.exe"),
            );
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            list.push(PathBuf::from(&profile).join("scoop").join("shims").join("7z.exe"));
            list.push(
                PathBuf::from(&profile)
                    .join("scoop")
                    .join("apps")
                    .join("7zip")
                    .join("current")
                    .join("7z.exe"),
            );
        }
        if let Ok(pd) = std::env::var("ProgramData") {
            list.push(PathBuf::from(&pd).join("chocolatey").join("bin").join("7z.exe"));
        }
    }
    #[cfg(not(windows))]
    {
        for dir in ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
            for name in ["7zz", "7z", "7za"] {
                list.push(PathBuf::from(dir).join(name));
            }
        }
    }
    list
}
