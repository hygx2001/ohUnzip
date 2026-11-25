#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
const TARGET_ROOTS: &[&str] = &[
    r"Software\Classes\*\shell\OhUnzip",
    r"Software\Classes\Directory\shell\OhUnzip",
];

pub fn is_registered() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey(TARGET_ROOTS[0]).is_ok()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn register() -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| format!("无法获取程序路径: {e}"))?;
        register_with_exe(&exe)
    }
    #[cfg(not(windows))]
    {
        Err("右键菜单仅支持 Windows".into())
    }
}

#[cfg(windows)]
fn register_with_exe(exe: &Path) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let exe_str = exe.to_string_lossy().to_string();
    let icon_val = format!("{exe_str},0");
    let cmd_here = format!("\"{exe_str}\" --extract-here \"%1\"");
    let cmd_to = format!("\"{exe_str}\" --extract-to \"%1\"");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    for root_path in TARGET_ROOTS {
        let (root_key, _) = hkcu
            .create_subkey(root_path)
            .map_err(|e| format!("写入注册表失败: {e}"))?;
        root_key
            .set_value("MUIVerb", &"OhUnzip")
            .map_err(|e| format!("设置菜单名失败: {e}"))?;
        root_key
            .set_value("SubCommands", &"")
            .map_err(|e| format!("设置子菜单失败: {e}"))?;
        root_key
            .set_value("Icon", &icon_val)
            .map_err(|e| format!("设置图标失败: {e}"))?;

        // Submenu 1: 解压到当前目录
        let (here_key, _) = root_key
            .create_subkey(r"shell\01_extract_here")
            .map_err(|e| format!("创建子菜单失败: {e}"))?;
        here_key
            .set_value("MUIVerb", &"解压到当前目录")
            .map_err(|e| format!("设置子菜单名称失败: {e}"))?;
        let (here_cmd, _) = here_key
            .create_subkey("command")
            .map_err(|e| format!("创建子菜单命令失败: {e}"))?;
        here_cmd
            .set_value("", &cmd_here)
            .map_err(|e| format!("写入命令失败: {e}"))?;

        // Submenu 2: 解压到指定目录
        let (to_key, _) = root_key
            .create_subkey(r"shell\02_extract_to")
            .map_err(|e| format!("创建子菜单失败: {e}"))?;
        to_key
            .set_value("MUIVerb", &"解压到指定目录")
            .map_err(|e| format!("设置子菜单名称失败: {e}"))?;
        let (to_cmd, _) = to_key
            .create_subkey("command")
            .map_err(|e| format!("创建子菜单命令失败: {e}"))?;
        to_cmd
            .set_value("", &cmd_to)
            .map_err(|e| format!("写入命令失败: {e}"))?;
    }

    Ok(())
}

pub fn unregister() -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::io::ErrorKind;
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for root_path in TARGET_ROOTS {
            if let Err(e) = hkcu.delete_subkey_all(root_path) {
                if e.kind() != ErrorKind::NotFound {
                    return Err(format!("移除注册表项失败: {e}"));
                }
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}
