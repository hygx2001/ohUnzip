const ICON_PNG_BYTES: &[u8] = include_bytes!("../assets/icon.png");

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\n', " ")
}

#[cfg(windows)]
fn ensure_aumid_registered() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let icon_path = dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("OhUnzip")
            .join("icon.png");

        if let Some(parent) = icon_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&icon_path, ICON_PNG_BYTES);

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok((key, _)) = hkcu.create_subkey(r"Software\Classes\AppUserModelId\OhUnzip") {
            let _ = key.set_value("DisplayName", &"OhUnzip");
            let _ = key.set_value("IconUri", &icon_path.to_string_lossy().to_string());
        }
    });
}

/// Sends a lightweight, non-blocking Windows Toast notification with our registered AUMID & icon.
pub fn send_notification(title: &str, body: &str) {
    #[cfg(windows)]
    {
        ensure_aumid_registered();
        let title = xml_escape(title);
        let body = xml_escape(body);
        std::thread::spawn(move || {
            use std::os::windows::process::CommandExt;
            use std::process::{Command, Stdio};
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;

            let script = format!(
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; \
                 [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null; \
                 $xml = [Windows.Data.Xml.Dom.XmlDocument]::new(); \
                 $xml.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>{title}</text><text>{body}</text></binding></visual></toast>'); \
                 $toast = [Windows.UI.Notifications.ToastNotification]::new($xml); \
                 [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('OhUnzip').Show($toast)"
            );

            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    &script,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        });
    }
    #[cfg(not(windows))]
    {
        let _ = (title, body);
    }
}
