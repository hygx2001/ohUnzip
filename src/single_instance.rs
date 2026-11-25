use crate::ui::StartupAction;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

const IPC_ADDR: &str = "127.0.0.1:47923";
const HELLO_MAGIC: &str = "OHUNZIP_IPC_V1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    Activate,
    ExtractHere(Vec<PathBuf>),
    ExtractTo(Vec<PathBuf>),
    ExtractDefault(Vec<PathBuf>),
}

impl IpcMessage {
    pub fn from_startup(action: Option<&StartupAction>) -> Self {
        match action {
            None => Self::Activate,
            Some(StartupAction::ExtractHere(p)) => Self::ExtractHere(p.clone()),
            Some(StartupAction::ExtractTo(p)) => Self::ExtractTo(p.clone()),
            Some(StartupAction::ExtractDefault(p)) => Self::ExtractDefault(p.clone()),
        }
    }

    pub fn into_startup(self) -> Option<StartupAction> {
        match self {
            Self::Activate => None,
            Self::ExtractHere(p) => Some(StartupAction::ExtractHere(p)),
            Self::ExtractTo(p) => Some(StartupAction::ExtractTo(p)),
            Self::ExtractDefault(p) => Some(StartupAction::ExtractDefault(p)),
        }
    }
}

pub enum InstanceRole {
    /// Primary instance: owns the IPC listener and receives forwarded actions.
    Primary(Receiver<IpcMessage>),
    /// Secondary instance: already forwarded its action to the primary instance and should exit.
    SecondaryForwarded,
}

/// Atomically elects a single primary instance on localhost.
/// If another instance is already running, forwards `startup_action` to it and returns `SecondaryForwarded`.
pub fn init_single_instance(startup_action: Option<&StartupAction>) -> InstanceRole {
    if let Ok(listener) = TcpListener::bind(IPC_ADDR) {
        let (tx, rx) = mpsc::channel::<IpcMessage>();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    if let Some(payload) = line.trim().strip_prefix(HELLO_MAGIC) {
                        if let Ok(msg) = serde_json::from_str::<IpcMessage>(payload.trim()) {
                            let _ = tx.send(msg);
                            let mut writer = &stream;
                            let _ = writer.write_all(b"OK\n");
                            let _ = writer.flush();
                        }
                    }
                }
            }
        });
        return InstanceRole::Primary(rx);
    }

    // Another instance owns the port: forward our message with brief retries (covers simultaneous Explorer multi-select!)
    let msg = IpcMessage::from_startup(startup_action);
    if let Ok(json) = serde_json::to_string(&msg) {
        let frame = format!("{HELLO_MAGIC} {json}\n");
        for _ in 0..8 {
            if let Ok(mut stream) =
                TcpStream::connect_timeout(&IPC_ADDR.parse().unwrap(), Duration::from_millis(250))
            {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                if stream.write_all(frame.as_bytes()).is_ok() && stream.flush().is_ok() {
                    let mut resp = String::new();
                    let mut reader = BufReader::new(&stream);
                    if reader.read_line(&mut resp).is_ok() && resp.trim() == "OK" {
                        return InstanceRole::SecondaryForwarded;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(60));
        }
    }

    // Fallback: port occupied by an unrelated app, run normally with a dummy channel
    let (_tx, rx) = mpsc::channel();
    InstanceRole::Primary(rx)
}
