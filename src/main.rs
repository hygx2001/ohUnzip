#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod context_menu;
mod detector;
mod extractor;
mod notify;
mod seven_zip;
mod single_instance;
mod stego;
mod theme;
mod trash;
mod ui;

use gpui_kit::*;
use single_instance::InstanceRole;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use ui::{OhUnzipApp, StartupAction};

fn parse_startup_action() -> Option<StartupAction> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return None;
    }

    match args[0].as_str() {
        "--extract-here" => {
            let paths: Vec<PathBuf> = args[1..].iter().map(PathBuf::from).collect();
            if paths.is_empty() {
                None
            } else {
                Some(StartupAction::ExtractHere(paths))
            }
        }
        "--extract-to" => {
            let paths: Vec<PathBuf> = args[1..].iter().map(PathBuf::from).collect();
            if paths.is_empty() {
                None
            } else {
                Some(StartupAction::ExtractTo(paths))
            }
        }
        _ => {
            let paths: Vec<PathBuf> = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .map(PathBuf::from)
                .collect();
            if paths.is_empty() {
                None
            } else {
                Some(StartupAction::ExtractDefault(paths))
            }
        }
    }
}

fn main() {
    let startup_action = parse_startup_action();

    let ipc_rx = match single_instance::init_single_instance(startup_action.as_ref()) {
        InstanceRole::Primary(rx) => Arc::new(Mutex::new(Some(rx))),
        InstanceRole::SecondaryForwarded => return,
    };

    application()
        .with_assets(assets::AllAssets)
        .run(move |cx| {
            init(cx);

            let initial_cfg = config::AppConfig::load();
            theme::apply_theme(&initial_cfg.theme, cx);

            let init_height = if initial_cfg.logs_expanded {
                px(580.)
            } else {
                px(292.)
            };
            let bounds = Bounds::centered(None, size(px(500.), init_height), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(400.), px(280.))),
                titlebar: Some(TitlebarOptions {
                    title: Some(concat!("OhUnzip v", env!("CARGO_PKG_VERSION")).into()),
                    ..Default::default()
                }),
                ..Default::default()
            };

            let action = startup_action.clone();
            let rx_holder = ipc_rx.clone();
            open_window(options, cx, |window, cx| {
                let rx = rx_holder.lock().ok().and_then(|mut g| g.take());
                cx.new(|cx| OhUnzipApp::new(action, rx, window, cx))
            })
            .expect("Failed to open OhUnzip window");
        });
}
