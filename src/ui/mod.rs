mod import_dialog;
mod main_page;
mod passwords_page;
mod settings_page;

use crate::config::AppConfig;
use crate::context_menu;
use crate::detector::{self, ArchiveFormat};
use crate::extractor::{self, ExtractEvent, OutputTarget};
use crate::notify;
use crate::seven_zip::{self, SevenZipInfo};
use crate::single_instance::IpcMessage;
use crate::theme::{self, THEME_PRESETS};
use crate::trash;
use gpui_kit::component::{
    ActiveTheme as _, Icon, IconName, Sizable as _, StyledExt as _, ThemeMode, WindowExt as _,
    button::{Button, ButtonVariant, ButtonVariants as _},
    h_flex,
    input::{InputEvent, InputState},
    popover::Popover,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

pub(super) const COLLAPSED_HEIGHT: Pixels = px(292.);
pub(super) const DEFAULT_EXPANDED_HEIGHT: Pixels = px(580.);
pub(super) const SUBPAGE_MIN_HEIGHT: Pixels = px(580.);
const MAX_CONCURRENT_TASKS: usize = 3;

#[derive(Debug, Clone)]
pub enum StartupAction {
    ExtractHere(Vec<PathBuf>),
    ExtractTo(Vec<PathBuf>),
    ExtractDefault(Vec<PathBuf>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Page {
    Main,
    Passwords,
    Settings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TaskStatus {
    Queued,
    Running,
    NeedPassword { message: String },
    Completed {
        output_dir: PathBuf,
        extracted_files: usize,
        max_depth_reached: usize,
    },
    Cancelled,
    Failed(String),
}

pub(super) struct ExtractTask {
    pub id: u64,
    pub source_path: PathBuf,
    pub display_name: String,
    pub output_target: OutputTarget,
    pub status: TaskStatus,
    pub stage: String,
    pub progress: u8,
    pub format: Option<ArchiveFormat>,
    pub cancel_flag: Arc<AtomicBool>,
    pub pending_manual_pw: Option<String>,
    pub pending_codepage: Option<u32>,
    pub badges: Vec<String>,
    pub matched_passwords: Vec<String>,
    pub nesting_depth: usize,
    pub logs: Vec<String>,
    pub retry_pw_input: Option<Entity<InputState>>,
    pub retry_pw_sub: Option<Subscription>,
}

pub struct OhUnzipApp {
    pub(super) page: Page,
    pub(super) logs_expanded: bool,
    pub(super) expanded_height: Pixels,
    pub(super) always_on_top: bool,
    pub(super) focus_handle: FocusHandle,
    pub(super) context_menu_registered: bool,
    pub(super) config: AppConfig,
    pub(super) seven_zip: Option<SevenZipInfo>,
    pub(super) tasks: Vec<ExtractTask>,
    pub(super) next_task_id: u64,
    pub(super) toast: Option<(String, bool)>,

    pub(super) new_pw_input: Entity<InputState>,
    pub(super) seven_zip_path_input: Entity<InputState>,
    pub(super) custom_out_dir_input: Entity<InputState>,

    _subscriptions: Vec<Subscription>,
}

impl OhUnzipApp {
    pub fn new(
        startup_action: Option<StartupAction>,
        ipc_rx: Option<Receiver<IpcMessage>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let config = AppConfig::load();
        let seven_zip = seven_zip::detect_seven_zip(&config.seven_zip_path);
        let context_menu_registered = context_menu::is_registered();

        let new_pw_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("输入密码（回车添加 / 自动筛选）")
        });

        let sz_val = config.seven_zip_path.clone();
        let seven_zip_path_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("留空自动检测 7z.exe")
                .default_value(sz_val)
        });

        let out_val = config.custom_output_dir.clone();
        let custom_out_dir_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("输出目录路径")
                .default_value(out_val)
        });

        let sub_pw = cx.subscribe_in(
            &new_pw_input,
            window,
            |this, _, ev: &InputEvent, window, cx| match ev {
                InputEvent::PressEnter { .. } => this.add_password_from_input(window, cx),
                InputEvent::Change => cx.notify(),
                _ => {}
            },
        );

        let sub_sz = cx.subscribe_in(
            &seven_zip_path_input,
            window,
            |this, _, ev: &InputEvent, _, cx| {
                if matches!(ev, InputEvent::PressEnter { .. }) {
                    let val = this.seven_zip_path_input.read(cx).value().to_string();
                    this.apply_seven_zip_path(val, cx);
                }
            },
        );

        let sub_out = cx.subscribe_in(
            &custom_out_dir_input,
            window,
            |this, _, ev: &InputEvent, _, cx| {
                if matches!(ev, InputEvent::PressEnter { .. }) {
                    let val = this
                        .custom_out_dir_input
                        .read(cx)
                        .value()
                        .trim()
                        .to_string();
                    this.config.custom_output_dir = val;
                    this.save_config();
                    this.set_toast("已保存输出目录", false, cx);
                }
            },
        );

        let logs_expanded = config.logs_expanded;
        let focus_handle = cx.focus_handle();

        let mut app = Self {
            page: Page::Main,
            logs_expanded,
            expanded_height: DEFAULT_EXPANDED_HEIGHT,
            always_on_top: false,
            focus_handle,
            context_menu_registered,
            config,
            seven_zip,
            tasks: Vec::new(),
            next_task_id: 1,
            toast: None,
            new_pw_input,
            seven_zip_path_input,
            custom_out_dir_input,
            _subscriptions: vec![sub_pw, sub_sz, sub_out],
        };

        if let Some(rx) = ipc_rx {
            app.start_ipc_listener(rx, window, cx);
        }

        if let Some(action) = startup_action {
            app.handle_startup_action(action, window, cx);
        }

        app
    }

    fn start_ipc_listener(
        &self,
        rx: Receiver<IpcMessage>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        cx.spawn_in(window, async move |this, cx| {
            loop {
                let mut msgs = Vec::new();
                let mut disconnected = false;
                loop {
                    match rx.try_recv() {
                        Ok(m) => msgs.push(m),
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => {
                            disconnected = true;
                            break;
                        }
                    }
                }

                if !msgs.is_empty() {
                    // Brief debounce window (180ms) so multi-selected Explorer right-clicks merge into one batch!
                    cx.background_executor()
                        .timer(Duration::from_millis(180))
                        .await;
                    while let Ok(m) = rx.try_recv() {
                        msgs.push(m);
                    }

                    let mut here_paths = Vec::new();
                    let mut to_paths = Vec::new();
                    let mut default_paths = Vec::new();

                    for msg in msgs {
                        match msg.into_startup() {
                            Some(StartupAction::ExtractHere(p)) => here_paths.extend(p),
                            Some(StartupAction::ExtractTo(p)) => to_paths.extend(p),
                            Some(StartupAction::ExtractDefault(p)) => default_paths.extend(p),
                            None => {}
                        }
                    }

                    let ok = this.update_in(cx, |app, window, cx| {
                        window.activate_window();
                        if !here_paths.is_empty() {
                            app.handle_startup_action(
                                StartupAction::ExtractHere(here_paths),
                                window,
                                cx,
                            );
                        }
                        if !default_paths.is_empty() {
                            app.handle_startup_action(
                                StartupAction::ExtractDefault(default_paths),
                                window,
                                cx,
                            );
                        }
                        if !to_paths.is_empty() {
                            app.handle_startup_action(
                                StartupAction::ExtractTo(to_paths),
                                window,
                                cx,
                            );
                        }
                    });
                    if ok.is_err() {
                        break;
                    }
                }

                if disconnected {
                    break;
                }

                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
            }
        })
        .detach();
    }

    fn handle_startup_action(
        &mut self,
        action: StartupAction,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match action {
            StartupAction::ExtractHere(paths) => {
                self.enqueue_paths_with_target(paths, OutputTarget::SameDir, window, cx);
            }
            StartupAction::ExtractDefault(paths) => {
                self.enqueue_paths_with_target(paths, OutputTarget::ConfigDefault, window, cx);
            }
            StartupAction::ExtractTo(paths) => {
                let receiver = cx.prompt_for_paths(PathPromptOptions {
                    files: false,
                    directories: true,
                    multiple: false,
                    prompt: Some("选择解压目标目录".into()),
                });
                cx.spawn_in(window, async move |this, cx| {
                    if let Ok(Ok(Some(dirs))) = receiver.await {
                        if let Some(target_dir) = dirs.into_iter().next() {
                            let _ = this.update_in(cx, |app, window, cx| {
                                app.enqueue_paths_with_target(
                                    paths,
                                    OutputTarget::SpecificDir(target_dir),
                                    window,
                                    cx,
                                );
                            });
                        }
                    }
                })
                .detach();
            }
        }
    }

    pub(super) fn save_config(&mut self) {
        if let Err(err) = self.config.save() {
            self.toast = Some((err, true));
        }
    }

    pub(super) fn set_toast(
        &mut self,
        msg: impl Into<String>,
        is_error: bool,
        cx: &mut Context<Self>,
    ) {
        self.toast = Some((msg.into(), is_error));
        cx.notify();
    }

    pub(super) fn select_theme(&mut self, theme_id: &str, cx: &mut Context<Self>) {
        self.config.theme = theme_id.to_string();
        self.save_config();
        theme::apply_theme(theme_id, cx);
        cx.notify();
    }

    pub(super) fn toggle_always_on_top(&mut self, cx: &mut Context<Self>) {
        self.always_on_top = !self.always_on_top;
        set_current_thread_window_topmost(self.always_on_top);
        cx.notify();
    }

    pub(super) fn sync_window_height(&self, window: &mut Window) {
        let cur = window.viewport_size();
        let target_h = match self.page {
            Page::Main => {
                if self.logs_expanded {
                    self.expanded_height
                } else {
                    COLLAPSED_HEIGHT
                }
            }
            Page::Passwords | Page::Settings => cur.height.max(SUBPAGE_MIN_HEIGHT),
        };
        if (cur.height - target_h).abs() > px(1.) {
            window.resize(size(cur.width, target_h));
        }
    }

    pub(super) fn toggle_logs_drawer(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.logs_expanded {
            let cur_h = window.viewport_size().height;
            if cur_h > COLLAPSED_HEIGHT + px(40.) {
                self.expanded_height = cur_h;
            }
            self.logs_expanded = false;
        } else {
            self.logs_expanded = true;
        }
        self.config.logs_expanded = self.logs_expanded;
        self.save_config();
        self.sync_window_height(window);
        cx.notify();
    }

    pub(super) fn toggle_page(&mut self, target: Page, window: &mut Window, cx: &mut Context<Self>) {
        if self.page == Page::Main && self.logs_expanded {
            let cur_h = window.viewport_size().height;
            if cur_h > COLLAPSED_HEIGHT + px(40.) {
                self.expanded_height = cur_h;
            }
        }
        self.page = if self.page == target {
            Page::Main
        } else {
            if target == Page::Settings {
                self.context_menu_registered = context_menu::is_registered();
            }
            target
        };
        self.toast = None;
        self.sync_window_height(window);
        cx.notify();
    }

    pub(super) fn enqueue_paths(
        &mut self,
        paths: Vec<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.enqueue_paths_with_target(paths, OutputTarget::ConfigDefault, window, cx);
    }

    pub(super) fn enqueue_paths_with_target(
        &mut self,
        paths: Vec<PathBuf>,
        output_target: OutputTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(ref _sz) = self.seven_zip else {
            self.page = Page::Settings;
            self.sync_window_height(window);
            self.set_toast("未检测到 7z，请指定 7z.exe 路径", true, cx);
            return;
        };

        let mut expanded = Vec::new();
        for p in paths {
            if p.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&p) {
                    let mut dir_files: Vec<PathBuf> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|fp| fp.is_file() && !detector::is_non_first_split_volume(fp))
                        .collect();
                    dir_files.sort();
                    expanded.extend(dir_files);
                }
            } else if p.is_file() && !detector::is_non_first_split_volume(&p) {
                expanded.push(p);
            }
        }

        if expanded.is_empty() {
            return;
        }

        self.page = Page::Main;
        self.sync_window_height(window);
        self.toast = None;

        for file_path in expanded {
            let task_id = self.next_task_id;
            self.next_task_id += 1;
            let display_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("文件")
                .to_string();

            let cancel_flag = Arc::new(AtomicBool::new(false));
            self.tasks.insert(
                0,
                ExtractTask {
                    id: task_id,
                    source_path: file_path,
                    display_name,
                    output_target: output_target.clone(),
                    status: TaskStatus::Queued,
                    stage: "排队中...".into(),
                    progress: 0,
                    format: None,
                    cancel_flag,
                    pending_manual_pw: None,
                    pending_codepage: None,
                    badges: Vec::new(),
                    matched_passwords: Vec::new(),
                    nesting_depth: 0,
                    logs: Vec::new(),
                    retry_pw_input: None,
                    retry_pw_sub: None,
                },
            );
        }

        self.pump_queue(window, cx);
        cx.notify();
    }

    /// Starts queued tasks up to `MAX_CONCURRENT_TASKS` to avoid thrashing CPU/SSD on large batches.
    fn pump_queue(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ref sz) = self.seven_zip else {
            return;
        };
        let sz_path = sz.path.clone();

        let running_count = self
            .tasks
            .iter()
            .filter(|t| matches!(t.status, TaskStatus::Running))
            .count();

        if running_count >= MAX_CONCURRENT_TASKS {
            return;
        }

        let mut slots = MAX_CONCURRENT_TASKS - running_count;
        let mut to_spawn = Vec::new();

        // Pick oldest queued tasks first (tasks are stored newest-first)
        for task in self.tasks.iter_mut().rev() {
            if slots == 0 {
                break;
            }
            if matches!(task.status, TaskStatus::Queued) {
                task.status = TaskStatus::Running;
                task.stage = match task.pending_codepage {
                    Some(cp) => format!("按编码 {cp} 重解中..."),
                    None => "检测中...".into(),
                };
                to_spawn.push((
                    task.id,
                    task.source_path.clone(),
                    task.pending_manual_pw.take(),
                    task.output_target.clone(),
                    task.pending_codepage.take(),
                    task.cancel_flag.clone(),
                ));
                slots -= 1;
            }
        }

        for (task_id, source_path, manual_pw, output_target, codepage, cancel_flag) in to_spawn {
            self.spawn_extraction_task(
                task_id,
                source_path,
                sz_path.clone(),
                manual_pw,
                output_target,
                codepage,
                cancel_flag,
                window,
                cx,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_extraction_task(
        &mut self,
        task_id: u64,
        source_path: PathBuf,
        seven_zip: PathBuf,
        manual_password: Option<String>,
        output_target: OutputTarget,
        codepage: Option<u32>,
        cancel_flag: Arc<AtomicBool>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let config_snapshot = self.config.clone();
        let (tx, rx) = mpsc::channel::<ExtractEvent>();

        std::thread::spawn(move || {
            extractor::run_extraction_job(
                source_path,
                seven_zip,
                config_snapshot,
                manual_password,
                output_target,
                codepage,
                cancel_flag,
                tx,
            );
        });

        cx.spawn_in(window, async move |this, cx| {
            loop {
                let mut batch = Vec::new();
                let mut disconnected = false;
                loop {
                    match rx.try_recv() {
                        Ok(ev) => batch.push(ev),
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => {
                            disconnected = true;
                            break;
                        }
                    }
                }

                if !batch.is_empty() {
                    let ok = this.update_in(cx, |app, window, cx| {
                        app.apply_task_events(task_id, batch, window, cx);
                    });
                    if ok.is_err() {
                        break;
                    }
                }

                if disconnected {
                    break;
                }

                cx.background_executor()
                    .timer(Duration::from_millis(60))
                    .await;
            }
        })
        .detach();
    }

    fn apply_task_events(
        &mut self,
        task_id: u64,
        events: Vec<ExtractEvent>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut hit_passwords = Vec::new();
        let mut needs_pw_input = false;
        let mut notify_msg: Option<(String, String)> = None;

        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            for ev in events {
                match ev {
                    ExtractEvent::Log(line) => task.logs.push(line),
                    ExtractEvent::Stage(stage) => task.stage = stage,
                    ExtractEvent::Progress(pct) => task.progress = pct,
                    ExtractEvent::Format(fmt) => task.format = Some(fmt),
                    ExtractEvent::Badge(badge) => {
                        if !task.badges.contains(&badge) {
                            task.badges.push(badge);
                        }
                    }
                    ExtractEvent::NestingDepth(depth) => {
                        if depth > task.nesting_depth {
                            task.nesting_depth = depth;
                        }
                    }
                    ExtractEvent::PasswordMatched(pw) => {
                        if !task.matched_passwords.contains(&pw) {
                            task.matched_passwords.push(pw.clone());
                        }
                        hit_passwords.push(pw);
                    }
                    ExtractEvent::NeedPassword {
                        archive_path,
                        message,
                    } => {
                        let file_label = archive_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("压缩包");
                        task.stage = "需要密码".into();
                        task.status = TaskStatus::NeedPassword {
                            message: format!("{file_label}: {message}"),
                        };
                        needs_pw_input = task.retry_pw_input.is_none();
                        notify_msg = Some((
                            "OhUnzip 需要密码".into(),
                            format!("{} 需要输入解压密码", task.display_name),
                        ));
                    }
                    ExtractEvent::Completed {
                        output_dir,
                        extracted_files,
                        max_depth_reached,
                    } => {
                        task.stage = "完成".into();
                        task.progress = 100;
                        task.nesting_depth = max_depth_reached;
                        task.status = TaskStatus::Completed {
                            output_dir,
                            extracted_files,
                            max_depth_reached,
                        };
                        notify_msg = Some((
                            "OhUnzip 解压完成".into(),
                            format!("{} · 共 {} 个文件", task.display_name, extracted_files),
                        ));
                    }
                    ExtractEvent::Cancelled => {
                        task.stage = "已取消".into();
                        task.status = TaskStatus::Cancelled;
                        task.logs.push("任务已被用户取消".into());
                    }
                    ExtractEvent::Failed(err) => {
                        task.stage = "失败".into();
                        task.status = TaskStatus::Failed(err);
                    }
                }
            }
        }

        if needs_pw_input {
            let input_entity =
                cx.new(|cx| InputState::new(window, cx).placeholder("输入密码，回车重试"));
            let sub = cx.subscribe_in(
                &input_entity,
                window,
                move |this, _, ev: &InputEvent, window, cx| {
                    if matches!(ev, InputEvent::PressEnter { .. }) {
                        this.retry_task(task_id, window, cx);
                    }
                },
            );
            if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
                task.retry_pw_input = Some(input_entity);
                task.retry_pw_sub = Some(sub);
            }
        }

        if !hit_passwords.is_empty() {
            for pw in hit_passwords {
                self.config.record_password_hit(&pw);
            }
            self.save_config();
        }

        if self.config.notify_on_complete {
            if let Some((title, body)) = notify_msg {
                notify::send_notification(&title, &body);
            }
        }

        self.pump_queue(window, cx);
        cx.notify();
    }

    pub(super) fn cancel_task(&mut self, task_id: u64, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            match task.status {
                TaskStatus::Running => {
                    task.cancel_flag.store(true, Ordering::Relaxed);
                    task.stage = "正在取消...".into();
                }
                TaskStatus::Queued => {
                    task.status = TaskStatus::Cancelled;
                    task.stage = "已取消".into();
                    task.logs.push("已从等待队列取消".into());
                }
                _ => {}
            }
        }
        self.pump_queue(window, cx);
        cx.notify();
    }

    pub(super) fn retry_task(&mut self, task_id: u64, window: &mut Window, cx: &mut Context<Self>) {
        self.retry_task_with_codepage(task_id, None, window, cx);
    }

    pub(super) fn retry_task_with_codepage(
        &mut self,
        task_id: u64,
        codepage: Option<u32>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.seven_zip.is_none() {
            self.page = Page::Settings;
            self.sync_window_height(window);
            return;
        }

        let new_cancel = Arc::new(AtomicBool::new(false));
        let (manual_pw, old_garbled_dir) = {
            let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) else {
                return;
            };
            let old_dir = if codepage.is_some() {
                match &task.status {
                    TaskStatus::Completed { output_dir, .. } => Some(output_dir.clone()),
                    _ => None,
                }
            } else {
                None
            };
            let manual_pw = task
                .retry_pw_input
                .as_ref()
                .map(|inp| inp.read(cx).value().trim().to_string())
                .filter(|s| !s.is_empty());

            task.status = TaskStatus::Queued;
            task.stage = "排队中...".into();
            task.progress = 0;
            task.cancel_flag = new_cancel;
            task.pending_manual_pw = manual_pw.clone();
            task.pending_codepage = codepage;
            task.badges.clear();
            task.matched_passwords.clear();
            task.nesting_depth = 0;
            (manual_pw, old_dir)
        };

        // When re-extracting a garbled ZIP with GBK / Shift-JIS, move the previous garbled output
        // folder safely to the Recycle Bin so the re-extracted folder gets the clean original name.
        if let Some(old_dir) = old_garbled_dir {
            if old_dir.exists() {
                if trash::move_to_trash(&old_dir).is_ok() {
                    if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
                        task.logs.push(format!(
                            "已将原乱码目录移入回收站: {}",
                            old_dir.display()
                        ));
                    }
                }
            }
        }

        if let Some(ref pw) = manual_pw {
            if self.config.add_password(pw, "") {
                self.save_config();
            }
        }

        self.pump_queue(window, cx);
        cx.notify();
    }

    pub(super) fn pick_files_to_extract(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("选择文件".into()),
        });

        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                if !paths.is_empty() {
                    let _ = this.update_in(cx, |app, window, cx| {
                        app.enqueue_paths(paths, window, cx);
                    });
                }
            }
        })
        .detach();
    }

    pub(super) fn open_in_file_manager(path: &Path, window: &mut Window, cx: &mut App) {
        if !path.exists() {
            let path_str = path.display().to_string();
            window.open_alert_dialog(cx, move |alert, _, cx| {
                alert
                    .width(px(360.))
                    .icon(
                        Icon::new(IconName::TriangleAlert)
                            .size(px(28.))
                            .text_color(cx.theme().warning),
                    )
                    .title("目标文件夹不存在")
                    .description(format!("目录可能已被移动或删除：\n{path_str}"))
                    .ok_text("知道了")
            });
            return;
        }

        #[cfg(windows)]
        {
            let _ = std::process::Command::new("explorer").arg(path).spawn();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open").arg(path).spawn();
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let _ = std::process::Command::new("xdg-open").arg(path).spawn();
        }
    }

    fn render_theme_dropdown(&self, cx: &Context<Self>) -> impl IntoElement + use<> {
        let active_id = theme::find_preset(&self.config.theme).id;
        let app_weak = cx.entity().downgrade();

        Popover::new("theme-dropdown")
            .anchor(Anchor::TopRight)
            .trigger(
                Button::new("theme-picker-btn")
                    .xsmall()
                    .ghost()
                    .icon(IconName::Palette),
            )
            .content(move |popover_state, _, cx| {
                let theme = cx.theme();
                let light_presets: Vec<_> = THEME_PRESETS
                    .iter()
                    .filter(|p| p.mode == ThemeMode::Light)
                    .collect();
                let dark_presets: Vec<_> = THEME_PRESETS
                    .iter()
                    .filter(|p| p.mode == ThemeMode::Dark)
                    .collect();

                let popover_entity = cx.entity();
                let _ = popover_state;

                let render_item = |preset: &'static theme::ThemePreset| {
                    let is_active = preset.id == active_id;
                    let weak = app_weak.clone();
                    let pop = popover_entity.clone();
                    let id = preset.id;

                    h_flex()
                        .id(SharedString::from(format!("theme-opt-{id}")))
                        .w_full()
                        .px_2()
                        .py_1p5()
                        .rounded(px(6.))
                        .cursor_pointer()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .bg(if is_active {
                            theme.secondary.opacity(0.75)
                        } else {
                            transparent_black()
                        })
                        .hover(|s| s.bg(theme.secondary.opacity(0.6)))
                        .on_click(move |_, window, cx| {
                            let _ = weak.update(cx, |app, cx| {
                                app.select_theme(id, cx);
                            });
                            pop.update(cx, |st, cx| st.dismiss(window, cx));
                        })
                        .child(
                            h_flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    // Dual-tone swatch (background circle + accent core)
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .size(px(16.))
                                        .rounded_full()
                                        .border_1()
                                        .border_color(theme.border)
                                        .bg(rgb(preset.preview_bg))
                                        .child(
                                            div()
                                                .size(px(8.))
                                                .rounded_full()
                                                .bg(rgb(preset.preview_accent)),
                                        ),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(theme.foreground)
                                        .child(preset.name),
                                ),
                        )
                        .when(is_active, |el| {
                            el.child(
                                Icon::new(IconName::Check)
                                    .size(px(13.))
                                    .text_color(theme.primary),
                            )
                        })
                };

                v_flex()
                    .w(px(148.))
                    .gap_0p5()
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child("浅色"),
                    )
                    .children(light_presets.into_iter().map(render_item))
                    .child(
                        div()
                            .my_1()
                            .h(px(1.))
                            .w_full()
                            .bg(theme.border.opacity(0.7)),
                    )
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child("深色"),
                    )
                    .children(dark_presets.into_iter().map(render_item))
            })
    }

    fn render_header(&self, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let pw_count = self.config.passwords.len();

        let left = match self.page {
            Page::Main => {
                let sz_status = match &self.seven_zip {
                    Some(info) => h_flex()
                        .items_center()
                        .gap_1p5()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(div().size(px(7.)).rounded_full().bg(theme.success))
                        .child(info.version.clone())
                        .into_any_element(),
                    None => Button::new("sz-missing")
                        .xsmall()
                        .danger()
                        .label("未检测到 7z")
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.toggle_page(Page::Settings, window, cx);
                        }))
                        .into_any_element(),
                };
                h_flex()
                    .items_center()
                    .gap_2p5()
                    .child(
                        h_flex()
                            .items_baseline()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(theme.foreground)
                                    .child("OhUnzip"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(concat!("v", env!("CARGO_PKG_VERSION"))),
                            ),
                    )
                    .child(sz_status)
                    .into_any_element()
            }
            Page::Passwords | Page::Settings => {
                let title = if self.page == Page::Passwords {
                    "密码管理"
                } else {
                    "设置"
                };
                h_flex()
                    .items_center()
                    .gap_1p5()
                    .child(
                        Button::new("back-main")
                            .xsmall()
                            .ghost()
                            .icon(IconName::ArrowLeft)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.page = Page::Main;
                                this.toast = None;
                                this.sync_window_height(window);
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .text_color(theme.foreground)
                            .child(title),
                    )
                    .into_any_element()
            }
        };

        let pw_btn = {
            let mut b = Button::new("nav-passwords")
                .xsmall()
                .with_variant(if self.page == Page::Passwords {
                    ButtonVariant::Secondary
                } else {
                    ButtonVariant::Ghost
                })
                .icon(Icon::new(gpui_kit::assets::IconName::KeyRound));
            if pw_count > 0 {
                b = b.label(format!("{pw_count}"));
            }
            b.on_click(cx.listener(|this, _, window, cx| {
                this.toggle_page(Page::Passwords, window, cx);
            }))
        };

        h_flex()
            .w_full()
            .px_4()
            .py_2p5()
            .items_center()
            .justify_between()
            .border_b_1()
            .border_color(theme.border)
            .child(left)
            .child(
                h_flex()
                    .items_center()
                    .gap_1()
                    .child(pw_btn)
                    .child(
                        Button::new("nav-settings")
                            .xsmall()
                            .with_variant(if self.page == Page::Settings {
                                ButtonVariant::Secondary
                            } else {
                                ButtonVariant::Ghost
                            })
                            .icon(IconName::Settings)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.toggle_page(Page::Settings, window, cx);
                            })),
                    )
                    .child(
                        Button::new("pin-window")
                            .xsmall()
                            .with_variant(if self.always_on_top {
                                ButtonVariant::Secondary
                            } else {
                                ButtonVariant::Ghost
                            })
                            .icon(Icon::new(if self.always_on_top {
                                gpui_kit::assets::IconName::Pin
                            } else {
                                gpui_kit::assets::IconName::PinOff
                            }))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.toggle_always_on_top(cx);
                            })),
                    )
                    .child(self.render_theme_dropdown(cx)),
            )
    }

    fn render_toast(&self, cx: &Context<Self>) -> Option<AnyElement> {
        let (msg, is_error) = self.toast.as_ref()?;
        let theme = cx.theme();
        let (bg, fg) = if *is_error {
            (theme.danger.opacity(0.12), theme.danger)
        } else {
            (theme.secondary.opacity(0.7), theme.foreground)
        };

        Some(
            h_flex()
                .mx_4()
                .mt_2()
                .px_3()
                .py_1p5()
                .rounded(px(7.))
                .bg(bg)
                .items_center()
                .justify_between()
                .text_xs()
                .text_color(fg)
                .child(msg.clone())
                .child(
                    Button::new("dismiss-toast")
                        .xsmall()
                        .ghost()
                        .icon(IconName::Close)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.toast = None;
                            cx.notify();
                        })),
                )
                .into_any_element(),
        )
    }
}

impl Render for OhUnzipApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let header = self.render_header(cx);
        let toast = self.render_toast(cx);
        let body = match self.page {
            Page::Main => self.render_main(cx).into_any_element(),
            Page::Passwords => self.render_passwords(cx).into_any_element(),
            Page::Settings => self.render_settings(cx).into_any_element(),
        };
        let bg = cx.theme().background;
        let fg = cx.theme().foreground;

        v_flex()
            .id("oh-unzip-root")
            .track_focus(&self.focus_handle)
            .size_full()
            .bg(bg)
            .text_color(fg)
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| {
                if ev.keystroke.key == "escape"
                    && this.page != Page::Main
                    && !window.has_active_dialog(cx)
                {
                    this.page = Page::Main;
                    this.toast = None;
                    this.sync_window_height(window);
                    cx.notify();
                }
            }))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, window, cx| {
                this.enqueue_paths(paths.paths().to_vec(), window, cx);
                cx.stop_propagation();
            }))
            .child(header)
            .children(toast)
            .child(div().flex_1().min_h_0().w_full().child(body))
    }
}

#[cfg(windows)]
fn set_current_thread_window_topmost(topmost: bool) {
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThreadId() -> u32;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn EnumThreadWindows(
            dw_thread_id: u32,
            lpfn: unsafe extern "system" fn(*mut c_void, isize) -> i32,
            lparam: isize,
        ) -> i32;
        fn SetWindowPos(
            hwnd: *mut c_void,
            hwnd_insert_after: isize,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            uflags: u32,
        ) -> i32;
    }

    const HWND_TOPMOST: isize = -1;
    const HWND_NOTOPMOST: isize = -2;
    const SWP_NOSIZE: u32 = 0x0001;
    const SWP_NOMOVE: u32 = 0x0002;
    const SWP_NOACTIVATE: u32 = 0x0010;

    unsafe extern "system" fn callback(hwnd: *mut c_void, lparam: isize) -> i32 {
        unsafe {
            SetWindowPos(
                hwnd,
                lparam,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }
        1
    }

    let insert_after = if topmost {
        HWND_TOPMOST
    } else {
        HWND_NOTOPMOST
    };
    unsafe {
        EnumThreadWindows(GetCurrentThreadId(), callback, insert_after);
    }
}

#[cfg(not(windows))]
fn set_current_thread_window_topmost(_topmost: bool) {}
