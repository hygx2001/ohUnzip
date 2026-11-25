use super::{ExtractTask, OhUnzipApp, TaskStatus};
use crate::detector::ArchiveFormat;
use gpui_kit::component::{
    ActiveTheme as _, Icon, IconName, Sizable as _, StyledExt as _,
    button::{Button, ButtonVariants as _},
    h_flex,
    input::Input,
    popover::Popover,
    scroll::ScrollableElement as _,
    tag::Tag,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

impl OhUnzipApp {
    pub(super) fn render_main(&self, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let has_done = self
            .tasks
            .iter()
            .any(|t| !matches!(t.status, TaskStatus::Running | TaskStatus::Queued));

        // Top section: fixed-height Drop Zone
        let drop_zone = v_flex()
            .id("drop-zone")
            .w_full()
            .h(px(168.))
            .flex_shrink_0()
            .px_4()
            .rounded(px(12.))
            .border_1()
            .border_dashed()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.25))
            .cursor_pointer()
            .items_center()
            .justify_center()
            .gap_2()
            .hover(|s| s.border_color(theme.primary.opacity(0.7)))
            .drag_over::<ExternalPaths>(|style, _, _, cx| {
                style
                    .border_color(cx.theme().primary)
                    .bg(cx.theme().primary.opacity(0.10))
            })
            .on_click(cx.listener(|this, _, window, cx| {
                this.pick_files_to_extract(window, cx);
            }))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, window, cx| {
                this.enqueue_paths(paths.paths().to_vec(), window, cx);
                cx.stop_propagation();
            }))
            .child(
                Icon::new(IconName::Inbox)
                    .size(px(28.))
                    .text_color(theme.primary),
            )
            .child(
                div()
                    .text_sm()
                    .font_medium()
                    .text_color(theme.foreground)
                    .child("拖入压缩包解压，或点击选择文件"),
            );

        // Bottom section: collapsible Log Drawer
        let log_title = if self.tasks.is_empty() {
            "日志".to_string()
        } else if !self.logs_expanded {
            if let Some(latest) = self.tasks.first() {
                let status_hint = match &latest.status {
                    TaskStatus::Queued => "排队中...".into(),
                    TaskStatus::Running => {
                        if latest.progress > 0 {
                            format!("{}%", latest.progress)
                        } else {
                            "解压中...".into()
                        }
                    }
                    TaskStatus::NeedPassword { .. } => "需要密码".into(),
                    TaskStatus::Completed { .. } => "完成".into(),
                    TaskStatus::Cancelled => "已取消".into(),
                    TaskStatus::Failed(_) => "失败".into(),
                };
                format!("日志 ({} · {status_hint})", self.tasks.len())
            } else {
                format!("日志 ({})", self.tasks.len())
            }
        } else {
            format!("日志 ({})", self.tasks.len())
        };

        let log_header = h_flex()
            .w_full()
            .px_3()
            .py_2()
            .items_center()
            .justify_between()
            .when(self.logs_expanded, |el| {
                el.border_b_1().border_color(theme.border.opacity(0.7))
            })
            .child(
                h_flex()
                    .id("toggle-log-drawer")
                    .flex_1()
                    .items_center()
                    .gap_1p5()
                    .cursor_pointer()
                    .text_xs()
                    .font_medium()
                    .text_color(theme.muted_foreground)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.toggle_logs_drawer(window, cx);
                    }))
                    .child(
                        Icon::new(if self.logs_expanded {
                            IconName::ChevronDown
                        } else {
                            IconName::ChevronRight
                        })
                        .size(px(14.)),
                    )
                    .child(log_title),
            )
            .when(has_done && self.logs_expanded, |el| {
                el.child(
                    Button::new("clear-done")
                        .xsmall()
                        .ghost()
                        .label("清空")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.tasks.retain(|t| {
                                matches!(t.status, TaskStatus::Running | TaskStatus::Queued)
                            });
                            cx.notify();
                        })),
                )
            });

        let mut log_panel = v_flex()
            .w_full()
            .rounded(px(12.))
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.16))
            .overflow_hidden()
            .child(log_header);

        if self.logs_expanded {
            let log_body = if self.tasks.is_empty() {
                v_flex()
                    .flex_1()
                    .w_full()
                    .items_center()
                    .justify_center()
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground.opacity(0.75))
                            .child("暂无日志"),
                    )
                    .into_any_element()
            } else {
                v_flex()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .p_3()
                    .gap_2p5()
                    .overflow_y_scrollbar()
                    .children(self.tasks.iter().map(|t| self.render_task_card(t, cx)))
                    .into_any_element()
            };
            log_panel = log_panel.flex_1().min_h_0().child(log_body);
        }

        v_flex()
            .size_full()
            .p_4()
            .gap_3()
            .child(drop_zone)
            .child(log_panel)
    }

    fn render_task_card(&self, task: &ExtractTask, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let task_id = task.id;

        let (status_icon, status_color) = match &task.status {
            TaskStatus::Queued => (IconName::Loader, theme.muted_foreground),
            TaskStatus::Running => (IconName::LoaderCircle, theme.info),
            TaskStatus::NeedPassword { .. } => (IconName::TriangleAlert, theme.warning),
            TaskStatus::Completed { .. } => (IconName::CircleCheck, theme.success),
            TaskStatus::Cancelled => (IconName::Ban, theme.muted_foreground),
            TaskStatus::Failed(_) => (IconName::CircleX, theme.danger),
        };

        let status_summary = match &task.status {
            TaskStatus::Queued => Some(("排队中...".into(), theme.muted_foreground)),
            TaskStatus::Running => {
                let txt = if task.progress > 0 {
                    format!("{} ({}%)", task.stage, task.progress)
                } else {
                    task.stage.clone()
                };
                Some((txt, theme.info))
            }
            TaskStatus::Completed {
                extracted_files,
                max_depth_reached,
                ..
            } => {
                let text = if *max_depth_reached > 0 {
                    format!(
                        "完成 · {extracted_files} 个文件 · {}层",
                        max_depth_reached + 1
                    )
                } else {
                    format!("完成 · {extracted_files} 个文件")
                };
                Some((text, theme.success))
            }
            TaskStatus::NeedPassword { message } => Some((message.clone(), theme.warning)),
            TaskStatus::Cancelled => Some(("已取消".into(), theme.muted_foreground)),
            TaskStatus::Failed(err) => Some((err.clone(), theme.danger)),
        };

        let is_completed_zip = matches!(task.status, TaskStatus::Completed { .. })
            && task.format == Some(ArchiveFormat::Zip);
        let app_weak = cx.entity().downgrade();

        let trick_badges: Vec<&String> = task
            .badges
            .iter()
            .filter(|b| !b.ends_with("压缩包"))
            .collect();

        let mut card = v_flex()
            .w_full()
            .px_3()
            .py_2()
            .gap_1p5()
            .rounded(px(8.))
            .border_1()
            .border_color(theme.border.opacity(0.8))
            .bg(theme.background);

        let top_row = h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .gap_2()
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .items_center()
                    .gap_2()
                    .child(Icon::new(status_icon).size(px(15.)).text_color(status_color))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .font_semibold()
                            .text_color(theme.foreground)
                            .truncate()
                            .child(task.display_name.clone()),
                    ),
            )
            .child(
                h_flex()
                    .items_center()
                    .gap_1()
                    .when(
                        matches!(task.status, TaskStatus::Running | TaskStatus::Queued),
                        |el| {
                            el.child(
                                Button::new(("cancel-task", task_id))
                                    .xsmall()
                                    .ghost()
                                    .icon(IconName::Close)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.cancel_task(task_id, window, cx);
                                    })),
                            )
                        },
                    )
                    .when(is_completed_zip, |el| {
                        let weak_cp = app_weak.clone();
                        el.child(
                            Popover::new(("cp-pop", task_id))
                                .anchor(Anchor::TopRight)
                                .trigger(
                                    Button::new(("cp-btn", task_id))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::ALargeSmall),
                                )
                                .content(move |_, _, cx| {
                                    let t = cx.theme();
                                    let pop = cx.entity();
                                    let w_gbk = weak_cp.clone();
                                    let p_gbk = pop.clone();
                                    let w_jis = weak_cp.clone();
                                    let p_jis = pop.clone();

                                    v_flex()
                                        .w(px(126.))
                                        .gap_0p5()
                                        .child(
                                            div()
                                                .px_2()
                                                .py_0p5()
                                                .text_xs()
                                                .text_color(t.muted_foreground)
                                                .child("乱码重解"),
                                        )
                                        .child(
                                            Button::new(("cp-gbk", task_id))
                                                .xsmall()
                                                .ghost()
                                                .w_full()
                                                .label("按 GBK 重解")
                                                .on_click(move |_, window, cx| {
                                                    p_gbk.update(cx, |s, cx| s.dismiss(window, cx));
                                                    let _ = w_gbk.update(cx, |app, cx| {
                                                        app.retry_task_with_codepage(
                                                            task_id,
                                                            Some(936),
                                                            window,
                                                            cx,
                                                        );
                                                    });
                                                }),
                                        )
                                        .child(
                                            Button::new(("cp-jis", task_id))
                                                .xsmall()
                                                .ghost()
                                                .w_full()
                                                .label("按 Shift-JIS 重解")
                                                .on_click(move |_, window, cx| {
                                                    p_jis.update(cx, |s, cx| s.dismiss(window, cx));
                                                    let _ = w_jis.update(cx, |app, cx| {
                                                        app.retry_task_with_codepage(
                                                            task_id,
                                                            Some(932),
                                                            window,
                                                            cx,
                                                        );
                                                    });
                                                }),
                                        )
                                }),
                        )
                    })
                    .when_some(
                        match &task.status {
                            TaskStatus::Completed { output_dir, .. } => Some(output_dir.clone()),
                            _ => None,
                        },
                        |el, out_dir| {
                            el.child(
                                Button::new(("open-dir", task_id))
                                    .xsmall()
                                    .secondary()
                                    .icon(IconName::FolderOpen)
                                    .on_click(move |_, window, cx| {
                                        Self::open_in_file_manager(&out_dir, window, cx);
                                    }),
                            )
                        },
                    )
                    .when(
                        matches!(task.status, TaskStatus::Failed(_) | TaskStatus::Cancelled),
                        |el| {
                            el.child(
                                Button::new(("retry-fail", task_id))
                                    .xsmall()
                                    .ghost()
                                    .icon(IconName::RotateCw)
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.retry_task(task_id, window, cx);
                                    })),
                            )
                        },
                    )
                    .when(
                        !matches!(task.status, TaskStatus::Running | TaskStatus::Queued),
                        |el| {
                        el.child(
                            Button::new(("rm-task", task_id))
                                .xsmall()
                                .ghost()
                                .icon(IconName::Close)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.tasks.retain(|t| t.id != task_id);
                                    cx.notify();
                                })),
                        )
                    }),
            );

        card = card.child(top_row);

        // Slim real-time progress bar while running
        if matches!(task.status, TaskStatus::Running) {
            let pct = (task.progress as f32 / 100.0).clamp(0.03, 1.0);
            card = card.child(
                div()
                    .ml(px(23.))
                    .h(px(3.))
                    .w_full()
                    .rounded_full()
                    .bg(theme.secondary)
                    .overflow_hidden()
                    .child(
                        div()
                            .h_full()
                            .w(relative(pct))
                            .rounded_full()
                            .bg(theme.primary),
                    ),
            );
        }

        if !trick_badges.is_empty() || !task.matched_passwords.is_empty() {
            let mut row = h_flex().flex_wrap().gap_1().pl(px(23.));
            for b in trick_badges {
                let tag = if b.contains("隐写") {
                    Tag::warning().outline().small().child(b.clone())
                } else {
                    Tag::info().outline().small().child(b.clone())
                };
                row = row.child(tag);
            }
            for pw in &task.matched_passwords {
                row = row.child(Tag::success().outline().small().child(format!("密码: {pw}")));
            }
            card = card.child(row);
        }

        if let Some((text, color)) = status_summary {
            card = card.child(div().pl(px(23.)).text_xs().text_color(color).child(text));
        }

        if matches!(task.status, TaskStatus::NeedPassword { .. }) {
            if let Some(ref pw_input) = task.retry_pw_input {
                card = card.child(
                    h_flex()
                        .pl(px(23.))
                        .pt_1()
                        .gap_1p5()
                        .items_center()
                        .child(div().flex_1().child(Input::new(pw_input).small()))
                        .child(
                            Button::new(("retry-pw", task_id))
                                .small()
                                .primary()
                                .label("重试")
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.retry_task(task_id, window, cx);
                                })),
                        ),
                );
            }
        }

        if !task.logs.is_empty() {
            card = card.child(
                v_flex()
                    .pl(px(23.))
                    .pt_0p5()
                    .gap_0p5()
                    .children(task.logs.iter().map(|line| {
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(line.clone())
                    })),
            );
        }

        card
    }
}
