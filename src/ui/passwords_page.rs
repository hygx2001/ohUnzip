use super::OhUnzipApp;
use super::import_dialog::ImportDialogView;
use crate::config::ExportFormat;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, Sizable as _, StyledExt as _,
    WindowExt as _,
    button::{Button, ButtonVariant, ButtonVariants as _},
    h_flex,
    input::Input,
    scroll::ScrollableElement as _,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::collections::HashSet;
use std::path::PathBuf;

impl OhUnzipApp {
    pub(super) fn add_password_from_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let raw = self.new_pw_input.read(cx).value().to_string();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed.contains('\n') {
            self.config.add_passwords_bulk(trimmed);
        } else {
            self.config.add_password(trimmed, "");
        }
        self.save_config();
        self.new_pw_input
            .update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }

    pub(super) fn import_passwords(&mut self, items: Vec<String>, cx: &mut Context<Self>) {
        let added = self.config.add_passwords_list(&items);
        self.save_config();
        self.set_toast(format!("已导入 {added} 条新密码"), false, cx);
    }

    pub(super) fn open_import_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let existing: HashSet<String> = self
            .config
            .passwords
            .iter()
            .map(|p| p.value.clone())
            .collect();
        let app_weak = cx.entity().downgrade();
        let import_view = cx.new(|cx| ImportDialogView::new(existing, app_weak, window, cx));

        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .title("导入密码")
                .width(px(452.))
                .overlay_closable(true)
                .child(import_view.clone())
        });
    }

    pub(super) fn open_export_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.config.passwords.is_empty() {
            self.set_toast("暂无密码可导出", true, cx);
            return;
        }
        let app_weak = cx.entity().downgrade();
        let count = self.config.passwords.len();

        window.open_dialog(cx, move |dialog, _, cx| {
            let theme = cx.theme();
            let weak_txt = app_weak.clone();
            let weak_json = app_weak.clone();
            let weak_csv = app_weak.clone();
            let weak_copy = app_weak.clone();

            dialog
                .title(format!("导出密码 ({count} 条)"))
                .width(px(360.))
                .overlay_closable(true)
                .child(
                    v_flex()
                        .w_full()
                        .gap_2()
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .child(
                                    Button::new("exp-txt")
                                        .flex_1()
                                        .secondary()
                                        .label("TXT")
                                        .on_click(move |_, window, cx| {
                                            window.close_dialog(cx);
                                            let _ = weak_txt.update(cx, |app, cx| {
                                                app.export_passwords_to_file(
                                                    ExportFormat::Txt,
                                                    window,
                                                    cx,
                                                );
                                            });
                                        }),
                                )
                                .child(
                                    Button::new("exp-json")
                                        .flex_1()
                                        .secondary()
                                        .label("JSON")
                                        .on_click(move |_, window, cx| {
                                            window.close_dialog(cx);
                                            let _ = weak_json.update(cx, |app, cx| {
                                                app.export_passwords_to_file(
                                                    ExportFormat::Json,
                                                    window,
                                                    cx,
                                                );
                                            });
                                        }),
                                )
                                .child(
                                    Button::new("exp-csv")
                                        .flex_1()
                                        .secondary()
                                        .label("CSV")
                                        .on_click(move |_, window, cx| {
                                            window.close_dialog(cx);
                                            let _ = weak_csv.update(cx, |app, cx| {
                                                app.export_passwords_to_file(
                                                    ExportFormat::Csv,
                                                    window,
                                                    cx,
                                                );
                                            });
                                        }),
                                ),
                        )
                        .child(
                            Button::new("exp-copy-all")
                                .w_full()
                                .ghost()
                                .icon(IconName::Copy)
                                .label("复制全部明文到剪贴板")
                                .on_click(move |_, window, cx| {
                                    window.close_dialog(cx);
                                    let _ = weak_copy.update(cx, |app, cx| {
                                        let text = app.config.export_passwords(ExportFormat::Txt);
                                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                                        app.set_toast(
                                            format!("已复制 {} 条密码", app.config.passwords.len()),
                                            false,
                                            cx,
                                        );
                                    });
                                }),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child("TXT 每行一个 · JSON 含完整记录 · CSV 表格格式"),
                        ),
                )
        });
    }

    fn export_passwords_to_file(
        &mut self,
        format: ExportFormat,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let content = self.config.export_passwords(format);
        let default_dir = dirs::desktop_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let receiver = cx.prompt_for_new_path(&default_dir, Some(format.suggested_filename()));

        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(path))) = receiver.await {
                let res = std::fs::write(&path, content);
                let _ = this.update_in(cx, |app, _, cx| match res {
                    Ok(()) => app.set_toast(
                        format!(
                            "已导出到 {}",
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("文件")
                        ),
                        false,
                        cx,
                    ),
                    Err(e) => app.set_toast(format!("导出失败: {e}"), true, cx),
                });
            }
        })
        .detach();
    }

    fn open_clear_all_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let count = self.config.passwords.len();
        if count == 0 {
            return;
        }
        let app_weak = cx.entity().downgrade();
        window.open_alert_dialog(cx, move |alert, _, cx| {
            let weak = app_weak.clone();
            alert
                .confirm()
                .width(px(340.))
                .icon(
                    Icon::new(IconName::TriangleAlert)
                        .size(px(26.))
                        .text_color(cx.theme().danger),
                )
                .title("清空全部密码")
                .description(format!("确定要删除已保存的 {count} 条密码吗？"))
                .ok_text("清空")
                .ok_variant(ButtonVariant::Danger)
                .cancel_text("取消")
                .on_ok(move |_, _, cx| {
                    let _ = weak.update(cx, |app, cx| {
                        app.config.passwords.clear();
                        app.save_config();
                        app.set_toast("已清空全部密码", false, cx);
                    });
                    true
                })
        });
    }

    pub(super) fn render_passwords(&self, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let count = self.config.passwords.len();
        let filter_query = self.new_pw_input.read(cx).value().trim().to_lowercase();
        let is_filtering = !filter_query.is_empty();

        let visible_entries: Vec<(usize, &crate::config::PasswordEntry)> = self
            .config
            .passwords
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                !is_filtering
                    || entry.value.to_lowercase().contains(&filter_query)
                    || entry.note.to_lowercase().contains(&filter_query)
            })
            .collect();

        let add_row = h_flex()
            .w_full()
            .gap_2()
            .items_center()
            .child(div().flex_1().child(Input::new(&self.new_pw_input).large()))
            .child(
                Button::new("add-pw")
                    .large()
                    .primary()
                    .icon(IconName::Plus)
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.add_password_from_input(window, cx);
                    })),
            );

        let count_text = if is_filtering {
            format!("匹配 {} / {} 条", visible_entries.len(), count)
        } else {
            format!("共 {count} 条")
        };

        let action_bar = h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(count_text),
            )
            .child(
                h_flex()
                    .items_center()
                    .gap_1()
                    .when(count > 1, |el| {
                        el.child(
                            Button::new("pw-sort-hits")
                                .xsmall()
                                .ghost()
                                .icon(IconName::SortDescending)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.config
                                        .passwords
                                        .sort_by(|a, b| b.use_count.cmp(&a.use_count));
                                    this.save_config();
                                    this.set_toast("已按命中次数排序", false, cx);
                                })),
                        )
                    })
                    .child(
                        Button::new("pw-import")
                            .xsmall()
                            .secondary()
                            .icon(Icon::new(gpui_kit::assets::IconName::Download))
                            .label("导入")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_import_dialog(window, cx);
                            })),
                    )
                    .child(
                        Button::new("pw-export")
                            .xsmall()
                            .secondary()
                            .icon(Icon::new(gpui_kit::assets::IconName::Upload))
                            .label("导出")
                            .disabled(count == 0)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_export_dialog(window, cx);
                            })),
                    )
                    .when(count > 0, |el| {
                        el.child(
                            Button::new("pw-clear-all")
                                .xsmall()
                                .ghost()
                                .icon(Icon::new(IconName::Delete).text_color(theme.danger))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.open_clear_all_dialog(window, cx);
                                })),
                        )
                    }),
            );

        let list = if visible_entries.is_empty() {
            v_flex()
                .flex_1()
                .w_full()
                .py_12()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(if is_filtering {
                            "无匹配密码，按回车可直接添加"
                        } else {
                            "暂无密码"
                        }),
                )
                .into_any_element()
        } else {
            v_flex()
                .w_full()
                .gap_2()
                .children(visible_entries.into_iter().map(|(idx, entry)| {
                    let val = entry.value.clone();
                    let copy_val = entry.value.clone();
                    let hits = entry.use_count;
                    let is_first = idx == 0;
                    let is_last = idx + 1 == count;

                    h_flex()
                        .w_full()
                        .h(px(40.))
                        .px_3()
                        .rounded(px(8.))
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.background)
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .child(
                            h_flex()
                                .flex_1()
                                .min_w_0()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_medium()
                                        .text_color(theme.foreground)
                                        .truncate()
                                        .child(val),
                                )
                                .when(hits > 0, |el| {
                                    el.child(
                                        div()
                                            .text_xs()
                                            .text_color(theme.muted_foreground)
                                            .child(format!("×{hits}")),
                                    )
                                }),
                        )
                        .child(
                            h_flex()
                                .items_center()
                                .gap_0p5()
                                .child(
                                    Button::new(("copy-pw", idx))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::Copy)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                copy_val.clone(),
                                            ));
                                            this.set_toast(
                                                format!("已复制: {copy_val}"),
                                                false,
                                                cx,
                                            );
                                        })),
                                )
                                .child(
                                    Button::new(("up-pw", idx))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::ArrowUp)
                                        .disabled(is_first)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.config.move_password_up(idx);
                                            this.save_config();
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new(("down-pw", idx))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::ArrowDown)
                                        .disabled(is_last)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.config.move_password_down(idx);
                                            this.save_config();
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new(("del-pw", idx))
                                        .xsmall()
                                        .ghost()
                                        .icon(IconName::Close)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.config.remove_password(idx);
                                            this.save_config();
                                            cx.notify();
                                        })),
                                ),
                        )
                }))
                .into_any_element()
        };

        v_flex()
            .size_full()
            .p_4()
            .gap_3()
            .overflow_y_scrollbar()
            .child(add_row)
            .child(action_bar)
            .child(list)
    }
}
