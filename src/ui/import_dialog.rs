use super::OhUnzipApp;
use crate::config::{self, ImportDelimiter};
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, IconName, Sizable as _, StyledExt as _, WindowExt as _,
    button::{Button, ButtonVariant, ButtonVariants as _},
    h_flex,
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
    scroll::ScrollableElement as _,
    tag::Tag,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::collections::HashSet;

pub(super) struct ImportDialogView {
    textarea: Entity<TextareaState>,
    custom_sep_input: Entity<InputState>,
    delimiter: ImportDelimiter,
    existing: HashSet<String>,
    app: WeakEntity<OhUnzipApp>,
    file_error: Option<String>,
    _subscriptions: Vec<Subscription>,
}

impl ImportDialogView {
    pub(super) fn new(
        existing: HashSet<String>,
        app: WeakEntity<OhUnzipApp>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let textarea = cx.new(|cx| {
            TextareaState::new(window, cx)
                .placeholder("粘贴文本或读取文件（支持 TXT / JSON / CSV / 网盘文案）")
        });
        let custom_sep_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("分隔符，如 | 或 \\t")
                .default_value("|")
        });

        let sub_text = cx.subscribe(&textarea, |_, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Change) {
                cx.notify();
            }
        });
        let sub_sep = cx.subscribe(&custom_sep_input, |_, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Change) {
                cx.notify();
            }
        });

        Self {
            textarea,
            custom_sep_input,
            delimiter: ImportDelimiter::Auto,
            existing,
            app,
            file_error: None,
            _subscriptions: vec![sub_text, sub_sep],
        }
    }

    fn load_from_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择密码文件".into()),
        });

        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                if let Some(path) = paths.into_iter().next() {
                    let result = std::fs::read(&path).map(|b| config::decode_text_bytes(&b));
                    let _ = this.update_in(cx, |view, window, cx| match result {
                        Ok(text) => {
                            view.file_error = None;
                            view.textarea.update(cx, |s, cx| {
                                s.set_value(text, window, cx);
                            });
                            cx.notify();
                        }
                        Err(e) => {
                            view.file_error = Some(format!("读取失败: {e}"));
                            cx.notify();
                        }
                    });
                }
            }
        })
        .detach();
    }

    fn paste_from_clipboard(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(item) = cx.read_from_clipboard() {
            if let Some(text) = item.text() {
                self.file_error = None;
                self.textarea.update(cx, |s, cx| {
                    s.set_value(text, window, cx);
                });
                cx.notify();
            }
        }
    }

    fn parsed_items(&self, cx: &Context<Self>) -> Vec<String> {
        let raw = self.textarea.read(cx).value().to_string();
        let custom_sep = self.custom_sep_input.read(cx).value().to_string();
        config::parse_import_passwords(&raw, self.delimiter, &custom_sep)
    }
}

impl Render for ImportDialogView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let parsed = self.parsed_items(cx);
        let total = parsed.len();
        let new_count = parsed
            .iter()
            .filter(|v| !self.existing.contains(v.as_str()))
            .count();
        let dup_count = total - new_count;

        let modes = [
            ImportDelimiter::Auto,
            ImportDelimiter::Newline,
            ImportDelimiter::Comma,
            ImportDelimiter::Semicolon,
            ImportDelimiter::Space,
            ImportDelimiter::Custom,
        ];

        let top_bar = h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .child(
                h_flex()
                    .gap_1p5()
                    .child(
                        Button::new("imp-file")
                            .xsmall()
                            .secondary()
                            .icon(IconName::FolderOpen)
                            .label("读取文件")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.load_from_file(window, cx);
                            })),
                    )
                    .child(
                        Button::new("imp-paste")
                            .xsmall()
                            .secondary()
                            .icon(IconName::Copy)
                            .label("粘贴")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.paste_from_clipboard(window, cx);
                            })),
                    ),
            )
            .child(
                Button::new("imp-clear")
                    .xsmall()
                    .ghost()
                    .label("清空")
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.file_error = None;
                        this.textarea
                            .update(cx, |s, cx| s.set_value("", window, cx));
                        cx.notify();
                    })),
            );

        let mut sep_row = h_flex().w_full().flex_wrap().items_center().gap_1();
        for (i, mode) in modes.into_iter().enumerate() {
            let active = self.delimiter == mode;
            sep_row = sep_row.child(
                Button::new(("imp-sep", i))
                    .xsmall()
                    .with_variant(if active {
                        ButtonVariant::Primary
                    } else {
                        ButtonVariant::Secondary
                    })
                    .label(mode.label())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.delimiter = mode;
                        cx.notify();
                    })),
            );
        }

        let preview_header = h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .child(
                div()
                    .text_xs()
                    .font_medium()
                    .text_color(theme.muted_foreground)
                    .child("导入预览"),
            )
            .child(
                h_flex()
                    .gap_2()
                    .text_xs()
                    .child(
                        div()
                            .text_color(if new_count > 0 {
                                theme.success
                            } else {
                                theme.muted_foreground
                            })
                            .child(format!("新增 {new_count}")),
                    )
                    .when(dup_count > 0, |el| {
                        el.child(
                            div()
                                .text_color(theme.muted_foreground)
                                .child(format!("已有 {dup_count}")),
                        )
                    }),
            );

        let preview_content = if parsed.is_empty() {
            v_flex()
                .flex_1()
                .w_full()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground.opacity(0.75))
                        .child("输入或读取文本后实时预览"),
                )
                .into_any_element()
        } else {
            let existing_ref = &self.existing;
            v_flex()
                .flex_1()
                .min_h_0()
                .w_full()
                .p_2()
                .overflow_y_scrollbar()
                .child(
                    h_flex()
                        .w_full()
                        .flex_wrap()
                        .gap_1p5()
                        .children(parsed.iter().take(200).map(|val| {
                            if existing_ref.contains(val.as_str()) {
                                Tag::secondary()
                                    .small()
                                    .child(format!("{val} (已有)"))
                            } else {
                                Tag::primary().outline().small().child(val.clone())
                            }
                        }))
                        .when(parsed.len() > 200, |el| {
                            el.child(
                                Tag::secondary()
                                    .small()
                                    .child(format!("...共 {total} 条")),
                            )
                        }),
                )
                .into_any_element()
        };

        let preview_box = v_flex()
            .w_full()
            .h(px(124.))
            .rounded(px(8.))
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.2))
            .overflow_hidden()
            .child(preview_content);

        let footer = h_flex()
            .w_full()
            .pt_1()
            .justify_end()
            .gap_2()
            .child(
                Button::new("imp-cancel")
                    .small()
                    .secondary()
                    .label("取消")
                    .on_click(|_, window, cx| {
                        window.close_dialog(cx);
                    }),
            )
            .child(
                Button::new("imp-confirm")
                    .small()
                    .primary()
                    .disabled(new_count == 0)
                    .label(if new_count > 0 {
                        format!("导入 {new_count} 条")
                    } else {
                        "导入".into()
                    })
                    .on_click(cx.listener(move |this, _, window, cx| {
                        let items = this.parsed_items(cx);
                        let _ = this.app.update(cx, |app, cx| {
                            app.import_passwords(items, cx);
                        });
                        window.close_dialog(cx);
                    })),
            );

        v_flex()
            .w_full()
            .gap_2p5()
            .child(top_bar)
            .when_some(self.file_error.as_ref(), |el, err| {
                el.child(div().text_xs().text_color(theme.danger).child(err.clone()))
            })
            .child(Textarea::new(&self.textarea).h(px(116.)))
            .child(sep_row)
            .when(self.delimiter == ImportDelimiter::Custom, |el| {
                el.child(Input::new(&self.custom_sep_input).small())
            })
            .child(preview_header)
            .child(preview_box)
            .child(footer)
    }
}
