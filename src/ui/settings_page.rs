use super::OhUnzipApp;
use crate::config::{AppConfig, OutputMode};
use crate::context_menu;
use crate::seven_zip;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, IconName, Sizable as _, StyledExt as _,
    button::{Button, ButtonVariant, ButtonVariants as _},
    h_flex,
    input::Input,
    scroll::ScrollableElement as _,
    switch::Switch,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

impl OhUnzipApp {
    pub(super) fn browse_seven_zip(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择 7z.exe".into()),
        });

        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                if let Some(path) = paths.into_iter().next() {
                    let path_str = path.to_string_lossy().to_string();
                    let _ = this.update_in(cx, |app, window, cx| {
                        app.seven_zip_path_input.update(cx, |state, cx| {
                            state.set_value(path_str.clone(), window, cx);
                        });
                        app.apply_seven_zip_path(path_str, cx);
                    });
                }
            }
        })
        .detach();
    }

    pub(super) fn browse_custom_output_dir(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择输出目录".into()),
        });

        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = receiver.await {
                if let Some(path) = paths.into_iter().next() {
                    let path_str = path.to_string_lossy().to_string();
                    let _ = this.update_in(cx, |app, window, cx| {
                        app.custom_out_dir_input.update(cx, |state, cx| {
                            state.set_value(path_str.clone(), window, cx);
                        });
                        app.config.custom_output_dir = path_str;
                        app.config.output_mode = OutputMode::CustomDir;
                        app.save_config();
                        app.set_toast("已更新输出目录", false, cx);
                    });
                }
            }
        })
        .detach();
    }

    pub(super) fn apply_seven_zip_path(&mut self, raw_path: String, cx: &mut Context<Self>) {
        let trimmed = raw_path.trim().to_string();
        self.config.seven_zip_path = trimmed.clone();
        self.seven_zip = seven_zip::detect_seven_zip(&trimmed);
        self.save_config();
        match &self.seven_zip {
            Some(info) => self.set_toast(format!("已连接 {}", info.version), false, cx),
            None => self.set_toast("无效的 7z 路径", true, cx),
        }
    }

    pub(super) fn render_settings(&self, cx: &Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let is_custom = self.config.output_mode == OutputMode::CustomDir;

        v_flex()
            .size_full()
            .p_4()
            .gap_4()
            .overflow_y_scrollbar()
            // 7-Zip path
            .child(
                v_flex()
                    .gap_1p5()
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(div().text_xs().font_semibold().child("7-Zip 路径"))
                            .when_some(self.seven_zip.as_ref(), |el, info| {
                                el.child(
                                    div()
                                        .text_xs()
                                        .text_color(theme.muted_foreground)
                                        .child(info.path.display().to_string()),
                                )
                            }),
                    )
                    .child(
                        h_flex()
                            .gap_1p5()
                            .items_center()
                            .child(
                                div()
                                    .flex_1()
                                    .child(Input::new(&self.seven_zip_path_input).small()),
                            )
                            .child(
                                Button::new("browse-7z")
                                    .small()
                                    .secondary()
                                    .icon(IconName::FolderOpen)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.browse_seven_zip(window, cx);
                                    })),
                            )
                            .child(
                                Button::new("auto-7z")
                                    .small()
                                    .ghost()
                                    .label("自动")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.seven_zip_path_input
                                            .update(cx, |s, cx| s.set_value("", window, cx));
                                        this.apply_seven_zip_path(String::new(), cx);
                                    })),
                            ),
                    ),
            )
            // Output directory
            .child(
                v_flex()
                    .gap_1p5()
                    .child(div().text_xs().font_semibold().child("输出目录"))
                    .child(
                        h_flex()
                            .gap_1p5()
                            .child(
                                Button::new("out-same")
                                    .small()
                                    .with_variant(if !is_custom {
                                        ButtonVariant::Primary
                                    } else {
                                        ButtonVariant::Secondary
                                    })
                                    .label("原文件同级")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.config.output_mode = OutputMode::SameDir;
                                        this.save_config();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("out-custom")
                                    .small()
                                    .with_variant(if is_custom {
                                        ButtonVariant::Primary
                                    } else {
                                        ButtonVariant::Secondary
                                    })
                                    .label("指定目录")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.config.output_mode = OutputMode::CustomDir;
                                        this.save_config();
                                        cx.notify();
                                    })),
                            ),
                    )
                    .when(is_custom, |el| {
                        el.child(
                            h_flex()
                                .gap_1p5()
                                .items_center()
                                .child(
                                    div()
                                        .flex_1()
                                        .child(Input::new(&self.custom_out_dir_input).small()),
                                )
                                .child(
                                    Button::new("browse-out")
                                        .small()
                                        .secondary()
                                        .icon(IconName::FolderOpen)
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.browse_custom_output_dir(window, cx);
                                        })),
                                ),
                        )
                    }),
            )
            // Compact toggles
            .child(
                v_flex()
                    .gap_2p5()
                    .pt_2()
                    .border_t_1()
                    .border_color(theme.border)
                    .child(self.toggle_row(
                        "opt-context-menu",
                        "右键菜单",
                        self.context_menu_registered,
                        cx.listener(|this, enable: &bool, _, cx| {
                            let res = if *enable {
                                context_menu::register()
                            } else {
                                context_menu::unregister()
                            };
                            match res {
                                Ok(()) => {
                                    this.context_menu_registered = *enable;
                                    this.set_toast(
                                        if *enable {
                                            "已注册到右键菜单"
                                        } else {
                                            "已移除右键菜单"
                                        },
                                        false,
                                        cx,
                                    );
                                }
                                Err(err) => {
                                    this.context_menu_registered = context_menu::is_registered();
                                    this.set_toast(err, true, cx);
                                }
                            }
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-disguised",
                        "处理后缀",
                        self.config.detect_disguised,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.detect_disguised = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-polyglot",
                        "隐写图种",
                        self.config.detect_polyglot,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.detect_polyglot = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-skip-office",
                        "跳过组件",
                        self.config.skip_office_zip,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.skip_office_zip = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-clean-mid",
                        "清理中间包",
                        self.config.clean_intermediate,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.clean_intermediate = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-fname-hint",
                        "文件名密码",
                        self.config.extract_filename_password_hint,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.extract_filename_password_hint = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-trash-src",
                        "解完移回收站",
                        self.config.move_source_to_trash,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.move_source_to_trash = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(self.toggle_row(
                        "opt-notify",
                        "完成系统通知",
                        self.config.notify_on_complete,
                        cx.listener(|this, v: &bool, _, cx| {
                            this.config.notify_on_complete = *v;
                            this.save_config();
                            cx.notify();
                        }),
                        cx,
                    ))
                    .child(
                        h_flex()
                            .w_full()
                            .items_center()
                            .justify_between()
                            .child(div().text_sm().text_color(theme.foreground).child("嵌套层数"))
                            .child(
                                h_flex()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        Button::new("depth-dec")
                                            .xsmall()
                                            .secondary()
                                            .icon(IconName::Minus)
                                            .disabled(self.config.max_depth <= 1)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                if this.config.max_depth > 1 {
                                                    this.config.max_depth -= 1;
                                                    this.save_config();
                                                    cx.notify();
                                                }
                                            })),
                                    )
                                    .child(
                                        div()
                                            .w(px(36.))
                                            .text_center()
                                            .text_xs()
                                            .child(format!("{}", self.config.max_depth)),
                                    )
                                    .child(
                                        Button::new("depth-inc")
                                            .xsmall()
                                            .secondary()
                                            .icon(IconName::Plus)
                                            .disabled(self.config.max_depth >= 20)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                if this.config.max_depth < 20 {
                                                    this.config.max_depth += 1;
                                                    this.save_config();
                                                    cx.notify();
                                                }
                                            })),
                                    ),
                            ),
                    ),
            )
            .when(AppConfig::is_portable_mode(), |el| {
                el.child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format!(
                            "便携模式 · {}",
                            AppConfig::config_file_path().display()
                        )),
                )
            })
    }

    fn toggle_row(
        &self,
        id: &'static str,
        title: &'static str,
        checked: bool,
        on_change: impl Fn(&bool, &mut Window, &mut App) + 'static,
        cx: &Context<Self>,
    ) -> Div {
        let theme = cx.theme();
        h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .child(div().text_sm().text_color(theme.foreground).child(title))
            .child(Switch::new(id).checked(checked).on_change(on_change))
    }
}
