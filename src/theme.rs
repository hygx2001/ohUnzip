use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, Hsla, rgb};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemePreset {
    pub id: &'static str,
    pub name: &'static str,
    pub mode: ThemeMode,
    /// Preview background swatch hex
    pub preview_bg: u32,
    /// Preview accent/primary swatch hex
    pub preview_accent: u32,
}

pub const THEME_PRESETS: &[ThemePreset] = &[
    ThemePreset {
        id: "light",
        name: "极简白",
        mode: ThemeMode::Light,
        preview_bg: 0xFFFFFF,
        preview_accent: 0x171717,
    },
    ThemePreset {
        id: "ocean",
        name: "晴空蓝",
        mode: ThemeMode::Light,
        preview_bg: 0xF8FAFC,
        preview_accent: 0x2563EB,
    },
    ThemePreset {
        id: "mint",
        name: "青瓷绿",
        mode: ThemeMode::Light,
        preview_bg: 0xF4FBF7,
        preview_accent: 0x059669,
    },
    ThemePreset {
        id: "warm",
        name: "暖纸米",
        mode: ThemeMode::Light,
        preview_bg: 0xFAF7F2,
        preview_accent: 0xD97706,
    },
    ThemePreset {
        id: "dark",
        name: "暗夜黑",
        mode: ThemeMode::Dark,
        preview_bg: 0x121212,
        preview_accent: 0xF5F5F5,
    },
    ThemePreset {
        id: "nord",
        name: "极光蓝",
        mode: ThemeMode::Dark,
        preview_bg: 0x1B2230,
        preview_accent: 0x60A5FA,
    },
    ThemePreset {
        id: "violet",
        name: "暮色紫",
        mode: ThemeMode::Dark,
        preview_bg: 0x1B1928,
        preview_accent: 0xA78BFA,
    },
    ThemePreset {
        id: "forest",
        name: "松林暗",
        mode: ThemeMode::Dark,
        preview_bg: 0x131C19,
        preview_accent: 0x34D399,
    },
];

pub fn find_preset(id: &str) -> &'static ThemePreset {
    THEME_PRESETS
        .iter()
        .find(|p| p.id == id)
        .unwrap_or(&THEME_PRESETS[0])
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

pub fn apply_theme(id: &str, cx: &mut App) {
    let preset = find_preset(id);
    // Reset to clean Light/Dark base first so untouched semantic tokens stay harmonious
    Theme::change(preset.mode, None, cx);

    match preset.id {
        "light" | "dark" => {
            // Keep GPUI Kit's crisp default Light / Dark palette as-is
        }
        "ocean" => Theme::update(cx, |t| {
            t.colors.background = c(0xF8FAFC);
            t.colors.foreground = c(0x0F172A);
            t.colors.border = c(0xCBD5E1);
            t.colors.input = c(0xCBD5E1);
            t.colors.secondary = c(0xE2E8F0);
            t.colors.secondary_hover = c(0xCBD5E1);
            t.colors.secondary_active = c(0xCBD5E1);
            t.colors.secondary_foreground = c(0x0F172A);
            t.colors.muted = c(0xF1F5F9);
            t.colors.muted_foreground = c(0x64748B);
            t.colors.popover = c(0xFFFFFF);
            t.colors.popover_foreground = c(0x0F172A);
            t.colors.primary = c(0x2563EB);
            t.colors.primary_hover = c(0x1D4ED8);
            t.colors.primary_active = c(0x1E40AF);
            t.colors.primary_foreground = c(0xFFFFFF);
            t.colors.ring = c(0x60A5FA);
            sync_button_colors(t);
        }),
        "mint" => Theme::update(cx, |t| {
            t.colors.background = c(0xF4FBF7);
            t.colors.foreground = c(0x062C22);
            t.colors.border = c(0xCBE7D8);
            t.colors.input = c(0xCBE7D8);
            t.colors.secondary = c(0xE1F3EA);
            t.colors.secondary_hover = c(0xCEEADB);
            t.colors.secondary_active = c(0xBCE0CE);
            t.colors.secondary_foreground = c(0x064E3B);
            t.colors.muted = c(0xEAF7F0);
            t.colors.muted_foreground = c(0x4B7566);
            t.colors.popover = c(0xFFFFFF);
            t.colors.popover_foreground = c(0x062C22);
            t.colors.primary = c(0x059669);
            t.colors.primary_hover = c(0x047857);
            t.colors.primary_active = c(0x065F46);
            t.colors.primary_foreground = c(0xFFFFFF);
            t.colors.ring = c(0x34D399);
            sync_button_colors(t);
        }),
        "warm" => Theme::update(cx, |t| {
            t.colors.background = c(0xFAF7F2);
            t.colors.foreground = c(0x292524);
            t.colors.border = c(0xE7DFD3);
            t.colors.input = c(0xE7DFD3);
            t.colors.secondary = c(0xEFE8DC);
            t.colors.secondary_hover = c(0xE5DCCB);
            t.colors.secondary_active = c(0xDBD0BC);
            t.colors.secondary_foreground = c(0x292524);
            t.colors.muted = c(0xF3EDE3);
            t.colors.muted_foreground = c(0x78716C);
            t.colors.popover = c(0xFFFDF9);
            t.colors.popover_foreground = c(0x292524);
            t.colors.primary = c(0xD97706);
            t.colors.primary_hover = c(0xB45309);
            t.colors.primary_active = c(0x92400E);
            t.colors.primary_foreground = c(0xFFFFFF);
            t.colors.ring = c(0xF59E0B);
            sync_button_colors(t);
        }),
        "nord" => Theme::update(cx, |t| {
            t.colors.background = c(0x1B2230);
            t.colors.foreground = c(0xE5ECF6);
            t.colors.border = c(0x303B50);
            t.colors.input = c(0x303B50);
            t.colors.secondary = c(0x252F42);
            t.colors.secondary_hover = c(0x2E3A51);
            t.colors.secondary_active = c(0x364460);
            t.colors.secondary_foreground = c(0xE5ECF6);
            t.colors.muted = c(0x222B3C);
            t.colors.muted_foreground = c(0x8FA1BD);
            t.colors.popover = c(0x20293A);
            t.colors.popover_foreground = c(0xE5ECF6);
            t.colors.primary = c(0x3B82F6);
            t.colors.primary_hover = c(0x60A5FA);
            t.colors.primary_active = c(0x2563EB);
            t.colors.primary_foreground = c(0xFFFFFF);
            t.colors.ring = c(0x60A5FA);
            sync_button_colors(t);
        }),
        "violet" => Theme::update(cx, |t| {
            t.colors.background = c(0x1B1928);
            t.colors.foreground = c(0xECE8FA);
            t.colors.border = c(0x332E4A);
            t.colors.input = c(0x332E4A);
            t.colors.secondary = c(0x27233A);
            t.colors.secondary_hover = c(0x312C48);
            t.colors.secondary_active = c(0x3A3456);
            t.colors.secondary_foreground = c(0xECE8FA);
            t.colors.muted = c(0x232034);
            t.colors.muted_foreground = c(0x9E95BD);
            t.colors.popover = c(0x221F33);
            t.colors.popover_foreground = c(0xECE8FA);
            t.colors.primary = c(0x8B5CF6);
            t.colors.primary_hover = c(0xA78BFA);
            t.colors.primary_active = c(0x7C3AED);
            t.colors.primary_foreground = c(0xFFFFFF);
            t.colors.ring = c(0xA78BFA);
            sync_button_colors(t);
        }),
        "forest" => Theme::update(cx, |t| {
            t.colors.background = c(0x131C19);
            t.colors.foreground = c(0xE4F3EC);
            t.colors.border = c(0x253831);
            t.colors.input = c(0x253831);
            t.colors.secondary = c(0x1C2B25);
            t.colors.secondary_hover = c(0x243730);
            t.colors.secondary_active = c(0x2C433A);
            t.colors.secondary_foreground = c(0xE4F3EC);
            t.colors.muted = c(0x182520);
            t.colors.muted_foreground = c(0x88ACA0);
            t.colors.popover = c(0x182420);
            t.colors.popover_foreground = c(0xE4F3EC);
            t.colors.primary = c(0x10B981);
            t.colors.primary_hover = c(0x34D399);
            t.colors.primary_active = c(0x059669);
            t.colors.primary_foreground = c(0x062018);
            t.colors.ring = c(0x34D399);
            sync_button_colors(t);
        }),
        _ => {}
    }
}

fn sync_button_colors(t: &mut Theme) {
    t.colors.button_primary = t.colors.primary;
    t.colors.button_primary_hover = t.colors.primary_hover;
    t.colors.button_primary_active = t.colors.primary_active;
    t.colors.button_primary_foreground = t.colors.primary_foreground;

    t.colors.button_secondary = t.colors.secondary;
    t.colors.button_secondary_hover = t.colors.secondary_hover;
    t.colors.button_secondary_active = t.colors.secondary_active;
    t.colors.button_secondary_foreground = t.colors.secondary_foreground;

    t.colors.accent = t.colors.secondary;
    t.colors.accent_foreground = t.colors.foreground;
    t.colors.drag_border = t.colors.primary;
}
