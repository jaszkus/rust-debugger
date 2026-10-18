use iced::{color, Color, Theme};

pub struct Palette;

impl Palette {
    pub const SHELL: Color = color!(0x141414);
    pub const BG: Color = color!(0x1e1e1e);
    pub const S1: Color = color!(0x262626);
    pub const S2: Color = color!(0x303030);
    pub const LINE: Color = color!(0x333333);
    pub const LINE2: Color = color!(0x444444);
    pub const TEXT: Color = color!(0xf4f4f4);
    pub const TEXT_DIM: Color = color!(0xc4c4c4);
    pub const TEXT_MUTE: Color = color!(0xa3a3a3);
    pub const SEL: Color = color!(0x3b3b3b);
    pub const ACCENT: Color = color!(0xffffff);
    pub const ON_ACCENT: Color = color!(0x000000);
    pub const SWITCH_OFF: Color = color!(0x454545);
    pub const HEX_ZERO: Color = color!(0x5c5c5c);

    pub const RUN: Color = color!(0x7bd88f);
    pub const BREAK: Color = color!(0xff7b7b);

    pub const MINT: Color = Palette::ACCENT;
    pub const ANNOT: Color = Palette::TEXT_MUTE;
    pub const LINK: Color = Palette::ACCENT;

    pub const LIGHT_SHELL: Color = color!(0xeeeeee);
    pub const LIGHT_BG: Color = color!(0xffffff);
    pub const LIGHT_S1: Color = color!(0xf6f6f6);
    pub const LIGHT_S2: Color = color!(0xebebeb);
    pub const LIGHT_LINE: Color = color!(0xdcdcdc);
    pub const LIGHT_LINE2: Color = color!(0xc8c8c8);
    pub const LIGHT_TEXT: Color = color!(0x111111);
    pub const LIGHT_DIM: Color = color!(0x444444);
    pub const LIGHT_MUTE: Color = color!(0x6a6a6a);
    pub const LIGHT_SEL: Color = color!(0xdedede);
    pub const LIGHT_ACCENT: Color = color!(0x111111);
    pub const LIGHT_ON_ACCENT: Color = color!(0xffffff);
    pub const LIGHT_SWITCH_OFF: Color = color!(0xc4c4c4);
    pub const LIGHT_RUN: Color = color!(0x1f8a3b);
    pub const LIGHT_BRK: Color = color!(0xc62828);
    pub const LIGHT_WARN: Color = color!(0x6a6a6a);
    pub const LIGHT_LINK: Color = color!(0x111111);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppThemeMode {
    #[default]
    System,
    Light,
    Dark,
}

impl AppThemeMode {
    pub const ALL: [AppThemeMode; 3] = [
        AppThemeMode::System,
        AppThemeMode::Light,
        AppThemeMode::Dark,
    ];

    pub fn label(self) -> &'static str {
        match self {
            AppThemeMode::System => "System",
            AppThemeMode::Light => "Light",
            AppThemeMode::Dark => "Dark",
        }
    }

    pub fn idx(self) -> usize {
        match self {
            AppThemeMode::System => 0,
            AppThemeMode::Light => 1,
            AppThemeMode::Dark => 2,
        }
    }

    pub fn from_idx(i: usize) -> AppThemeMode {
        match i {
            1 => AppThemeMode::Light,
            2 => AppThemeMode::Dark,
            _ => AppThemeMode::System,
        }
    }
}

pub fn is_light(theme: &Theme) -> bool {
    !theme.extended_palette().is_dark
}

pub fn mode_is_light(mode: AppThemeMode) -> bool {
    matches!(mode, AppThemeMode::Light)
}

macro_rules! pick {
    ($theme:expr, $light:expr, $dark:expr) => {
        if is_light($theme) {
            $light
        } else {
            $dark
        }
    };
}

pub fn shell_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_SHELL, Palette::SHELL)
}
pub fn app_bg_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_BG, Palette::BG)
}
pub fn s1_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_S1, Palette::S1)
}
pub fn s2_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_S2, Palette::S2)
}
pub fn sel_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_SEL, Palette::SEL)
}
pub fn side_bg_c(theme: &Theme) -> Color {
    s1_c(theme)
}
pub fn panel_bg_c(theme: &Theme) -> Color {
    s1_c(theme)
}
pub fn accent_bg(light: bool) -> Color {
    if light {
        Palette::LIGHT_BG
    } else {
        Palette::S1
    }
}
pub fn line_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_LINE, Palette::LINE)
}
pub fn line2_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_LINE2, Palette::LINE2)
}
pub fn text_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_TEXT, Palette::TEXT)
}
pub fn dim_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_DIM, Palette::TEXT_DIM)
}
pub fn mute_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_MUTE, Palette::TEXT_MUTE)
}
pub fn acc_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_ACCENT, Palette::ACCENT)
}
pub fn on_acc_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_ON_ACCENT, Palette::ON_ACCENT)
}
pub fn accbg_c(theme: &Theme) -> Color {
    sel_c(theme)
}
pub fn hover_c(theme: &Theme) -> Color {
    s2_c(theme)
}
pub fn switch_off_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_SWITCH_OFF, Palette::SWITCH_OFF)
}
pub fn run_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_RUN, Palette::RUN)
}
pub fn brk_c(theme: &Theme) -> Color {
    pick!(theme, Palette::LIGHT_BRK, Palette::BREAK)
}
pub fn warn_c(theme: &Theme) -> Color {
    mute_c(theme)
}
pub fn link_c(theme: &Theme) -> Color {
    acc_c(theme)
}

pub fn acc_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_ACCENT
    } else {
        Palette::ACCENT
    }
}
pub fn run_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_RUN
    } else {
        Palette::RUN
    }
}
pub fn brk_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_BRK
    } else {
        Palette::BREAK
    }
}
pub fn warn_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_WARN
    } else {
        Palette::TEXT_MUTE
    }
}
pub fn link_c_for_light(light: bool) -> Color {
    acc_c_for_light(light)
}
pub fn mute_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_MUTE
    } else {
        Palette::TEXT_MUTE
    }
}
pub fn dim_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_DIM
    } else {
        Palette::TEXT_DIM
    }
}
pub fn text_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_TEXT
    } else {
        Palette::TEXT
    }
}
pub fn line_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_LINE
    } else {
        Palette::LINE
    }
}
pub fn bg_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_BG
    } else {
        Palette::BG
    }
}
pub fn s1_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_S1
    } else {
        Palette::S1
    }
}
pub fn s2_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_S2
    } else {
        Palette::S2
    }
}
pub fn shell_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_SHELL
    } else {
        Palette::SHELL
    }
}
pub fn on_acc_c_for_light(light: bool) -> Color {
    if light {
        Palette::LIGHT_ON_ACCENT
    } else {
        Palette::ON_ACCENT
    }
}

#[derive(Clone, Copy)]
pub struct Tokens {
    pub is_light_flag: bool,
    pub text: Color,
    pub dim: Color,
    pub mute: Color,
    pub addr: Color,
    pub mnemonic: Color,
    pub operand: Color,
    pub string: Color,
    pub annot: Color,
    pub mint: Color,
    pub run: Color,
    pub brk: Color,
    pub link: Color,
    pub hover: Color,
    pub select: Color,
}

impl Tokens {
    pub fn resolve(light: bool) -> Self {
        let acc = acc_c_for_light(light);

        Self {
            is_light_flag: light,
            text: text_c_for_light(light),
            dim: dim_c_for_light(light),
            mute: mute_c_for_light(light),
            addr: mute_c_for_light(light),
            mnemonic: if light {
                color!(0x222222)
            } else {
                color!(0xd4d4d4)
            },
            operand: dim_c_for_light(light),
            string: dim_c_for_light(light),
            annot: mute_c_for_light(light),
            mint: acc,
            run: run_c_for_light(light),
            brk: brk_c_for_light(light),
            link: acc,
            hover: s2_c_for_light(light),
            select: if light {
                Palette::LIGHT_SEL
            } else {
                Palette::SEL
            },
        }
    }
}

pub const RAIL_W: f32 = 224.0;
pub const TOP_H: f32 = 54.0;
pub const PANEL_GAP: f32 = 10.0;
pub fn sidebar_width(_: bool) -> f32 {
    RAIL_W
}

pub use acc_c as accent;
pub use app_bg_c as bg;
pub use brk_c as brk;
pub use dim_c as dim;
pub use hover_c as hover;
pub use line_c as line;
pub use mute_c as mute;
pub use run_c as run;
pub use s1_c as s1;
pub use s2_c as s2;
pub use sel_c as select;
pub use text_c as text;

pub fn app_theme(light: bool) -> Theme {
    Theme::custom(
        if light { "RD Light" } else { "RD Dark" },
        iced::theme::Palette {
            background: bg_c_for_light(light),
            text: text_c_for_light(light),
            primary: acc_c_for_light(light),
            success: run_c_for_light(light),
            warning: warn_c_for_light(light),
            danger: brk_c_for_light(light),
        },
    )
}
