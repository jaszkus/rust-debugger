use iced::{Element, Theme};

use crate::gui::app::{Message, Shell};
use crate::gui::theme::Fonts;

pub fn ai_live_view<'a>(
    shell: &'a Shell,
    _fonts: &'a Fonts,
) -> Element<'a, Message, Theme, iced::Renderer> {
    super::super::ui::live_feed(shell)
}
