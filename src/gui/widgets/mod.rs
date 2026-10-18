pub mod split;
pub mod vlist;

pub fn inert<'a>(
    content: iced::Element<'a, crate::gui::app::Message>,
) -> iced::Element<'a, crate::gui::app::Message> {
    use crate::gui::app::Message;
    use iced::advanced::{
        layout, renderer,
        widget::{tree, Tree},
        Layout, Widget,
    };
    use iced::{Element, Length, Rectangle, Size, Theme};
    struct Inert<'a>(Element<'a, Message>);
    impl Widget<Message, Theme, iced::Renderer> for Inert<'_> {
        fn tag(&self) -> tree::Tag {
            self.0.as_widget().tag()
        }
        fn state(&self) -> tree::State {
            self.0.as_widget().state()
        }
        fn children(&self) -> Vec<Tree> {
            self.0.as_widget().children()
        }
        fn diff(&self, tree: &mut Tree) {
            self.0.as_widget().diff(tree);
        }
        fn size(&self) -> Size<Length> {
            self.0.as_widget().size()
        }
        fn layout(
            &mut self,
            tree: &mut Tree,
            renderer: &iced::Renderer,
            limits: &layout::Limits,
        ) -> layout::Node {
            self.0.as_widget_mut().layout(tree, renderer, limits)
        }
        fn draw(
            &self,
            tree: &Tree,
            renderer: &mut iced::Renderer,
            theme: &Theme,
            style: &renderer::Style,
            layout: Layout<'_>,
            _cursor: iced::mouse::Cursor,
            viewport: &Rectangle,
        ) {
            self.0.as_widget().draw(
                tree,
                renderer,
                theme,
                style,
                layout,
                iced::mouse::Cursor::Unavailable,
                viewport,
            );
        }
    }
    Element::new(Inert(content))
}
