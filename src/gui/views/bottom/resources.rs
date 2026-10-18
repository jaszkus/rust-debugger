use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, mc, table_rev, table_tokens, RowCells, RowsData};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::vlist;

pub(crate) fn resources_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let (lines, analyzed): (Vec<String>, bool) = shell.read(|s| {
        let Some(a) = &s.analysis else {
            return (Vec::new(), false);
        };
        let Some(pe) = &a.pe_resources else {
            return (Vec::new(), true);
        };
        let mut v = vec![format!("{} resources found", pe.get_resource_count())];
        if let Some(vi) = &pe.version_info {
            if !vi.company_name.is_empty() {
                v.push(format!("  Company:      {}", vi.company_name));
            }
            if !vi.file_description.is_empty() {
                v.push(format!("  Description:  {}", vi.file_description));
            }
            if !vi.product_name.is_empty() {
                v.push(format!("  Product:      {}", vi.product_name));
            }
            if !vi.original_filename.is_empty() {
                v.push(format!("  Filename:     {}", vi.original_filename));
            }
            if !vi.legal_copyright.is_empty() {
                v.push(format!("  Copyright:    {}", vi.legal_copyright));
            }
        }
        for (rt, res) in &pe.get_resources_by_type() {
            v.push(format!("{}: {} items", rt.as_str(), res.len()));
        }
        (v, true)
    });
    let t = table_tokens(shell);
    let rows: Vec<RowCells> = lines
        .into_iter()
        .map(|l| RowCells {
            cells: vec![mc(l, t.text)],
            addr: None,
        })
        .collect();
    if rows.is_empty() {
        return empty_state(
            "No resources".to_string(),
            if analyzed {
                "This binary exposes no version info or resource entries.".to_string()
            } else {
                "Resources appear after automatic analysis.".to_string()
            },
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    vlist(RowsData {
        rows,
        first,
        selected: None,
        rev: table_rev(shell),
    })
    .into()
}
