// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    components::{Component, utils::centered_rect},
    focus::{EventResult, FocusManager, FocusTarget},
    mode::Scene,
    style::{EUCALYPTUS, GHOST_WHITE, LIGHT_PERIWINKLE, RED, VERY_LIGHT_AZURE, clear_area},
    tui::Frame,
};
use ant_node_manager::config::get_service_log_dir_path;
use ant_releases::ReleaseType;
use arboard::Clipboard;
use color_eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, ListState, Padding, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Wrap,
    },
};
use std::{
    fs,
    io::{BufRead, BufReader},
};
use tracing::error;

pub struct NodeLogsPopup {
    node_name: String,
    logs: Vec<String>,
    list_state: ListState,
    scroll_state: ScrollbarState,
    is_following_tail: bool,
    selection_start: Option<usize>,
    selection_end: Option<usize>,
    is_selecting: bool,
    word_wrap_enabled: bool,
    word_wrap_scroll_offset: usize,
    word_wrap_cursor_offset: usize,
    word_wrap_window_size: usize,
    clipboard: Option<Clipboard>,
}

impl NodeLogsPopup {
    pub fn new(node_name: String) -> Self {
        let mut instance = Self {
            node_name,
            logs: vec![],
            list_state: ListState::default(),
            scroll_state: ScrollbarState::default(),
            is_following_tail: true,
            selection_start: None,
            selection_end: None,
            is_selecting: false,
            word_wrap_enabled: false,
            word_wrap_scroll_offset: 0,
            word_wrap_cursor_offset: 0,
            word_wrap_window_size: 10,
            clipboard: Clipboard::new().ok(),
        };
        // Load initial logs
        if let Err(e) = instance.load_logs() {
            error!("Failed to load logs for node: {e}");
            instance.logs = vec![format!("Error loading logs: {e}")];
        }
        instance
    }

    fn load_logs(&mut self) -> Result<()> {
        if self.node_name.is_empty() || self.node_name == "No node available" {
            self.logs = vec![
                "No nodes available for log viewing".to_string(),
                "".to_string(),
                "To view logs:".to_string(),
                "1. Add some nodes by pressing [+]".to_string(),
                "2. Start at least one node".to_string(),
                "3. Select a node and press [L] to view its logs".to_string(),
            ];
            return Ok(());
        }

        let log_dir = get_service_log_dir_path(ReleaseType::NodeLaunchpad, None, None)?
            .join(&self.node_name)
            .join("logs");

        if !log_dir.exists() {
            self.logs = vec![
                format!("Log directory not found for node '{}'", self.node_name),
                format!("Expected path: {}", log_dir.display()),
                "".to_string(),
                "This could mean:".to_string(),
                "- The node hasn't been started yet".to_string(),
                "- The node name is incorrect".to_string(),
                "- Logs are stored in a different location".to_string(),
            ];
            return Ok(());
        }

        // Find the most recent log file
        let mut log_files: Vec<_> = fs::read_dir(&log_dir)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.is_file() && path.extension()? == "log" {
                    let metadata = entry.metadata().ok()?;
                    Some((path, metadata.modified().ok()?))
                } else {
                    None
                }
            })
            .collect();
        if log_files.is_empty() {
            self.logs = vec![
                format!("No log files found for node '{}'", self.node_name),
                format!("Searched in: {}", log_dir.display()),
            ];
            return Ok(());
        }

        // Sort by modification time, most recent first
        log_files.sort_by(|a, b| b.1.cmp(&a.1));
        let latest_log_file = &log_files[0].0;

        // Read the log file (tail the last 1000 lines for performance)
        let file = fs::File::open(latest_log_file)?;
        let reader = BufReader::new(file);
        let mut lines: Vec<String> = reader.lines().collect::<Result<Vec<_>, _>>()?;

        // Keep only the last 1000 lines for performance
        if lines.len() > 1000 {
            let skip_count = lines.len() - 1000;
            lines = lines.into_iter().skip(skip_count).collect();
        }

        if lines.is_empty() {
            self.logs = vec![
                format!("Log file for node '{}' is empty", self.node_name),
                format!("File: {}", latest_log_file.display()),
            ];
        } else {
            self.logs = lines;
            // Add header with file info
            self.logs
                .insert(0, format!("=== Logs for node '{}' ===", self.node_name));
            self.logs
                .insert(1, format!("File: {}", latest_log_file.display()));
            self.logs.insert(
                2,
                format!("Lines: {} (showing last 1000)", self.logs.len() - 3),
            );
            self.logs.insert(3, "".to_string());
        }

        if self.is_following_tail && !self.logs.is_empty() {
            let last_index = self.logs.len() - 1;
            self.list_state.select(Some(last_index));
            self.scroll_state = self.scroll_state.position(last_index);
        }
        self.scroll_state = self.scroll_state.content_length(self.logs.len());

        Ok(())
    }

    pub fn set_node_name(&mut self, node_name: String) {
        if self.node_name != node_name {
            self.node_name = node_name;
            // Reload logs for the new node
            if let Err(e) = self.load_logs() {
                error!("Failed to load logs for node: {e}");
                self.logs = vec![format!("Error loading logs: {e}")];
            }
        }
    }

    pub fn add_log_line(&mut self, line: String) {
        self.logs.push(line);
        if self.is_following_tail {
            // Auto-scroll to bottom
            let last_index = self.logs.len().saturating_sub(1);
            self.list_state.select(Some(last_index));
            self.scroll_state = self.scroll_state.position(last_index);
        }
    }

    pub fn set_logs(&mut self, logs: Vec<String>) {
        self.logs = logs;
        if self.is_following_tail && !self.logs.is_empty() {
            let last_index = self.logs.len().saturating_sub(1);
            self.list_state.select(Some(last_index));
            self.scroll_state = self.scroll_state.position(last_index);
        }
        self.scroll_state = self.scroll_state.content_length(self.logs.len());
    }

    fn handle_scroll_up(&mut self, with_shift: bool) {
        self.is_following_tail = false;

        if self.word_wrap_enabled {
            // In wrap mode, first try to move cursor up, then scroll window
            if self.word_wrap_cursor_offset > 0 {
                self.word_wrap_cursor_offset -= 1;
            } else if self.word_wrap_scroll_offset > 0 {
                self.word_wrap_scroll_offset = self.word_wrap_scroll_offset.saturating_sub(1);
            }
            if !with_shift {
                self.clear_selection();
            }
            return;
        }

        if let Some(selected) = self.list_state.selected() {
            if selected > 0 {
                let new_pos = selected - 1;
                self.list_state.select(Some(new_pos));
                self.scroll_state = self.scroll_state.position(new_pos);

                if with_shift {
                    if !self.is_selecting {
                        self.start_selection(selected);
                    }
                    self.extend_selection(new_pos);
                } else {
                    self.clear_selection();
                }
            }
        } else if !self.logs.is_empty() {
            let last_index = self.logs.len() - 1;
            self.list_state.select(Some(last_index));
            if with_shift {
                self.start_selection(last_index);
            } else {
                self.clear_selection();
            }
        }
    }

    fn handle_scroll_down(&mut self, with_shift: bool) {
        if self.word_wrap_enabled {
            // Calculate current absolute position in logs
            let current_position = self.word_wrap_scroll_offset + self.word_wrap_cursor_offset;

            // Check if we can move to the next log
            if current_position < self.logs.len().saturating_sub(1) {
                let window_size = self.word_wrap_window_size;

                // Calculate actual displayed lines (same logic as in rendering)
                let start = self
                    .word_wrap_scroll_offset
                    .min(self.logs.len().saturating_sub(1));
                let end = (start + window_size).min(self.logs.len());
                let actual_lines_displayed = end - start;
                let max_cursor_in_displayed = actual_lines_displayed.saturating_sub(1);

                // If cursor can move down within the visible window, just move cursor
                if self.word_wrap_cursor_offset < max_cursor_in_displayed {
                    self.word_wrap_cursor_offset += 1;
                } else {
                    // Cursor is at bottom of window, need to scroll
                    // Check if we can scroll further
                    let max_scroll_offset = self.logs.len().saturating_sub(window_size);
                    if self.word_wrap_scroll_offset < max_scroll_offset {
                        // Scroll window down
                        self.word_wrap_scroll_offset += 1;

                        // Recalculate displayed lines for new window position
                        let new_start = self
                            .word_wrap_scroll_offset
                            .min(self.logs.len().saturating_sub(1));
                        let new_end = (new_start + window_size).min(self.logs.len());
                        let new_actual_lines = new_end - new_start;

                        // Ensure cursor doesn't exceed the new window bounds
                        if self.word_wrap_cursor_offset >= new_actual_lines {
                            self.word_wrap_cursor_offset = new_actual_lines.saturating_sub(1);
                        }
                    }
                }
            }

            // Don't automatically enable tail following during manual scroll
            if !with_shift {
                self.clear_selection();
            }
            return;
        }

        if let Some(selected) = self.list_state.selected() {
            if selected < self.logs.len().saturating_sub(1) {
                let new_pos = selected + 1;
                self.list_state.select(Some(new_pos));
                self.scroll_state = self.scroll_state.position(new_pos);

                if with_shift {
                    if !self.is_selecting {
                        self.start_selection(selected);
                    }
                    self.extend_selection(new_pos);
                } else {
                    self.clear_selection();
                }

                // If we've reached the bottom, enable tail following
                if new_pos == self.logs.len().saturating_sub(1) {
                    self.is_following_tail = true;
                }
            } else {
                // Already at the bottom, enable tail following
                self.is_following_tail = true;
                if !with_shift {
                    self.clear_selection();
                }
            }
        } else if !self.logs.is_empty() {
            self.list_state.select(Some(0));
            self.scroll_state = self.scroll_state.position(0);
            if with_shift {
                self.start_selection(0);
            } else {
                self.clear_selection();
            }
        }
    }

    fn handle_page_up(&mut self, with_shift: bool) {
        self.is_following_tail = false;

        if self.word_wrap_enabled {
            // Page up by moving window and cursor
            let page_size = 10;
            if self.word_wrap_scroll_offset >= page_size {
                self.word_wrap_scroll_offset -= page_size;
            } else {
                self.word_wrap_scroll_offset = 0;
                self.word_wrap_cursor_offset = 0;
            }
            if !with_shift {
                self.clear_selection();
            }
            return;
        }

        if let Some(selected) = self.list_state.selected() {
            let new_pos = selected.saturating_sub(10);
            self.list_state.select(Some(new_pos));
            self.scroll_state = self.scroll_state.position(new_pos);

            if with_shift {
                if !self.is_selecting {
                    self.start_selection(selected);
                }
                self.extend_selection(new_pos);
            } else {
                self.clear_selection();
            }
        }
    }

    fn handle_page_down(&mut self, with_shift: bool) {
        if self.word_wrap_enabled {
            // Page down by moving window
            let page_size = 10;
            let window_size = self.word_wrap_window_size;
            let max_scroll_offset = self.logs.len().saturating_sub(window_size);
            let new_offset = (self.word_wrap_scroll_offset + page_size).min(max_scroll_offset);

            self.word_wrap_scroll_offset = new_offset;
            // Reset cursor to top of new window
            self.word_wrap_cursor_offset = 0;
            // Don't automatically enable tail following during page down
            if !with_shift {
                self.clear_selection();
            }
            return;
        }

        if let Some(selected) = self.list_state.selected() {
            let new_pos = (selected + 10).min(self.logs.len().saturating_sub(1));
            self.list_state.select(Some(new_pos));
            self.scroll_state = self.scroll_state.position(new_pos);

            if with_shift {
                if !self.is_selecting {
                    self.start_selection(selected);
                }
                self.extend_selection(new_pos);
            } else {
                self.clear_selection();
            }

            if new_pos >= self.logs.len().saturating_sub(1) {
                self.is_following_tail = true;
            }
        }
    }

    fn handle_home(&mut self, with_shift: bool) {
        self.is_following_tail = false;

        if self.word_wrap_enabled {
            self.word_wrap_scroll_offset = 0;
            self.word_wrap_cursor_offset = 0;
            if !with_shift {
                self.clear_selection();
            }
            return;
        }

        if !self.logs.is_empty() {
            if with_shift {
                if let Some(selected) = self.list_state.selected() {
                    if !self.is_selecting {
                        self.start_selection(selected);
                    }
                    self.extend_selection(0);
                }
            } else {
                self.clear_selection();
            }
            self.list_state.select(Some(0));
            self.scroll_state = self.scroll_state.position(0);
        }
    }

    fn handle_end(&mut self, with_shift: bool) {
        if self.word_wrap_enabled {
            // In wrap mode, End key should enable tail following
            self.word_wrap_scroll_offset = 0; // Reset to 0 since tail following will show last logs
            self.word_wrap_cursor_offset = 0; // Cursor doesn't matter in tail mode
            self.is_following_tail = true;
            if !with_shift {
                self.clear_selection();
            }
            return;
        }

        if !self.logs.is_empty() {
            let last_index = self.logs.len() - 1;
            if with_shift {
                if let Some(selected) = self.list_state.selected() {
                    if !self.is_selecting {
                        self.start_selection(selected);
                    }
                    self.extend_selection(last_index);
                }
            } else {
                self.clear_selection();
            }
            self.list_state.select(Some(last_index));
            self.scroll_state = self.scroll_state.position(last_index);
            self.is_following_tail = true;
        }
    }

    fn get_selection_range(&self) -> Option<(usize, usize)> {
        match (self.selection_start, self.selection_end) {
            (Some(start), Some(end)) => {
                let min = start.min(end);
                let max = start.max(end);
                Some((min, max))
            }
            _ => None,
        }
    }

    fn is_line_selected(&self, index: usize) -> bool {
        if let Some((start, end)) = self.get_selection_range() {
            index >= start && index <= end
        } else {
            false
        }
    }

    fn clear_selection(&mut self) {
        self.selection_start = None;
        self.selection_end = None;
        self.is_selecting = false;
    }

    fn start_selection(&mut self, index: usize) {
        self.selection_start = Some(index);
        self.selection_end = Some(index);
        self.is_selecting = true;
    }

    fn extend_selection(&mut self, index: usize) {
        if self.selection_start.is_none() {
            self.start_selection(index);
        } else {
            self.selection_end = Some(index);
        }
    }

    fn select_all(&mut self) {
        if !self.logs.is_empty() {
            self.selection_start = Some(0);
            self.selection_end = Some(self.logs.len() - 1);
            self.is_selecting = true;
        }
    }

    fn get_selected_text(&self) -> String {
        if let Some((start, end)) = self.get_selection_range() {
            self.logs[start..=end].join("\n")
        } else if let Some(current) = self.list_state.selected() {
            self.logs.get(current).cloned().unwrap_or_default()
        } else {
            String::new()
        }
    }

    fn copy_to_clipboard(&mut self) -> Result<()> {
        let text = self.get_selected_text();
        if !text.is_empty()
            && let Some(ref mut clipboard) = self.clipboard
        {
            clipboard.set_text(text)?;
        }
        Ok(())
    }

    fn toggle_word_wrap(&mut self) {
        self.word_wrap_enabled = !self.word_wrap_enabled;

        if self.word_wrap_enabled {
            // Entering wrap mode - convert from list position
            if self.is_following_tail {
                self.word_wrap_scroll_offset = 0;
                self.word_wrap_cursor_offset = 0;
            } else {
                let selected = self.list_state.selected().unwrap_or(0);
                // Show some context around the selected line
                self.word_wrap_scroll_offset = selected.saturating_sub(5);
                self.word_wrap_cursor_offset =
                    selected.saturating_sub(self.word_wrap_scroll_offset).min(5);
            }
        } else {
            // Exiting wrap mode - restore position to list
            if !self.is_following_tail {
                let absolute_position = self.word_wrap_scroll_offset + self.word_wrap_cursor_offset;
                let clamped_position = absolute_position.min(self.logs.len().saturating_sub(1));
                self.list_state.select(Some(clamped_position));
                self.scroll_state = self.scroll_state.position(clamped_position);
            } else {
                // Keep tail following active
                let last_index = self.logs.len().saturating_sub(1);
                self.list_state.select(Some(last_index));
                self.scroll_state = self.scroll_state.position(last_index);
            }
        }
    }
}

impl Component for NodeLogsPopup {
    fn focus_target(&self) -> FocusTarget {
        FocusTarget::NodeLogsPopup
    }

    fn handle_key_events(
        &mut self,
        key: KeyEvent,
        _focus_manager: &FocusManager,
    ) -> Result<(Vec<Action>, EventResult)> {
        let shift_pressed = key.modifiers.contains(KeyModifiers::SHIFT);
        let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);

        let action = match key.code {
            KeyCode::Esc => Action::SwitchScene(Scene::Status),
            KeyCode::Up => {
                self.handle_scroll_up(shift_pressed);
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::Down => {
                self.handle_scroll_down(shift_pressed);
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::PageUp => {
                self.handle_page_up(shift_pressed);
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::PageDown => {
                self.handle_page_down(shift_pressed);
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::Home => {
                self.handle_home(shift_pressed);
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::End => {
                self.handle_end(shift_pressed);
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::Char('c') if ctrl_pressed => {
                if let Err(e) = self.copy_to_clipboard() {
                    error!("Failed to copy to clipboard: {e}");
                }
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::Char('a') if ctrl_pressed => {
                self.select_all();
                return Ok((vec![], EventResult::Consumed));
            }
            KeyCode::Char('w') | KeyCode::Char('W') => {
                self.toggle_word_wrap();
                return Ok((vec![], EventResult::Consumed));
            }
            _ => return Ok((vec![], EventResult::Ignored)),
        };

        Ok((vec![action], EventResult::Consumed))
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::SwitchScene(Scene::NodeLogsPopUp) => {
                Ok(Some(Action::SwitchInputMode(crate::mode::InputMode::Entry)))
            }
            Action::SetNodeLogsTarget(node_name) => {
                self.set_node_name(node_name);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        // Create a popup area (80% width, 85% height)
        let popup_area = centered_rect(80, 85, area);
        clear_area(f, popup_area);

        // Create the main layout
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Title
                Constraint::Min(1),    // Logs
                Constraint::Length(5), // Instructions (2 lines + padding + border)
            ])
            .split(popup_area);

        // Draw border and title
        let title = format!(" Node Logs - {} ", self.node_name);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_style(Style::default().fg(EUCALYPTUS).bold())
            .border_style(Style::default().fg(EUCALYPTUS));

        f.render_widget(block, popup_area);

        // Create logs display area
        let logs_area = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .margin(1)
            .split(main_layout[1]);

        // Render logs based on word wrap setting
        if self.word_wrap_enabled {
            // Use window-based approach - no scroll() method, just control which logs are shown
            let viewport_height = logs_area[0].height as usize;
            let window_size = (viewport_height / 2).max(10); // Conservative: assume each log takes ~2 lines when wrapped, minimum 10

            // Store the actual window size for scroll handlers to use
            self.word_wrap_window_size = window_size;

            let display_logs = if self.is_following_tail {
                // Show the last 'window_size' logs
                let start = self.logs.len().saturating_sub(window_size);
                &self.logs[start..]
            } else {
                // Show logs from scroll position (word_wrap_scroll_offset is now log line index)
                let start = self
                    .word_wrap_scroll_offset
                    .min(self.logs.len().saturating_sub(1));
                let end = (start + window_size).min(self.logs.len());
                &self.logs[start..end]
            };

            // Calculate display cursor position without modifying state
            let actual_lines_displayed = display_logs.len();
            let display_cursor = self
                .word_wrap_cursor_offset
                .min(actual_lines_displayed.saturating_sub(1));

            // Build styled text with cursor highlighting
            let mut text_lines = Vec::new();
            for (i, line) in display_logs.iter().enumerate() {
                // Highlight the cursor line in wrap mode (unless tail following)
                let should_highlight = !self.is_following_tail && i == display_cursor;
                let style = if should_highlight {
                    Style::default().fg(GHOST_WHITE).bg(VERY_LIGHT_AZURE)
                } else {
                    Style::default().fg(GHOST_WHITE)
                };

                text_lines.push(Line::from(Span::styled(line.clone(), style)));
            }

            // Create paragraph WITHOUT scroll - we control which lines are included
            let paragraph = Paragraph::new(text_lines)
                .wrap(Wrap { trim: true })
                .style(Style::default().fg(GHOST_WHITE));

            f.render_widget(paragraph, logs_area[0]);
        } else {
            // Use List widget (existing implementation)
            let log_items: Vec<ListItem> = self
                .logs
                .iter()
                .enumerate()
                .map(|(i, log)| {
                    let style = if Some(i) == self.list_state.selected() {
                        Style::default().fg(GHOST_WHITE).bg(VERY_LIGHT_AZURE)
                    } else if self.is_line_selected(i) {
                        Style::default().fg(GHOST_WHITE).bg(LIGHT_PERIWINKLE)
                    } else {
                        Style::default().fg(GHOST_WHITE)
                    };
                    ListItem::new(log.clone()).style(style)
                })
                .collect();

            let logs_list = List::new(log_items)
                .style(Style::default().fg(GHOST_WHITE))
                .highlight_style(Style::default().fg(GHOST_WHITE).bg(VERY_LIGHT_AZURE));

            f.render_stateful_widget(logs_list, logs_area[0], &mut self.list_state);
        }

        // Draw scrollbar
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(LIGHT_PERIWINKLE));

        f.render_stateful_widget(scrollbar, logs_area[1], &mut self.scroll_state);

        // Draw instructions
        let selection_count = if let Some((start, end)) = self.get_selection_range() {
            format!(" {} lines selected", end - start + 1)
        } else {
            String::new()
        };

        let instructions = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("↑/↓", Style::default().fg(EUCALYPTUS).bold()),
                Span::styled(" Scroll  ", Style::default().fg(GHOST_WHITE)),
                Span::styled("Shift+↑/↓", Style::default().fg(EUCALYPTUS).bold()),
                Span::styled(" Select  ", Style::default().fg(GHOST_WHITE)),
                Span::styled("Ctrl+C", Style::default().fg(EUCALYPTUS).bold()),
                Span::styled(" Copy", Style::default().fg(GHOST_WHITE)),
            ]),
            Line::from(vec![
                Span::styled("ESC", Style::default().fg(RED).bold()),
                Span::styled(" Close  ", Style::default().fg(GHOST_WHITE)),
                Span::styled("W", Style::default().fg(EUCALYPTUS).bold()),
                Span::styled(" Word Wrap  ", Style::default().fg(GHOST_WHITE)),
                Span::styled("Ctrl+A", Style::default().fg(EUCALYPTUS).bold()),
                Span::styled(" Select All", Style::default().fg(GHOST_WHITE)),
                Span::styled(&selection_count, Style::default().fg(LIGHT_PERIWINKLE)),
            ]),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(EUCALYPTUS))
                .padding(Padding::uniform(1)),
        );

        f.render_widget(instructions, main_layout[2]);

        // Draw tail following and word wrap indicators
        let mut indicators = Vec::new();
        if self.is_following_tail {
            indicators.push(" [TAIL] ");
        }
        if self.word_wrap_enabled {
            indicators.push(" [WRAP] ");
        }

        if !indicators.is_empty() {
            let indicator_text = indicators.join("");
            let indicator_width = indicator_text.len() as u16;
            let indicator_area = Rect::new(
                popup_area.right().saturating_sub(indicator_width + 1),
                popup_area.y + 1,
                indicator_width,
                1,
            );
            let indicator =
                Paragraph::new(indicator_text).style(Style::default().fg(EUCALYPTUS).bold());
            f.render_widget(indicator, indicator_area);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        focus::{EventResult, FocusManager, FocusTarget},
        mode::Scene,
        test_utils::*,
    };
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn test_esc_key_closes_popup() {
        let mut popup = NodeLogsPopup::new("antnode1".to_string());
        let focus_manager = FocusManager::new(FocusTarget::NodeLogsPopup);
        let key_event = KeyEvent::new(KeyCode::Esc, KeyModifiers::empty());

        let result = popup.handle_key_events(key_event, &focus_manager);

        assert!(result.is_ok());
        let (actions, event_result) = result.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], Action::SwitchScene(Scene::Status));
        assert_eq!(event_result, EventResult::Consumed);
    }

    #[test]
    fn test_page_up_key_handling() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let focus_manager = FocusManager::new(FocusTarget::NodeLogsPopup);
        let key_event = KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty());

        let result = popup.handle_key_events(key_event, &focus_manager);

        assert!(result.is_ok());
        let (actions, event_result) = result.unwrap();
        assert_eq!(actions.len(), 0);
        assert_eq!(event_result, EventResult::Consumed);
    }

    #[test]
    fn test_keyboard_sequence_simulation() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let focus_manager = FocusManager::new(FocusTarget::NodeLogsPopup);

        let key_sequence = KeySequence::new()
            .arrow_down()
            .arrow_down()
            .arrow_up()
            .page_down()
            .home()
            .end()
            .esc()
            .build();

        for key_event in key_sequence {
            let result = popup.handle_key_events(key_event, &focus_manager);
            assert!(result.is_ok());

            if key_event.code == KeyCode::Esc {
                let (actions, _) = result.unwrap();
                assert_eq!(actions.len(), 1);
                assert_eq!(actions[0], Action::SwitchScene(Scene::Status));
                break;
            }
        }
    }

    // === ADVANCED TESTING ===

    #[test]
    fn test_tail_mode_behavior_with_scrolling() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs = (0..10).map(|i| format!("Log line {i}")).collect();
        popup.set_logs(test_logs);

        // Should start in tail mode at the end
        assert!(popup.is_following_tail);
        assert_eq!(popup.list_state.selected(), Some(9));

        // Scrolling up should disable tail mode
        popup.handle_scroll_up(false);
        assert!(!popup.is_following_tail);
        assert_eq!(popup.list_state.selected(), Some(8));

        // Scrolling down to the end should re-enable tail mode
        popup.handle_scroll_down(false);
        assert!(popup.is_following_tail);
        assert_eq!(popup.list_state.selected(), Some(9));

        // Page up should disable tail mode
        popup.handle_page_up(false);
        assert!(!popup.is_following_tail);

        // Page down to the end should re-enable tail mode
        popup.handle_page_down(false);
        assert!(popup.is_following_tail);

        // Home should disable tail mode
        popup.handle_home(false);
        assert!(!popup.is_following_tail);
        assert_eq!(popup.list_state.selected(), Some(0));

        // End should re-enable tail mode
        popup.handle_end(false);
        assert!(popup.is_following_tail);
        assert_eq!(popup.list_state.selected(), Some(9));
    }

    #[test]
    fn test_set_logs_functionality() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs = vec![
            "First log line".to_string(),
            "Second log line".to_string(),
            "Third log line".to_string(),
        ];

        popup.set_logs(test_logs.clone());

        assert_eq!(popup.logs, test_logs);
        // Should auto-scroll to bottom when in tail mode
        assert_eq!(popup.list_state.selected(), Some(2));
    }

    #[test]
    fn test_set_logs_empty_collection() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        popup.set_logs(vec![]);

        assert!(popup.logs.is_empty());
        assert_eq!(popup.list_state.selected(), None);
    }

    #[test]
    fn test_add_log_line_functionality() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        popup.set_logs(vec!["Initial log".to_string()]);

        // Add a new log line
        popup.add_log_line("New log line".to_string());

        assert_eq!(popup.logs.len(), 2);
        assert_eq!(popup.logs[1], "New log line");

        // Should auto-scroll to new line when in tail mode
        assert!(popup.is_following_tail);
        assert_eq!(popup.list_state.selected(), Some(1));
    }

    #[test]
    fn test_add_log_line_when_not_following_tail() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        popup.set_logs(vec![
            "Line 1".to_string(),
            "Line 2".to_string(),
            "Line 3".to_string(),
        ]);

        // Disable tail following by scrolling up
        popup.handle_scroll_up(false);
        assert!(!popup.is_following_tail);
        let selected_before = popup.list_state.selected();

        // Add a new log line
        popup.add_log_line("New line".to_string());

        assert_eq!(popup.logs.len(), 4);
        assert_eq!(popup.logs[3], "New line");

        // Should NOT auto-scroll when not following tail
        assert_eq!(popup.list_state.selected(), selected_before);
    }

    #[test]
    fn test_no_node_available_message() {
        let popup = NodeLogsPopup::new("No node available".to_string());

        // Should display specific messages for no nodes
        assert!(
            popup
                .logs
                .iter()
                .any(|log| log.contains("No nodes available for log viewing"))
        );
        assert!(
            popup
                .logs
                .iter()
                .any(|log| log.contains("Add some nodes by pressing [+]"))
        );
        assert!(
            popup
                .logs
                .iter()
                .any(|log| log.contains("Select a node and press [L] to view its logs"))
        );
    }

    #[test]
    fn test_empty_node_name_message() {
        let popup = NodeLogsPopup::new("".to_string());

        // Should display no nodes message for empty name
        assert!(
            popup
                .logs
                .iter()
                .any(|log| log.contains("No nodes available for log viewing"))
        );
    }

    #[test]
    fn test_set_node_name_changes_logs() {
        let mut popup = NodeLogsPopup::new("initial_node".to_string());
        assert_eq!(popup.node_name, "initial_node");

        // Change to a different node name
        popup.set_node_name("new_node".to_string());
        assert_eq!(popup.node_name, "new_node");

        // Set to same name should not reload
        popup.set_node_name("new_node".to_string());
        assert_eq!(popup.node_name, "new_node");

        // Change to "No node available" should trigger special message
        popup.set_node_name("No node available".to_string());
        assert!(
            popup
                .logs
                .iter()
                .any(|log| log.contains("No nodes available for log viewing"))
        );
    }

    #[test]
    fn test_scroll_state_synchronization() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs: Vec<String> = (0..20).map(|i| format!("Log line {i}")).collect();
        popup.set_logs(test_logs);

        // Scroll to different positions and verify list state is updated
        popup.handle_home(false);
        assert_eq!(popup.list_state.selected(), Some(0));

        popup.handle_page_down(false);
        let selected = popup.list_state.selected().unwrap();
        assert!(selected > 0); // Should have moved from position 0

        popup.handle_end(false);
        assert_eq!(popup.list_state.selected(), Some(19));
    }

    #[test]
    fn test_scroll_navigation_with_empty_logs() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        popup.set_logs(vec![]);

        // All navigation should be safe with empty logs
        popup.handle_scroll_up(false);
        assert_eq!(popup.list_state.selected(), None);

        popup.handle_scroll_down(false);
        assert_eq!(popup.list_state.selected(), None);

        popup.handle_page_up(false);
        assert_eq!(popup.list_state.selected(), None);

        popup.handle_page_down(false);
        assert_eq!(popup.list_state.selected(), None);

        popup.handle_home(false);
        assert_eq!(popup.list_state.selected(), None);

        popup.handle_end(false);
        assert_eq!(popup.list_state.selected(), None);
    }

    #[test]
    fn test_scroll_navigation_with_single_log() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        popup.set_logs(vec!["Single log line".to_string()]);

        // Should start at the only item
        assert_eq!(popup.list_state.selected(), Some(0));

        // All navigation should keep selection at the single item
        popup.handle_scroll_up(false);
        assert_eq!(popup.list_state.selected(), Some(0));

        popup.handle_scroll_down(false);
        assert_eq!(popup.list_state.selected(), Some(0));

        popup.handle_page_up(false);
        assert_eq!(popup.list_state.selected(), Some(0));

        popup.handle_page_down(false);
        assert_eq!(popup.list_state.selected(), Some(0));
    }

    #[test]
    fn test_page_navigation_behavior() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs: Vec<String> = (0..50).map(|i| format!("Log line {i}")).collect();
        popup.set_logs(test_logs);

        // Start at bottom (index 49)
        assert_eq!(popup.list_state.selected(), Some(49));

        // Page up should move up by 10
        popup.handle_page_up(false);
        assert_eq!(popup.list_state.selected(), Some(39));
        assert!(!popup.is_following_tail);

        // Page down should move down by 10
        popup.handle_page_down(false);
        assert_eq!(popup.list_state.selected(), Some(49));
        assert!(popup.is_following_tail); // Should re-enable tail at bottom

        // From top, page up should stay at 0
        popup.handle_home(false);
        popup.handle_page_up(false);
        assert_eq!(popup.list_state.selected(), Some(0));
    }

    #[test]
    fn test_log_content_length_management() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());

        // Start with no logs
        popup.set_logs(vec![]);
        assert_eq!(popup.logs.len(), 0);

        // Add some logs
        let test_logs: Vec<String> = (0..5).map(|i| format!("Log {i}")).collect();
        popup.set_logs(test_logs.clone());
        assert_eq!(popup.logs.len(), 5);
        assert_eq!(popup.logs, test_logs);

        // Add more logs dynamically
        popup.add_log_line("Extra log".to_string());
        assert_eq!(popup.logs.len(), 6);
        assert_eq!(popup.logs[5], "Extra log");
    }

    #[test]
    fn test_drawing_with_various_content_states() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // Test drawing with no logs
        let mut popup_empty = NodeLogsPopup::new("empty_node".to_string());
        popup_empty.set_logs(vec![]);

        let result = terminal.draw(|f| {
            let area = f.area();
            if let Err(e) = popup_empty.draw(f, area) {
                panic!("Drawing failed with empty logs: {e}");
            }
        });
        assert!(result.is_ok());

        // Test drawing with many logs
        let mut popup_full = NodeLogsPopup::new("full_node".to_string());
        let many_logs: Vec<String> = (0..1000).map(|i| format!("Log line {i}")).collect();
        popup_full.set_logs(many_logs);

        let result = terminal.draw(|f| {
            let area = f.area();
            if let Err(e) = popup_full.draw(f, area) {
                panic!("Drawing failed with many logs: {e}");
            }
        });
        assert!(result.is_ok());

        // Test drawing with "No node available"
        let mut popup_no_node = NodeLogsPopup::new("No node available".to_string());

        let result = terminal.draw(|f| {
            let area = f.area();
            if let Err(e) = popup_no_node.draw(f, area) {
                panic!("Drawing failed with no node: {e}");
            }
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_tail_indicator_visibility() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs: Vec<String> = (0..10).map(|i| format!("Log line {i}")).collect();
        popup.set_logs(test_logs);

        // Should be following tail initially
        assert!(popup.is_following_tail);

        // Scroll up should disable tail following
        popup.handle_scroll_up(false);
        assert!(!popup.is_following_tail);

        // Back to bottom should re-enable
        popup.handle_end(false);
        assert!(popup.is_following_tail);
    }

    #[test]
    fn test_focus_target_consistency() {
        let popup1 = NodeLogsPopup::new("node1".to_string());
        let popup2 = NodeLogsPopup::new("node2".to_string());
        let popup3 = NodeLogsPopup::new("".to_string());

        // All instances should have the same focus target
        assert_eq!(popup1.focus_target(), FocusTarget::NodeLogsPopup);
        assert_eq!(popup2.focus_target(), FocusTarget::NodeLogsPopup);
        assert_eq!(popup3.focus_target(), FocusTarget::NodeLogsPopup);
    }

    #[test]
    fn test_selection_functionality() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs: Vec<String> = (0..10).map(|i| format!("Log line {i}")).collect();
        popup.set_logs(test_logs);

        // Test selection with shift+down
        popup.list_state.select(Some(2));
        popup.handle_scroll_down(true);
        assert!(popup.is_selecting);
        assert_eq!(popup.selection_start, Some(2));
        assert_eq!(popup.selection_end, Some(3));
        assert!(popup.is_line_selected(2));
        assert!(popup.is_line_selected(3));
        assert!(!popup.is_line_selected(1));

        // Test extending selection
        popup.handle_scroll_down(true);
        assert_eq!(popup.selection_start, Some(2));
        assert_eq!(popup.selection_end, Some(4));
        assert!(popup.is_line_selected(4));

        // Test clearing selection on normal navigation
        popup.handle_scroll_down(false);
        assert!(!popup.is_selecting);
        assert_eq!(popup.selection_start, None);
        assert_eq!(popup.selection_end, None);
    }

    #[test]
    fn test_select_all_functionality() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs: Vec<String> = (0..5).map(|i| format!("Line {i}")).collect();
        popup.set_logs(test_logs);

        popup.select_all();
        assert!(popup.is_selecting);
        assert_eq!(popup.selection_start, Some(0));
        assert_eq!(popup.selection_end, Some(4));

        // Check all lines are selected
        for i in 0..5 {
            assert!(popup.is_line_selected(i));
        }
    }

    #[test]
    fn test_get_selected_text() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let test_logs = vec![
            "First line".to_string(),
            "Second line".to_string(),
            "Third line".to_string(),
        ];
        popup.set_logs(test_logs);

        // Test getting single line when no selection
        popup.list_state.select(Some(1));
        let text = popup.get_selected_text();
        assert_eq!(text, "Second line");

        // Test getting multiple selected lines
        popup.selection_start = Some(0);
        popup.selection_end = Some(2);
        let text = popup.get_selected_text();
        assert_eq!(text, "First line\nSecond line\nThird line");
    }

    #[test]
    fn test_word_wrap_toggle() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        assert!(!popup.word_wrap_enabled);

        popup.toggle_word_wrap();
        assert!(popup.word_wrap_enabled);

        popup.toggle_word_wrap();
        assert!(!popup.word_wrap_enabled);
    }

    #[test]
    fn test_log_content_with_special_characters() {
        let mut popup = NodeLogsPopup::new("test_node".to_string());
        let special_logs = vec![
            "Log with émojis 🚀 and ünïcødé".to_string(),
            "Log with\ttabs and\nnewlines".to_string(),
            "Log with very long line that exceeds normal width and should be handled gracefully by the display system".to_string(),
            "".to_string(), // Empty line
            "   Log with leading/trailing spaces   ".to_string(),
        ];

        popup.set_logs(special_logs.clone());
        assert_eq!(popup.logs, special_logs);

        // Should still function normally with special characters
        assert_eq!(popup.list_state.selected(), Some(4));
        popup.handle_home(false);
        assert_eq!(popup.list_state.selected(), Some(0));
    }
}
