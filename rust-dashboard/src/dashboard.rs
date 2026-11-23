use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use eframe::egui::{
    self, Color32, ComboBox, Frame, Label, Layout, RichText, ScrollArea, Sense, Stroke,
    TextWrapMode,
};

use crate::audit::{self, Event, Filter, Outcome, Snapshot, Summary, RECENT_LIMIT};

const REFRESH: Duration = Duration::from_secs(2);
const BACKGROUND: Color32 = Color32::from_rgb(15, 18, 25);
const CARD: Color32 = Color32::from_rgb(23, 28, 39);
const BORDER: Color32 = Color32::from_rgb(44, 51, 66);
const MUTED: Color32 = Color32::from_rgb(164, 174, 192);
const ACCENT: Color32 = Color32::from_rgb(114, 185, 249);
const PASS: Color32 = Color32::from_rgb(108, 213, 167);
const HOLD: Color32 = Color32::from_rgb(251, 132, 136);
const SANITIZE: Color32 = Color32::from_rgb(249, 198, 119);
const UNCERTAIN: Color32 = Color32::from_rgb(195, 172, 255);

#[derive(Clone, PartialEq, Eq)]
struct Query {
    path: PathBuf,
    filter: Filter,
}

struct Report {
    query: Query,
    result: Result<Snapshot, String>,
}

pub struct Dashboard {
    query: Query,
    path_entry: String,
    snapshot: Option<Snapshot>,
    displayed_filter: Option<Filter>,
    error: Option<String>,
    selected: Option<i64>,
    in_flight: bool,
    due: Instant,
    tx: Sender<Query>,
    rx: Receiver<Report>,
}

impl Dashboard {
    pub fn new(creation: &eframe::CreationContext<'_>, path: PathBuf) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BACKGROUND;
        visuals.window_fill = CARD;
        visuals.selection.bg_fill = Color32::from_rgb(42, 73, 111);
        creation.egui_ctx.set_visuals(visuals);

        let (tx, request_rx) = mpsc::channel::<Query>();
        let (report_tx, rx) = mpsc::channel();
        let ctx = creation.egui_ctx.clone();
        thread::spawn(move || {
            while let Ok(query) = request_rx.recv() {
                let result =
                    audit::read(&query.path, &query.filter).map_err(|error| error.to_string());
                if report_tx.send(Report { query, result }).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });

        Self {
            path_entry: path.to_string_lossy().into_owned(),
            query: Query {
                path,
                filter: Filter::default(),
            },
            snapshot: None,
            displayed_filter: None,
            error: None,
            selected: None,
            in_flight: false,
            due: Instant::now(),
            tx,
            rx,
        }
    }

    fn read_updates(&mut self, ctx: &egui::Context) {
        if let Ok(report) = self.rx.try_recv() {
            self.in_flight = false;
            if report.query == self.query {
                match report.result {
                    Ok(snapshot) => {
                        self.snapshot = Some(snapshot);
                        self.displayed_filter = Some(report.query.filter);
                        self.error = None;
                    }
                    Err(error) => {
                        self.snapshot = None;
                        self.displayed_filter = None;
                        self.error = Some(error);
                    }
                }
            }
        }
        let now = Instant::now();
        if !self.in_flight && self.due <= now {
            self.in_flight = self.tx.send(self.query.clone()).is_ok();
            if !self.in_flight {
                self.error = Some("The read worker stopped. Reopen the dashboard.".into());
            }
            self.due = now + REFRESH;
        }
        ctx.request_repaint_after(if self.in_flight {
            REFRESH
        } else {
            self.due.saturating_duration_since(now)
        });
    }

    fn open(&mut self, path: PathBuf) {
        self.query = Query {
            path,
            filter: Filter::default(),
        };
        self.path_entry = self.query.path.to_string_lossy().into_owned();
        self.snapshot = None;
        self.displayed_filter = None;
        self.error = None;
        self.selected = None;
        self.due = Instant::now();
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Audit database").color(MUTED));
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.path_entry)
                    .desired_width((ui.available_width() - 170.0).max(170.0)),
            );
            let enter = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if (enter || ui.button("Open").clicked()) && !self.path_entry.trim().is_empty() {
                self.open(PathBuf::from(self.path_entry.trim()));
            }
            if ui.button("Refresh").clicked() {
                self.due = Instant::now();
            }
        });
    }

    fn event_view(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.snapshot else {
            if let Some(error) = &self.error {
                ui.label(
                    RichText::new("Audit database unavailable")
                        .strong()
                        .color(HOLD),
                );
                ui.label("Start the middleware or open an existing security_events.db. This dashboard opens the database read-only.");
                ui.label(RichText::new(error).color(MUTED));
            } else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Reading the audit database…");
                });
            }
            return;
        };
        let mut changed = summary_cards(ui, &snapshot.summary, &mut self.query.filter.outcome);
        ui.add_space(8.0);
        outcome_bar(ui, &snapshot.summary);
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.heading("Case monitor");
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{} shown · {} matches", snapshot.events.len(),
                        snapshot.matching_events)).color(MUTED),
                );
            });
        });
        if snapshot.matching_events > RECENT_LIMIT as u64 {
            ui.label(RichText::new(format!("Showing the latest {RECENT_LIMIT} matching events")).size(11.0).color(MUTED));
        }
        changed |= filter_bar(ui, &mut self.query.filter, snapshot);
        if changed {
            self.selected = None;
            self.due = Instant::now() + Duration::from_millis(140);
        }
        if self.displayed_filter.as_ref() != Some(&self.query.filter) {
            ui.label(RichText::new("Refreshing filtered events…").color(MUTED));
            return;
        }
        ui.add_space(6.0);
        if snapshot.events.is_empty() {
            ui.label(RichText::new(if snapshot.summary.event_count == 0 {
                "No events yet. Send a request through the middleware to populate this dashboard."
            } else {
                "No events match these filters."
            }).color(MUTED));
            return;
        }
        let selected = snapshot
            .events
            .iter()
            .find(|event| Some(event.id) == self.selected);
        if let Some(event) = selected {
            ui.columns(2, |columns| {
                event_list(&mut columns[0], &snapshot.events, &mut self.selected);
                event_detail(&mut columns[1], event, &self.query.path);
            });
        } else {
            event_list(ui, &snapshot.events, &mut self.selected);
        }
    }
}

impl eframe::App for Dashboard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(path) = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        }) {
            self.open(path);
        }
        self.read_updates(ctx);
        egui::CentralPanel::default()
            .frame(Frame::new().fill(BACKGROUND).inner_margin(22.0))
            .show(ctx, |ui| {
                ui.heading(RichText::new("Prompt Security").size(30.0).strong());
                ui.label(
                    RichText::new("Local activity and inspection outcomes")
                        .color(MUTED),
                );
                ui.add_space(16.0);
                self.toolbar(ui);
                ui.add_space(16.0);
                self.event_view(ui);
            });
    }
}

fn summary_cards(ui: &mut egui::Ui, summary: &Summary, selected: &mut Option<Outcome>) -> bool {
    let cards = [
        (Outcome::Passed, summary.passed),
        (Outcome::Sanitized, summary.sanitized),
        (Outcome::Malicious, summary.malicious_blocked),
        (Outcome::Uncertain, summary.uncertain),
    ];
    let before = *selected;
    ui.columns(cards.len(), |columns| {
        for (column, (outcome, count)) in columns.iter_mut().zip(cards) {
            let color = outcome_color(outcome);
            let active = Some(outcome) == *selected;
            let tile = Frame::new()
                .fill(CARD)
                .stroke(Stroke::new(1.0_f32, if active { color } else { BORDER }))
                .corner_radius(10.0)
                .inner_margin(12.0)
                .show(column, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        outcome_icon(ui, outcome);
                        ui.label(RichText::new(outcome.label()).color(MUTED));
                    });
                    ui.label(
                        RichText::new(count.to_string())
                            .size(28.0)
                            .strong()
                            .color(color),
                    );
                });
            if tile.response.interact(Sense::click()).on_hover_text("Filter by this outcome").clicked() {
                *selected = if active { None } else { Some(outcome) };
            }
        }
    });
    *selected != before
}

fn outcome_bar(ui: &mut egui::Ui, summary: &Summary) {
    Frame::new()
        .fill(CARD)
        .corner_radius(9.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Inspection outcomes").strong());
                ui.label(RichText::new("All time").color(MUTED));
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} forwarding and action events",
                            summary.action_events
                        ))
                        .color(MUTED),
                    );
                });
            });
            let outcomes = [
                ("Passed", summary.passed, PASS),
                ("Sanitized", summary.sanitized, SANITIZE),
                ("Malicious", summary.malicious_blocked, HOLD),
                ("Uncertain", summary.uncertain, UNCERTAIN),
                ("Other withheld", summary.withheld - summary.malicious_blocked - summary.uncertain, MUTED),
                ("Other", summary.other_inspections, MUTED),
            ];
            if summary.inspections > 0 {
                let (track, _) =
                    ui.allocate_exact_size(egui::vec2(ui.available_width(), 8.0), Sense::hover());
                let mut left = track.left();
                for (_, count, color) in outcomes {
                    let width = track.width() * (count as f32 / summary.inspections as f32);
                    let segment = egui::Rect::from_min_size(
                        egui::pos2(left, track.top()),
                        egui::vec2(width, track.height()),
                    );
                    ui.painter().rect_filled(segment, 0.0, color);
                    left += width;
                }
            }
            ui.horizontal_wrapped(|ui| {
                for (label, count, color) in outcomes {
                    ui.label(RichText::new(format!("{label}  {count}")).color(color));
                }
            });
        });
}

fn filter_bar(ui: &mut egui::Ui, filter: &mut Filter, snapshot: &Snapshot) -> bool {
    let before = filter.clone();
    Frame::new().fill(CARD).stroke(Stroke::new(1.0, BORDER)).corner_radius(9.0)
        .inner_margin(10.0).show(ui, |ui| {
            ui.add(egui::TextEdit::singleline(&mut filter.search)
                .desired_width(f32::INFINITY).char_limit(200)
                .hint_text("Search by case ID, reason, prompt, or rule"));
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ComboBox::from_id_salt("outcome")
                    .selected_text(filter.outcome.map_or("All outcomes", Outcome::label))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut filter.outcome, None, "All outcomes");
                        for outcome in Outcome::ALL {
                            ui.selectable_value(&mut filter.outcome, Some(outcome), outcome.label());
                        }
                    });
                choice(ui, "event_type", "All event types", &mut filter.event_type, &snapshot.event_types);
                choice(ui, "decision", "All recorded verdicts", &mut filter.decision, &snapshot.decisions);
                let periods = [(None, "All time"), (Some(1), "Last hour"), (Some(24), "Last 24 hours"),
                               (Some(168), "Last 7 days")];
                ComboBox::from_id_salt("hours")
                    .selected_text(periods.iter().find(|(value, _)| *value == filter.hours)
                        .map_or("All time", |(_, label)| *label))
                    .show_ui(ui, |ui| {
                        for (value, label) in periods {
                            ui.selectable_value(&mut filter.hours, value, label);
                        }
                    });
                if ui.add_enabled(*filter != Filter::default(), egui::Button::new("Clear filters")).clicked() {
                    *filter = Filter::default();
                }
            });
        });
    *filter != before
}

fn choice(
    ui: &mut egui::Ui,
    id: &str,
    all: &str,
    selection: &mut Option<String>,
    values: &BTreeSet<String>,
) -> bool {
    let before = selection.clone();
    ComboBox::from_id_salt(id)
        .selected_text(selection.as_deref().unwrap_or(all))
        .show_ui(ui, |ui| {
            ui.selectable_value(selection, None, all);
            for value in values {
                ui.selectable_value(selection, Some(value.clone()), value);
            }
        });
    *selection != before
}

fn outcome_color(outcome: Outcome) -> Color32 {
    match outcome {
        Outcome::Malicious | Outcome::Withheld => HOLD,
        Outcome::Uncertain => UNCERTAIN,
        Outcome::Sanitized => SANITIZE,
        Outcome::Passed => PASS,
        Outcome::Other => ACCENT,
    }
}

fn outcome_icon(ui: &mut egui::Ui, outcome: Outcome) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(19.0, 19.0), Sense::hover());
    let center = rect.center();
    let color = outcome_color(outcome);
    let paint = ui.painter();
    let stroke = Stroke::new(1.4, color);
    paint.circle_filled(center, 9.0, color.gamma_multiply(0.15));
    let point = |x, y| center + egui::vec2(x, y);
    let line = |a, b| paint.line_segment([a, b], stroke);
    match outcome {
        Outcome::Passed => {
            line(point(-4.0, 0.0), point(-1.0, 3.0));
            line(point(-1.0, 3.0), point(4.0, -3.0));
        }
        Outcome::Sanitized => {
            line(point(-4.0, 4.0), point(4.0, -4.0));
            line(point(-4.0, -2.0), point(0.0, -2.0));
            line(point(-2.0, -4.0), point(-2.0, 0.0));
        }
        Outcome::Malicious | Outcome::Withheld => {
            line(point(-3.0, -3.0), point(3.0, 3.0));
            line(point(-3.0, 3.0), point(3.0, -3.0));
        }
        Outcome::Uncertain => {
            line(point(0.0, -4.0), point(0.0, 1.0));
            paint.circle_filled(point(0.0, 4.0), 0.9, color);
        }
        Outcome::Other => {
            paint.circle_stroke(center, 3.0, stroke);
        }
    }
}

fn event_list(ui: &mut egui::Ui, events: &[Event], selected: &mut Option<i64>) {
    ScrollArea::vertical()
        .id_salt("security-events")
        .show(ui, |ui| {
            for event in events {
                let active = *selected == Some(event.id);
                Frame::new()
                    .fill(if active {
                        Color32::from_rgb(31, 51, 76)
                    } else {
                        CARD
                    })
                    .corner_radius(8.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            outcome_icon(ui, event.outcome);
                            if ui
                                .selectable_label(
                                    active,
                                    format!(
                                        "#{}  {}",
                                        event.id,
                                        event.event_type.replace('_', " ")
                                    ),
                                )
                                .clicked()
                            {
                                *selected = if active { None } else { Some(event.id) };
                            }
                            ui.label(RichText::new(event.outcome.label()).small().color(outcome_color(event.outcome)));
                        });
                        ui.add(
                            Label::new(RichText::new(&event.reason).color(MUTED))
                                .wrap_mode(TextWrapMode::Truncate),
                        );
                        ui.label(RichText::new(&event.timestamp).size(11.0).color(MUTED));
                    });
                ui.add_space(4.0);
            }
        });
}

fn event_detail(ui: &mut egui::Ui, event: &Event, database: &Path) {
    Frame::new()
        .fill(CARD)
        .corner_radius(9.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ScrollArea::vertical()
                .id_salt("security-event-details")
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        outcome_icon(ui, event.outcome);
                        ui.heading(format!("Case #{}", event.id));
                    });
                    ui.label(RichText::new(event.outcome.label()).color(outcome_color(event.outcome)));
                    if let Some(verdict) = &event.decision {
                        ui.label(RichText::new(format!("Recorded verdict: {verdict}")).small().color(MUTED));
                    }
                    ui.label(RichText::new(&event.timestamp).monospace().color(MUTED));
                    if let Some(task) = &event.task_id {
                        ui.label(format!("Task: {task}"));
                    }
                    ui.label(&event.reason);
                    ui.separator();
                    let parsed = serde_json::from_str::<serde_json::Value>(&event.details_json).ok();
                    if let Some(review) = parsed.as_ref().and_then(|value| value.get("prompt_review")) {
                        prompt_review(ui, event.id, review, database);
                        return;
                    }
                    let details = parsed
                        .and_then(|value| serde_json::to_string_pretty(&value).ok())
                        .unwrap_or_else(|| event.details_json.clone());
                    ui.add(
                        egui::Label::new(RichText::new(details).monospace())
                            .selectable(true)
                            .wrap(),
                    );
                });
        });
}

fn prompt_review(ui: &mut egui::Ui, event_id: i64, review: &serde_json::Value, database: &Path) {
    ui.heading("Original prompt");
    if let Some(original) = review["original"].as_str() {
        ui.add(Label::new(original).selectable(true).wrap());
    }
    ui.separator();
    ui.heading("Flagged text");
    if let Some(findings) = review["findings"].as_array().filter(|items| !items.is_empty()) {
        for finding in findings {
            ui.label(finding["rule_id"].as_str().unwrap_or("Rule match"));
            ui.add(Label::new(finding["matched_text"].as_str().unwrap_or("")).selectable(true).wrap());
        }
    } else {
        ui.label("The detector did not identify an exact span.");
    }
    if let Some(risks) = review["classifier_risk"].as_array() {
        for risk in risks.iter().filter_map(serde_json::Value::as_str) {
            ui.label(format!("Horizon: {risk}"));
        }
    }
    ui.separator();
    if review["decision"].as_str() == Some("MALICIOUS_BLOCKED") {
        ui.label("Malicious · Blocked by policy. This event cannot be released.");
        return;
    }
    ui.heading("Prompt to resubmit");
    let token = review["acp_token"].as_str();
    if token.is_some() {
        ui.label("Edit the prompt within two minutes. The adapter rechecks it before sending it to the waiting chat.");
    } else {
        ui.label("Review or rewrite the text, then paste it into a new agent chat for inspection.");
    }
    let draft_id = ui.id().with(("prompt-review-draft", database, event_id));
    let mut draft = ui.data_mut(|data| data.get_temp::<String>(draft_id))
        .unwrap_or_else(|| review["cleaned"].as_str().unwrap_or("").to_owned());
    if ui.text_edit_multiline(&mut draft).changed() {
        ui.data_mut(|data| data.insert_temp(draft_id, draft.clone()));
    }
    if let Some(token) = token {
        let status_id = draft_id.with("release-status");
        let ready = !draft.trim().is_empty() && draft.chars().count() <= 20_000;
        if ui.add_enabled(ready, egui::Button::new("Recheck and send")).clicked() {
            let status = match audit::approve_acp_review(database, token, &draft) {
                Ok(true) => "Draft queued for inspection.",
                Ok(false) => "This review is no longer pending.",
                Err(_) => "Could not queue the draft. Try again.",
            };
            ui.data_mut(|data| data.insert_temp(status_id, status.to_owned()));
        }
        if let Some(status) = ui.data_mut(|data| data.get_temp::<String>(status_id)) {
            ui.label(status);
        }
    } else if ui.add_enabled(!draft.trim().is_empty(), egui::Button::new("Copy for resubmission")).clicked() {
        ui.ctx().copy_text(draft);
    }
}
