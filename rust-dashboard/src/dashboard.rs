use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use eframe::egui::{
    self, Color32, ComboBox, Frame, Label, Layout, RichText, ScrollArea, Sense, Stroke,
    TextWrapMode,
};

use crate::audit::{self, Event, Filter, Snapshot, Summary, RECENT_LIMIT};

const REFRESH: Duration = Duration::from_secs(2);
const BACKGROUND: Color32 = Color32::from_rgb(14, 20, 31);
const CARD: Color32 = Color32::from_rgb(23, 33, 49);
const BORDER: Color32 = Color32::from_rgb(43, 58, 80);
const MUTED: Color32 = Color32::from_rgb(163, 178, 198);
const ACCENT: Color32 = Color32::from_rgb(114, 185, 249);
const PASS: Color32 = Color32::from_rgb(108, 213, 167);
const HOLD: Color32 = Color32::from_rgb(251, 132, 136);
const SANITIZE: Color32 = Color32::from_rgb(249, 198, 119);

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
                        self.error = None;
                    }
                    Err(error) => {
                        self.snapshot = None;
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
        summary_cards(ui, &snapshot.summary);
        ui.add_space(8.0);
        outcome_bar(ui, &snapshot.summary);
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.heading("Recent events");
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("Latest {RECENT_LIMIT} matching events")).color(MUTED),
                );
            });
        });
        let changed = ui
            .horizontal(|ui| {
                let event_changed = choice(
                    ui,
                    "event_type",
                    "All event types",
                    &mut self.query.filter.event_type,
                    &snapshot.event_types,
                );
                let decision_changed = choice(
                    ui,
                    "decision",
                    "All decisions",
                    &mut self.query.filter.decision,
                    &snapshot.decisions,
                );
                event_changed || decision_changed
            })
            .inner;
        if changed {
            self.selected = None;
            self.due = Instant::now();
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
                event_detail(&mut columns[1], event);
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
                ui.heading(RichText::new("Security events").size(30.0));
                ui.label(
                    RichText::new("Local audit activity and prompt screening outcomes")
                        .color(MUTED),
                );
                ui.add_space(16.0);
                self.toolbar(ui);
                ui.add_space(16.0);
                self.event_view(ui);
            });
    }
}

fn summary_cards(ui: &mut egui::Ui, summary: &Summary) {
    let cards = [
        ("Audit events", summary.event_count, ACCENT),
        ("Inspections", summary.inspections, Color32::WHITE),
        ("Withheld", summary.withheld, HOLD),
        ("Sanitized", summary.sanitized, SANITIZE),
    ];
    ui.columns(cards.len(), |columns| {
        for (column, (label, count, color)) in columns.iter_mut().zip(cards) {
            Frame::new()
                .fill(CARD)
                .stroke(Stroke::new(1.0_f32, BORDER))
                .corner_radius(10.0)
                .inner_margin(12.0)
                .show(column, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(label).color(MUTED));
                    ui.label(
                        RichText::new(count.to_string())
                            .size(28.0)
                            .strong()
                            .color(color),
                    );
                });
        }
    });
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
                ("Withheld", summary.withheld, HOLD),
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

fn color_for(decision: &str) -> Color32 {
    match decision {
        "HOLD_FOR_REVIEW" | "BLOCKED" | "HOLD" | "BLOCK" | "DENY" | "FAILED" | "REJECTED" => HOLD,
        "SANITIZE" => SANITIZE,
        "PASS" | "RELEASED" | "SUCCEEDED" | "APPROVED" | "ALLOW" => PASS,
        _ => MUTED,
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
                            let decision = event.decision.as_deref().unwrap_or("—");
                            ui.label(RichText::new(decision).small().color(color_for(decision)));
                        });
                        ui.add(
                            Label::new(RichText::new(&event.reason).color(MUTED))
                                .wrap_mode(TextWrapMode::Truncate),
                        );
                    });
                ui.add_space(4.0);
            }
        });
}

fn event_detail(ui: &mut egui::Ui, event: &Event) {
    Frame::new()
        .fill(CARD)
        .corner_radius(9.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ScrollArea::vertical()
                .id_salt("security-event-details")
                .show(ui, |ui| {
                    ui.heading(format!("Event #{}", event.id));
                    ui.label(RichText::new(&event.timestamp).monospace().color(MUTED));
                    if let Some(task) = &event.task_id {
                        ui.label(format!("Task: {task}"));
                    }
                    ui.label(&event.reason);
                    ui.separator();
                    let details = serde_json::from_str::<serde_json::Value>(&event.details_json)
                        .ok()
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
