use std::{collections::BTreeSet, path::Path, time::Duration};

use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;

pub const RECENT_LIMIT: usize = 200;

#[derive(Clone, Default, Eq, PartialEq)]
pub struct Filter {
    pub event_type: Option<String>,
    pub decision: Option<String>,
    pub outcome: Option<Outcome>,
    pub search: String,
    pub hours: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Passed,
    Sanitized,
    Malicious,
    Uncertain,
    Withheld,
    Other,
}

impl Outcome {
    pub const ALL: [Self; 6] = [
        Self::Passed, Self::Sanitized, Self::Malicious, Self::Uncertain, Self::Withheld, Self::Other,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Sanitized => "sanitized",
            Self::Malicious => "malicious",
            Self::Uncertain => "uncertain",
            Self::Withheld => "withheld",
            Self::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Passed => "Passed",
            Self::Sanitized => "Sanitized",
            Self::Malicious => "Malicious · Blocked",
            Self::Uncertain => "Uncertain · Held",
            Self::Withheld => "Other withheld",
            Self::Other => "Other events",
        }
    }

    fn from_key(key: &str) -> Self {
        Self::ALL.into_iter().find(|outcome| outcome.key() == key).unwrap_or(Self::Other)
    }
}

#[derive(Clone, Default, Serialize)]
pub struct Summary {
    pub event_count: u64,
    pub inspections: u64,
    pub withheld: u64,
    pub malicious_blocked: u64,
    pub uncertain: u64,
    pub sanitized: u64,
    pub passed: u64,
    pub other_inspections: u64,
    pub action_events: u64,
}

impl Summary {
    fn add_group(&mut self, event_type: &str, decision: &str, count: u64, sanitized: u64) {
        self.event_count += count;
        if matches!(
            event_type,
            "middleware_inspection"
                | "hook_inspection"
                | "content_inspection"
                | "protected_model_test"
                | "secure_document_retrieval"
        ) {
            self.inspections += count;
            match decision {
                "MALICIOUS_BLOCKED" => {
                    self.withheld += count;
                    self.malicious_blocked += count;
                }
                "UNCERTAIN" => {
                    self.withheld += count;
                    self.uncertain += count;
                }
                "BLOCKED" | "HOLD_FOR_REVIEW" | "HOLD" | "BLOCK" | "DENY" => self.withheld += count,
                "SANITIZE" => self.sanitized += count,
                "PASS" | "RELEASED" => {
                    self.sanitized += sanitized;
                    self.passed += count - sanitized;
                }
                _ => self.other_inspections += count,
            }
        }
        if matches!(
            event_type,
            "middleware_forward"
                | "middleware_outcome"
                | "tool_action"
                | "action_execution"
                | "tool_authorization"
                | "tool_execution"
        ) {
            self.action_events += count;
        }
    }
}

pub struct Event {
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub task_id: Option<String>,
    pub decision: Option<String>,
    pub outcome: Outcome,
    pub reason: String,
    pub details_json: String,
}

pub struct Snapshot {
    pub summary: Summary,
    pub events: Vec<Event>,
    pub matching_events: u64,
    pub event_types: BTreeSet<String>,
    pub decisions: BTreeSet<String>,
}

pub fn approve_acp_review(path: &Path, token: &str, draft: &str) -> rusqlite::Result<bool> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(Duration::from_millis(200))?;
    let changed = connection.execute(
        "UPDATE acp_reviews SET state = 'approved', draft = ?1
         WHERE token = ?2 AND state = 'pending' AND expires_at > unixepoch()",
        params![draft, token],
    )?;
    Ok(changed == 1)
}

pub fn read(path: &Path, filter: &Filter) -> rusqlite::Result<Snapshot> {
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(Duration::from_millis(200))?;
    let transaction = connection.transaction()?;
    let snapshot = read_connection(&transaction, filter)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn read_connection(connection: &Connection, filter: &Filter) -> rusqlite::Result<Snapshot> {
    let mut summary = Summary::default();
    let mut event_types = BTreeSet::new();
    let mut decisions = BTreeSet::new();
    let mut groups = connection.prepare(
        "SELECT event_type, decision, COUNT(*),
                SUM(CASE
                  WHEN event_type = 'middleware_inspection' AND decision = 'RELEASED'
                    AND EXISTS (
                      SELECT 1 FROM json_each(
                        CASE WHEN json_valid(details_json) THEN details_json ELSE '{}' END,
                        '$.content_decisions'
                      ) WHERE value = 'SANITIZE'
                    )
                  THEN 1 ELSE 0 END)
         FROM security_events GROUP BY event_type, decision",
    )?;
    let mut results = groups.query([])?;
    while let Some(row) = results.next()? {
        let event_type: String = row.get(0)?;
        let decision: Option<String> = row.get(1)?;
        summary.add_group(
            &event_type,
            decision.as_deref().unwrap_or_default(),
            row.get(2)?,
            row.get(3)?,
        );
        event_types.insert(event_type);
        decisions.extend(decision);
    }

    let mut recent = connection.prepare(
        "WITH cases AS (
            SELECT security_events.*,
                CASE
                    WHEN event_type NOT IN ('middleware_inspection','hook_inspection',
                        'content_inspection','protected_model_test','secure_document_retrieval') THEN 'other'
                    WHEN decision = 'SANITIZE' OR (
                        event_type = 'middleware_inspection' AND decision = 'RELEASED' AND EXISTS (
                            SELECT 1 FROM json_each(
                                CASE WHEN json_valid(details_json) THEN details_json ELSE '{}' END,
                                '$.content_decisions'
                            ) WHERE value = 'SANITIZE'
                        )
                    ) THEN 'sanitized'
                    WHEN decision = 'MALICIOUS_BLOCKED' THEN 'malicious'
                    WHEN decision = 'UNCERTAIN' THEN 'uncertain'
                    WHEN decision IN ('BLOCKED','HOLD_FOR_REVIEW','HOLD','BLOCK','DENY') THEN 'withheld'
                    WHEN decision IN ('PASS','RELEASED') THEN 'passed'
                    ELSE 'other'
                END AS outcome
            FROM security_events
            WHERE (?1 IS NULL OR event_type = ?1) AND (?2 IS NULL OR decision = ?2)
                AND (?5 IS NULL OR julianday(created_at) >= julianday('now') - ?5 / 24.0)
                AND (?4 = '' OR instr(lower(reason), ?4) > 0 OR instr(lower(details_json), ?4) > 0
                    OR instr(lower(event_type), ?4) > 0 OR instr(lower(coalesce(task_id,'')), ?4) > 0
                    OR CAST(event_id AS TEXT) = ?4)
         )
         SELECT event_id, created_at, event_type, task_id, decision, reason, details_json,
                outcome, COUNT(*) OVER()
         FROM cases WHERE (?6 IS NULL OR outcome = ?6)
         ORDER BY event_id DESC LIMIT ?3",
    )?;
    let mut matching_events = 0;
    let events = recent
        .query_map(
            params![filter.event_type, filter.decision, RECENT_LIMIT,
                    filter.search.trim().to_ascii_lowercase(), filter.hours, filter.outcome.map(Outcome::key)],
            |row| {
                matching_events = row.get(8)?;
                Ok(Event {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    task_id: row.get(3)?,
                    decision: row.get(4)?,
                    outcome: Outcome::from_key(&row.get::<_, String>(7)?),
                    reason: row.get(5)?,
                    details_json: row.get(6)?,
                })
            },
        )?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Snapshot {
        summary,
        events,
        matching_events,
        event_types,
        decisions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE security_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    task_id TEXT,
                    decision TEXT,
                    reason TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );",
            )
            .unwrap();
        connection
    }

    #[test]
    fn counts_screening_outcomes_once_and_filters_recent_events() {
        let connection = test_database();
        for (kind, decision, details) in [
            (
                "middleware_inspection",
                "RELEASED",
                r#"{"content_decisions":["SANITIZE"]}"#,
            ),
            ("middleware_forward", "RELEASED", "{}"),
            ("middleware_outcome", "SUCCEEDED", "{}"),
            ("middleware_inspection", "RELEASED", "invalid JSON"),
            ("hook_inspection", "BLOCKED", "{}"),
            ("content_inspection", "HOLD_FOR_REVIEW", "{}"),
            ("secure_document_retrieval", "PASS", "{}"),
        ] {
            connection.execute(
                "INSERT INTO security_events (created_at,event_type,decision,reason,details_json)
                 VALUES ('2026-11-20T12:00:00+00:00',?1,?2,'test',?3)",
                params![kind, decision, details],
            ).unwrap();
        }
        let snapshot = read_connection(&connection, &Filter::default()).unwrap();
        assert_eq!(snapshot.summary.event_count, 7);
        assert_eq!(snapshot.summary.inspections, 5);
        assert_eq!(snapshot.summary.withheld, 2);
        assert_eq!(snapshot.summary.sanitized, 1);
        assert_eq!(snapshot.summary.passed, 2);
        assert_eq!(snapshot.summary.action_events, 2);
        assert_eq!(snapshot.events[0].id, 7);
        let filtered = read_connection(
            &connection,
            &Filter {
                event_type: Some("hook_inspection".into()),
                decision: Some("BLOCKED".into()),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(filtered.events.len(), 1);
        assert_eq!(filtered.events[0].id, 5);
        assert_eq!(filtered.summary.event_count, 7);
        let sanitized = read_connection(
            &connection,
            &Filter { outcome: Some(Outcome::Sanitized), search: "sanitize".into(), ..Filter::default() },
        ).unwrap();
        assert_eq!(sanitized.matching_events, 1);
        assert_eq!(sanitized.events[0].id, 1);
        assert_eq!(sanitized.events[0].outcome, Outcome::Sanitized);
    }

    #[test]
    fn empty_database_is_a_valid_snapshot() {
        let snapshot = read_connection(&test_database(), &Filter::default()).unwrap();
        assert_eq!(snapshot.summary.event_count, 0);
        assert!(snapshot.events.is_empty());
    }

    #[test]
    fn filter_combines_period_and_literal_text_search() {
        let connection = test_database();
        for (age, reason) in [
            ("-30 minutes", "A 20% threshold"),
            ("-1 day", "An old 20% threshold"),
            ("-20 minutes", "A 200 threshold"),
        ] {
            connection.execute(
                "INSERT INTO security_events (created_at,event_type,decision,reason,details_json)
                 VALUES (datetime('now', ?1),'middleware_inspection','UNCERTAIN',?2,'{}')",
                params![age, reason],
            ).unwrap();
        }
        let filtered = read_connection(&connection, &Filter {
            outcome: Some(Outcome::Uncertain), search: "20% THRESHOLD".into(),
            hours: Some(1), ..Filter::default()
        }).unwrap();
        assert_eq!(filtered.summary.event_count, 3);
        assert_eq!(filtered.matching_events, 1);
        assert_eq!(filtered.events[0].id, 1);
    }
}
