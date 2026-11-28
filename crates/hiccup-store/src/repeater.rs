// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repeater tabs and the requests sent from them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, Row, params};

use crate::{Store, StoreError, millis};

/// A repeater tab: where to send, what, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tab {
    /// Its ID in the project (0 for a tab not created yet).
    pub id: i64,
    /// What the user calls it.
    pub name: String,
    /// The target host.
    pub host: String,
    /// The target port.
    pub port: u16,
    /// Whether the target speaks TLS.
    pub tls: bool,
    /// The request as last edited.
    pub request: Vec<u8>,
    /// The helpers, as JSON: the store does not read them.
    pub options: String,
}

/// A request sent from a tab: one per redirect hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepeaterSend {
    /// Its ID in the project (0 for a send not recorded yet): higher is
    /// newer.
    pub id: i64,
    /// The tab it was sent from.
    pub tab: i64,
    /// When it started.
    pub started: SystemTime,
    /// How long it took.
    pub duration: Duration,
    /// Where it went.
    pub host: String,
    /// The port it went to.
    pub port: u16,
    /// Over TLS or not.
    pub tls: bool,
    /// The response status, if a response arrived.
    pub status: Option<u16>,
    /// Why it failed, if it did.
    pub error: Option<String>,
    /// Timings, helpers applied and other details, as JSON: the store does
    /// not read them.
    pub details: String,
    /// The bytes sent.
    pub request: Vec<u8>,
    /// Every byte received; empty in lists.
    pub response: Vec<u8>,
    /// How many bytes were received (the length of `response`).
    pub response_size: u64,
}

const TAB: &str = "id, name, host, port, tls, request, options";

fn tab(row: &Row<'_>) -> rusqlite::Result<Tab> {
    Ok(Tab {
        id: row.get(0)?,
        name: row.get(1)?,
        host: row.get(2)?,
        port: row.get(3)?,
        tls: row.get(4)?,
        request: row.get(5)?,
        options: row.get(6)?,
    })
}

/// The columns [`send`] reads; `?` stands for the response.
const SEND: &str = "id, tab, started_ms, duration_ms, host, port, tls, status, error, details,
    request, length(response), ?";

fn send(row: &Row<'_>) -> rusqlite::Result<RepeaterSend> {
    let ms = |i| row.get::<_, u64>(i).map(Duration::from_millis);
    Ok(RepeaterSend {
        id: row.get(0)?,
        tab: row.get(1)?,
        started: UNIX_EPOCH + ms(2)?,
        duration: ms(3)?,
        host: row.get(4)?,
        port: row.get(5)?,
        tls: row.get(6)?,
        status: row.get(7)?,
        error: row.get(8)?,
        details: row.get(9)?,
        request: row.get(10)?,
        response_size: row.get(11)?,
        response: row.get::<_, Option<Vec<u8>>>(12)?.unwrap_or_default(),
    })
}

impl Store {
    /// Creates a tab from `tab` (its `id` is ignored). Returns it with its ID.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn create_tab(&mut self, tab: &Tab) -> Result<Tab, StoreError> {
        self.db
            .prepare_cached(
                "INSERT INTO repeater_tabs (name, host, port, tls, request, options)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![
                tab.name,
                tab.host,
                tab.port,
                tab.tls,
                tab.request,
                tab.options
            ])?;
        Ok(Tab {
            id: self.db.last_insert_rowid(),
            ..tab.clone()
        })
    }

    /// Every tab, oldest first.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn tabs(&self) -> Result<Vec<Tab>, StoreError> {
        let mut query = self
            .db
            .prepare_cached(&format!("SELECT {TAB} FROM repeater_tabs ORDER BY id"))?;
        let rows = query.query_map([], tab)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// One tab.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn tab(&self, id: i64) -> Result<Option<Tab>, StoreError> {
        Ok(self
            .db
            .prepare_cached(&format!("SELECT {TAB} FROM repeater_tabs WHERE id = ?1"))?
            .query_row([id], tab)
            .optional()?)
    }

    /// Saves `tab`. Returns whether it exists.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn update_tab(&mut self, tab: &Tab) -> Result<bool, StoreError> {
        let changed = self
            .db
            .prepare_cached(
                "UPDATE repeater_tabs SET name = ?2, host = ?3, port = ?4, tls = ?5,
                     request = ?6, options = ?7
                 WHERE id = ?1",
            )?
            .execute(params![
                tab.id,
                tab.name,
                tab.host,
                tab.port,
                tab.tls,
                tab.request,
                tab.options
            ])?;
        Ok(changed == 1)
    }

    /// Deletes a tab and what was sent from it. Returns whether it existed.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn delete_tab(&mut self, id: i64) -> Result<bool, StoreError> {
        let deleted = self
            .db
            .prepare_cached("DELETE FROM repeater_tabs WHERE id = ?1")?
            .execute([id])?;
        Ok(deleted == 1)
    }

    /// Records sends, in order (a request and its redirect hops), at once.
    /// Returns their IDs.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does, or the tab does not exist.
    pub fn insert_sends(&mut self, sends: &[RepeaterSend]) -> Result<Vec<i64>, StoreError> {
        let tx = self.db.transaction()?;
        let mut ids = Vec::with_capacity(sends.len());
        for s in sends {
            tx.prepare_cached(
                "INSERT INTO repeater_sends (tab, started_ms, duration_ms, host, port, tls,
                     status, error, details, request, response)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?
            .execute(params![
                s.tab,
                millis(s.started.duration_since(UNIX_EPOCH).unwrap_or_default()),
                millis(s.duration),
                s.host,
                s.port,
                s.tls,
                s.status,
                s.error,
                s.details,
                s.request,
                s.response,
            ])?;
            ids.push(tx.last_insert_rowid());
        }
        tx.commit()?;
        Ok(ids)
    }

    /// What was sent from `tab`, newest first, without the responses: at
    /// most `limit`, older than `before` (an ID from the previous page) if
    /// given.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn sends(
        &self,
        tab: i64,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<RepeaterSend>, StoreError> {
        let mut query = self.db.prepare_cached(&format!(
            "SELECT {} FROM repeater_sends
             WHERE tab = ?1 AND (?2 IS NULL OR id < ?2)
             ORDER BY id DESC LIMIT ?3",
            SEND.replace('?', "NULL")
        ))?;
        let rows = query.query_map(params![tab, before, limit], send)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// One send, with its response.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn send(&self, id: i64) -> Result<Option<RepeaterSend>, StoreError> {
        Ok(self
            .db
            .prepare_cached(&format!(
                "SELECT {} FROM repeater_sends WHERE id = ?1",
                SEND.replace('?', "response")
            ))?
            .query_row([id], send)
            .optional()?)
    }
}
