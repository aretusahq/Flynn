//! History, rollups, retention and explorer queries.
//!
//! Runs in the app process only, never in the capture extension. It ingests
//! the event spool the data plane writes, keeps raw connections for days and
//! hourly and daily rollups for months, and answers the explorer's queries.
//! The encrypted SQLite store lands in M5.

/// Bumped on every schema migration. The schema is identical on every
/// platform, so Android reuses ingest, retention and queries unchanged.
pub const SCHEMA_VERSION: u32 = 1;

/// Default retention for raw connection rows.
pub const DEFAULT_RAW_RETENTION_DAYS: u32 = 7;

/// Default retention for hourly and daily rollups.
pub const DEFAULT_ROLLUP_RETENTION_MONTHS: u32 = 13;
