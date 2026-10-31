-- Initial schema. Each table belongs to the issue that builds its component
-- (secrets #7, audit_events #8, jobs and sessions #9), which may refine it.
--
-- Conventions: STRICT tables; timestamps are UTC RFC 3339 TEXT; JSON is TEXT;
-- hashes and ciphertext are BLOB. No SQLite-only column types, so the same
-- shapes carry over to Postgres.

-- Hekate (#7): upstream secrets, envelope-encrypted. Plaintext never stored.
CREATE TABLE secrets (
	name        TEXT PRIMARY KEY,
	key_id      TEXT NOT NULL, -- which master key wrapped data_key
	wrapped_key BLOB NOT NULL, -- per-secret data key, wrapped by the master key
	nonce       BLOB NOT NULL,
	ciphertext  BLOB NOT NULL, -- AES-256-GCM, secret name as additional data
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
) STRICT;

-- Jobs (#9): one unit of agent work.
CREATE TABLE jobs (
	id             TEXT PRIMARY KEY,
	role           TEXT NOT NULL,
	grants         TEXT NOT NULL, -- JSON: connector -> resources, e.g. {"github":{"repos":["xcwds/site"]}}
	branch_pattern TEXT NOT NULL,
	ttl_seconds    INTEGER NOT NULL CHECK (ttl_seconds > 0),
	expires_at     TEXT NOT NULL,
	state          TEXT NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
	created_by     TEXT NOT NULL,
	created_at     TEXT NOT NULL,
	revoked_at     TEXT
) STRICT;

-- Sessions (#9): the agent's bearer token, stored only as its SHA-256.
CREATE TABLE sessions (
	id         TEXT PRIMARY KEY,
	job_id     TEXT NOT NULL REFERENCES jobs (id),
	token_hash BLOB NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	revoked_at TEXT
) STRICT;

CREATE INDEX sessions_job ON sessions (job_id);

-- Clio (#8): hash-chained, append-only audit log.
CREATE TABLE audit_events (
	seq             INTEGER PRIMARY KEY, -- assigned by the single writer, no gaps
	time            TEXT NOT NULL,
	job_id          TEXT,
	session_id      TEXT,
	interface       TEXT NOT NULL, -- mcp, git, egress, admin, cli
	action          TEXT NOT NULL,
	params          TEXT NOT NULL, -- redacted JSON
	decision        TEXT NOT NULL,
	rule            TEXT,
	upstream_status INTEGER,
	error           TEXT,
	prev_hash       BLOB NOT NULL,
	hash            BLOB NOT NULL
) STRICT;

CREATE INDEX audit_events_job ON audit_events (job_id, seq);

-- Append-only, enforced in the database too: no code path updates or deletes
-- audit rows, and these make an accidental one fail loudly.
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
	SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
	SELECT RAISE(ABORT, 'audit_events is append-only');
END;
