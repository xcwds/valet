-- Container enrollment (#19, RFC decision 10): one-time codes a container
-- exchanges for its job's session at start-up. Stored only as SHA-256.
CREATE TABLE enrollments (
	id         TEXT PRIMARY KEY,
	job_id     TEXT NOT NULL REFERENCES jobs (id),
	code_hash  BLOB NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at    TEXT,            -- first use; set once, atomically
	session_id TEXT,            -- the session first use created
	revoked_at TEXT             -- superseded by a re-enrollment
) STRICT;

CREATE INDEX enrollments_job ON enrollments (job_id);
