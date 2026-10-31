-- Operator auth (#9): admin API tokens, stored only as their SHA-256.
CREATE TABLE admin_tokens (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	token_hash BLOB NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	revoked_at TEXT
) STRICT;
