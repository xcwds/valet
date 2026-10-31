-- Hekate (#7): one row per master key that has been used with this database.
-- The canary is a value encrypted under that key; valetd decrypts it at start
-- to prove the configured key is the right one before touching any secret.
CREATE TABLE master_keys (
	key_id     TEXT PRIMARY KEY, -- HMAC-derived; reveals nothing about the key
	canary     BLOB NOT NULL,
	created_at TEXT NOT NULL
) STRICT;
