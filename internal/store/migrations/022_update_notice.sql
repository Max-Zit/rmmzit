-- The notice of a new RMMZit version, hidden by an administrator: for that
-- version (newer ones show it again) until the time given (five days).
ALTER TABLE users
    ADD COLUMN update_hidden_version text NOT NULL DEFAULT '',
    ADD COLUMN update_hidden_until   timestamptz;
