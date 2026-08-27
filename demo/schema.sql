-- Schema file for the Agent Firewall demonstration.
-- The fake psql client reads this file. It never sends the file to a server.

CREATE TABLE IF NOT EXISTS customer_archive (
    id integer PRIMARY KEY,
    name text NOT NULL,
    archived_at timestamp DEFAULT now()
);

CREATE INDEX IF NOT EXISTS customer_archive_name_idx ON customer_archive (name);
