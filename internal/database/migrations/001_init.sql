-- Sample memory: what UNPACKR has seen, never the samples themselves.
CREATE TABLE samples (
    sha256      TEXT PRIMARY KEY,
    md5         TEXT NOT NULL,
    sha1        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    last_name   TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    times_seen  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE analyses (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256         TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    analysed_at    TEXT NOT NULL,
    tool_version   TEXT NOT NULL,
    profile        TEXT NOT NULL,
    format         TEXT NOT NULL,
    architecture   TEXT NOT NULL,
    packing_state  TEXT NOT NULL,
    packing_family TEXT NOT NULL,
    language       TEXT NOT NULL,
    compiler       TEXT NOT NULL,
    findings       INTEGER NOT NULL,
    high           INTEGER NOT NULL,
    medium         INTEGER NOT NULL,
    report_gz      BLOB NOT NULL
);
CREATE INDEX analyses_sha ON analyses(sha256, analysed_at);

-- Values that can be pivoted on: indicators, hashes of structure, rule hits.
CREATE TABLE features (
    sha256 TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    kind   TEXT NOT NULL,
    value  TEXT NOT NULL,
    PRIMARY KEY (sha256, kind, value)
);
CREATE INDEX features_lookup ON features(kind, value);

-- Derived files: an unpacked layer or extracted payload and where it came from.
CREATE TABLE edges (
    parent TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    child  TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    kind   TEXT NOT NULL,
    tool   TEXT NOT NULL,
    PRIMARY KEY (parent, child, kind)
);

CREATE TABLE cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL
);

CREATE TABLE case_samples (
    case_id  INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    sha256   TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    added_at TEXT NOT NULL,
    PRIMARY KEY (case_id, sha256)
);

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    sha256     TEXT,
    created_at TEXT NOT NULL,
    body       TEXT NOT NULL
);
CREATE VIRTUAL TABLE notes_fts USING fts5(body, content='notes', content_rowid='id');
CREATE TRIGGER notes_ai AFTER INSERT ON notes BEGIN
    INSERT INTO notes_fts(rowid, body) VALUES (new.id, new.body);
END;
CREATE TRIGGER notes_ad AFTER DELETE ON notes BEGIN
    INSERT INTO notes_fts(notes_fts, rowid, body) VALUES ('delete', old.id, old.body);
END;

CREATE TABLE timeline (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    at      TEXT NOT NULL,
    kind    TEXT NOT NULL,
    sha256  TEXT,
    detail  TEXT NOT NULL
);
CREATE INDEX timeline_case ON timeline(case_id, at);
