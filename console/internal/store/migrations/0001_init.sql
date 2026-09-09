CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A published release: immutable, hash-verified, never modified or deleted.
CREATE TABLE releases (
    id            BIGSERIAL PRIMARY KEY,
    version       TEXT        NOT NULL,
    target        TEXT        NOT NULL CHECK (target IN ('windows-amd64','linux-amd64','linux-arm64')),
    published_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by  TEXT        NOT NULL,
    UNIQUE (version, target)
);

-- One row per file in a release. sha256 is also the blob-store key.
CREATE TABLE release_files (
    release_id  BIGINT   NOT NULL REFERENCES releases(id),
    path        TEXT     NOT NULL,
    sha256      CHAR(64) NOT NULL,
    PRIMARY KEY (release_id, path)
);

-- A rule's identity. Its text lives in rule_revisions; this row never holds text.
-- layer determines who may change it: foundation is exclude-only (design D7).
CREATE TABLE rules (
    id          BIGSERIAL PRIMARY KEY,
    identifier  TEXT NOT NULL UNIQUE,
    layer       TEXT NOT NULL CHECK (layer IN ('foundation','own','custom')),
    source_pack TEXT,
    deleted_at  TIMESTAMPTZ
);

CREATE TABLE rule_revisions (
    id         BIGSERIAL PRIMARY KEY,
    rule_id    BIGINT      NOT NULL REFERENCES rules(id),
    revision   INT         NOT NULL,
    text       TEXT        NOT NULL,
    lang       TEXT,
    author     TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_id, revision)
);

-- A rule set. While draft, `selection` holds the analyst's choices as JSON and version is NULL.
-- Freezing materialises rule_set_members, sets version, and records the compiled blob's hash.
CREATE TABLE rule_sets (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT        NOT NULL,
    version     INT,
    selection   JSONB       NOT NULL DEFAULT '{"layers":[],"rules":[]}',
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    frozen_at   TIMESTAMPTZ,
    frozen_by   TEXT,
    yarc_sha256 CHAR(64),
    UNIQUE (name, version)
);

-- Written only at freeze. Pinning the REVISION, not the rule, is what makes a frozen set
-- reconstructible after the rules inside it are later edited or deleted.
CREATE TABLE rule_set_members (
    rule_set_id      BIGINT NOT NULL REFERENCES rule_sets(id),
    rule_revision_id BIGINT NOT NULL REFERENCES rule_revisions(id),
    PRIMARY KEY (rule_set_id, rule_revision_id)
);

CREATE TABLE rule_set_exclusions (
    rule_set_id BIGINT      NOT NULL REFERENCES rule_sets(id),
    rule_id     BIGINT      NOT NULL REFERENCES rules(id),
    reason      TEXT        NOT NULL,
    author      TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_set_id, rule_id)
);

CREATE TABLE audit_log (
    id      BIGSERIAL   PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor   TEXT        NOT NULL,
    action  TEXT        NOT NULL,
    subject TEXT        NOT NULL,
    detail  JSONB
);

CREATE INDEX rules_layer_idx ON rules (layer) WHERE deleted_at IS NULL;
CREATE INDEX rule_revisions_rule_idx ON rule_revisions (rule_id, revision DESC);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
