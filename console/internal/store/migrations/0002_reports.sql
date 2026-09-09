-- An engagement. Free text identity; the unit of evidence retention and purging.
CREATE TABLE cases (
    id         BIGSERIAL   PRIMARY KEY,
    name       TEXT        NOT NULL UNIQUE,
    created_by TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at  TIMESTAMPTZ
);

-- One agent execution.
--
-- run_id is UNIQUE because it is the ingest idempotency key: importing the same run folder twice
-- must not create a second scan, and the constraint -- not application logic -- is what guarantees
-- it. build_id and rule_set are nullable because they do not exist until stage 2's agent
-- generation; a hand-run scanner produces neither.
CREATE TABLE scans (
    id           BIGSERIAL   PRIMARY KEY,
    case_id      BIGINT      NOT NULL REFERENCES cases(id),
    run_id       TEXT        NOT NULL UNIQUE,
    host         TEXT        NOT NULL,
    started      TIMESTAMPTZ,
    finished     TIMESTAMPTZ,
    tool_version TEXT,
    operator     TEXT,
    invocation   TEXT,
    build_id     TEXT,
    rule_set     TEXT,
    tier         TEXT        NOT NULL,
    score        INT         NOT NULL,
    incomplete   BOOLEAN     NOT NULL,
    integrity    TEXT        NOT NULL CHECK (integrity IN ('verified','unverified','altered')),
    source       TEXT,
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-view coverage, stored beside the verdict rather than folded into it.
--
-- A verdict rendered without its coverage is how a scanner tells a comfortable lie: "clean" over a
-- webroot where 398 files were unreadable is not clean. The skip counters are kept as columns, not
-- as prose, so the UI can show them without parsing a sentence.
CREATE TABLE scan_coverage (
    scan_id              BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    view                 TEXT   NOT NULL,
    status               TEXT   NOT NULL,
    reason               TEXT,
    targets_scanned      INT    NOT NULL DEFAULT 0,
    non_regular          INT    NOT NULL DEFAULT 0,
    unreadable           INT    NOT NULL DEFAULT 0,
    oversize_skipped     INT    NOT NULL DEFAULT 0,
    no_language_detector INT    NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, view)
);

-- One detection.
--
-- content_key is what triage groups on, and it is the FILE CONTENT HASH -- not fingerprint.
-- fingerprint embeds host and path, so it identifies one detection on one host, which is what a
-- SUPPRESSION needs and the opposite of what grouping needs.
CREATE TABLE findings (
    id            BIGSERIAL PRIMARY KEY,
    scan_id       BIGINT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_ref   TEXT      NOT NULL,
    content_key   TEXT      NOT NULL,
    host          TEXT      NOT NULL,
    view          TEXT      NOT NULL,
    file_path     TEXT,
    file_sha256   CHAR(64),
    artifact_kind TEXT,
    artifact_id   TEXT,
    basis         TEXT      NOT NULL,
    knowledge_ref TEXT,
    evidence      TEXT,
    score         INT       NOT NULL,
    tier          TEXT      NOT NULL,
    mitre         TEXT[],
    fingerprint   TEXT,
    UNIQUE (scan_id, finding_ref, fingerprint)
);

-- A person's judgement about CONTENT, not about a finding row.
--
-- Keying on content_key rather than on a finding is what lets a judgement outlive the scan that
-- prompted it: the next scan containing the same file surfaces the earlier decision, its author and
-- its case, before the analyst is asked to decide again. A decision tied to a finding id would die
-- with that scan and the team would re-litigate the same file on every engagement.
CREATE TABLE decisions (
    id          BIGSERIAL   PRIMARY KEY,
    content_key TEXT        NOT NULL,
    verdict     TEXT        NOT NULL CHECK (verdict IN ('malicious','false-positive','benign-noteworthy','undecided')),
    note        TEXT,
    author      TEXT        NOT NULL,
    case_id     BIGINT      REFERENCES cases(id),
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX findings_content_idx  ON findings (content_key);
CREATE INDEX findings_scan_idx     ON findings (scan_id);
CREATE INDEX findings_tier_idx     ON findings (tier);
CREATE INDEX decisions_content_idx ON decisions (content_key, decided_at DESC);
CREATE INDEX scans_case_idx        ON scans (case_id, imported_at DESC);
