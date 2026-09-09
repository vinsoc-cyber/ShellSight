-- Generated agents. One row per archive handed to an analyst.
--
-- The row records what PRODUCED the archive, not a description of it, because the point is to be
-- able to answer "what was this agent" months later from a returning report's build_id. Spec 6.4
-- lists the fields; SC-003 requires that these inputs regenerate the same bytes.
--
-- build_id is the natural key an agent carries in its own agent.json and echoes into a report, so
-- it is UNIQUE. It is derived from the build's inputs rather than random, which means an identical
-- request collides on it deliberately -- see the ON CONFLICT in RecordBuild.
--
-- rule_set_id is nullable because a memory-only build carries no rule set at all (G8). agent_json
-- is stored verbatim rather than as parsed columns: it is the artefact's own statement of what it
-- is, and re-serialising it from columns would let the record and the archive disagree.
--
-- sha256 is the archive's hash AND its blob-store key, the same arrangement rule_sets.yarc_sha256
-- uses, so there is no separate key column to keep in step.
CREATE TABLE builds (
    id           BIGSERIAL   PRIMARY KEY,
    build_id     TEXT        NOT NULL UNIQUE,
    release_id   BIGINT      NOT NULL REFERENCES releases(id),
    rule_set_id  BIGINT      REFERENCES rule_sets(id),
    views        TEXT[]      NOT NULL,
    sha256       CHAR(64)    NOT NULL,
    size_bytes   BIGINT      NOT NULL,
    agent_json   JSONB       NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    generated_by TEXT        NOT NULL
);

CREATE INDEX builds_release_idx ON builds (release_id);
