-- Metadata a rule declared in its YARA meta: block, extracted so the library can be searched.
--
-- It attaches to the REVISION, not the rule: editing a rule can change its meta block, and a
-- frozen set must keep the metadata of the revision it pinned rather than of whatever the rule
-- says today.
--
-- All three are nullable, and null means the rule declared nothing. About 17 rules in the shipped
-- packs carry no meta block; a NOT NULL column would force the backfill to invent a value.
--
-- No index. Filtering happens in the browser over an index fetched once (design C7), so the only
-- query these columns serve is a full scan that builds that payload. An index here would cost
-- writes and buy nothing.
ALTER TABLE rule_revisions
    ADD COLUMN description TEXT,
    ADD COLUMN score       INT,
    ADD COLUMN meta        JSONB;
