-- Runs once, on first start of an empty data volume.
--
-- The test suite drops and recreates the `public` schema on every run, so it needs a database of
-- its own. Pointing CONSOLE_TEST_DSN at the development database instead would wipe the
-- developer's data on every `go test`.
CREATE DATABASE shellsight_console_test OWNER console;
